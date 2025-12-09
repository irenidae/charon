#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

if [[ "$OSTYPE" == "darwin"* ]]; then
    export LC_ALL=C
    export LANG=C
    export LC_CTYPE=C
fi

info() { printf "[info] %s\n" "$*"; }
warn() { printf "[warn] %s\n" "$*"; }
err() { printf "[error] %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }
clear_scr() { clear 2>/dev/null || true; printf '\e[3J' 2>/dev/null || true; }

if xargs -r </dev/null echo >/dev/null 2>&1; then
    xargs_r='-r'
else
    xargs_r=''
fi
export xargs_r

SUDO=""

if [[ "$OSTYPE" == "darwin"* ]]; then
    info "macOS detected."
    if ! command -v docker >/dev/null 2>&1; then
        err "Docker is not installed."
        info "hint: Install Docker Desktop, launch it, then re-run this script."
        exit 1
    fi

    if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix://* ]]; then
        sock="${DOCKER_HOST#unix://}"
        if [[ ! -S "$sock" ]]; then
            err  "DOCKER_HOST points to '$sock', but that socket does not exist."
            info "hint: Start Docker Desktop, or run: unset DOCKER_HOST ; docker context use default"
            exit 1
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        err  "Docker is installed but not running."
        info "hint: Open 'Docker.app' and wait until the whale icon stops animating, then re-run this script."
        info "hint: If you use custom contexts, try: unset DOCKER_HOST ; docker context use default"
        exit 1
    fi

    SUDO=""
    info "Docker Desktop is running."
else
    if docker ps >/dev/null 2>&1; then
        SUDO=""
        info "docker is usable without sudo."
    else
        if command -v sudo >/dev/null 2>&1; then
            if sudo -n true 2>/dev/null; then
                SUDO="sudo"
                info "using passwordless sudo for docker."
            else
                if [[ -t 0 && -t 1 ]]; then
                    info "asking for sudo password to use docker…"
                    sudo -v || { err "sudo authentication failed."; exit 1; }
                    SUDO="sudo"
                else
                    err  "docker requires sudo but no TTY is available to prompt for password."
                    info "hint: add your user to the docker group or enable passwordless sudo for docker."
                    exit 1
                fi
            fi
        else
            err "docker is not accessible and sudo is not installed."
            exit 1
        fi
    fi
fi

export SUDO
declare -a _tmp_files=()
declare -a _tmp_dirs=()
declare -a _tmp_images=()
append_tmp_file() { _tmp_files+=("$1"); }
append_tmp_dir() { _tmp_dirs+=("$1"); }
append_tmp_image() { _tmp_images+=("$1"); }

sudo_keepalive_start() {
    local max_minutes="${1:-60}"

    [[ "${SUDO:-}" != "sudo" ]] && return 0

    sudo -v || exit 1
    (
        local end=$((SECONDS + max_minutes*60))
        while (( SECONDS < end )); do
            sleep 60
            kill -0 "$PPID" 2>/dev/null || exit 0
            sudo -n -v 2>/dev/null || exit 0
        done
    ) & SUDO_KEEPALIVE_PID=$!
}
sudo_keepalive_stop() {
    if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
        unset SUDO_KEEPALIVE_PID
    fi
    if [[ "${SUDO:-}" == "sudo" ]]; then
        sudo -K 2>/dev/null || true
    fi
}
__compose() {
    if ${SUDO} docker compose version >/dev/null 2>&1; then
        ${SUDO} docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        ${SUDO} docker-compose "$@"
    else
        err "docker compose is not available."
        return 1
    fi
}
prune_build_caches() {
    ${SUDO} docker builder prune -af >/dev/null 2>&1 || true

    if ${SUDO} docker buildx ls >/dev/null 2>&1; then
        if ${SUDO} docker buildx ls --format '{{.Name}}' >/dev/null 2>&1; then
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                ${SUDO} docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(${SUDO} docker buildx ls --format '{{.Name}}')
        else
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                ${SUDO} docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(${SUDO} docker buildx ls | awk 'NR>1{print $1}')
        fi
    fi
}
preclean_patterns() {
    for name in exit_a exit_b haproxy support; do
        ${SUDO} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r} ${SUDO} docker rm -f >/dev/null 2>&1 || true
    done
    local nets=()
    [[ -n "${ext_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$ext_network_container_subnet_cidr_ipv4" )
    [[ -n "${int_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$int_network_container_subnet_cidr_ipv4" )
    ${SUDO} docker network ls -q | while read -r nid; do
        subnets=$(${SUDO} docker network inspect "$nid" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
        for net in "${nets[@]}"; do
            if echo "$subnets" | grep -qw -- "$net"; then
                ${SUDO} docker network rm "$nid" >/dev/null 2>&1 || true
                break
            fi
        done
    done
    prune_build_caches
}
cleanup_project() {
    local proj="$1"
    local yml="$2"

    if [[ -f "$yml" ]]; then
        __compose -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in exit_a exit_b haproxy bitlaunch; do
        ${SUDO} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r} ${SUDO} docker rm -f >/dev/null 2>&1 || true
    done

    ${SUDO} docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r} ${SUDO} docker network rm >/dev/null 2>&1 || true
    ${SUDO} docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r} ${SUDO} docker volume rm -f >/dev/null 2>&1 || true
    if [[ -z "$(${SUDO} docker ps -aq --filter ancestor=debian:trixie-slim 2>/dev/null)" ]]; then
        ${SUDO} docker rmi -f debian:trixie-slim >/dev/null 2>&1 || true
    fi
}

guard_pid=""

start_session_guard() {
    local proj="$1"
    local yml="$2"
    local parent="$$"
    local tty_path
    tty_path="${SSH_TTY:-$(tty 2>/dev/null || echo)}"
    mkdir -p "${tmp_folder}/${proj}"
    local guard="${tmp_folder}/${proj}/._guard.sh"
    local pidfile="${tmp_folder}/${proj}/._guard.pid"

    cat >"$guard" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail

proj="$1"
yml="$2"
parent="$3"
tty_path="$4"

on_term() {
    if [[ -f "$yml" ]]; then
        ${SUDO:-} docker compose -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in exit_a exit_b haproxy bitlaunch; do
        ${SUDO:-} docker ps -aq -f "name=^${name}$" | xargs ${xargs_r:-} ${SUDO:-} docker rm -f >/dev/null 2>&1 || true
    done

    ${SUDO:-} docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} ${SUDO:-} docker network rm >/dev/null 2>&1 || true
    ${SUDO:-} docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} ${SUDO:-} docker volume rm -f >/dev/null 2>&1 || true

    exit 0
}

trap on_term INT TERM HUP

while :; do
    kill -0 "$parent" 2>/dev/null || break
    if [[ -n "$tty_path" && ! -e "$tty_path" ]]; then
        break
    fi
    sleep 1
done

on_term
EOS

    chmod +x "$guard"

    if command -v setsid >/dev/null 2>&1; then
        (
            setsid -w bash "$guard" "$proj" "$yml" "$parent" "$tty_path" >/dev/null 2>&1 &
            echo $! > "$pidfile"
        )
    else
        (
            nohup bash "$guard" "$proj" "$yml" "$parent" "$tty_path" >/dev/null 2>&1 &
            echo $! > "$pidfile"
        )
    fi

    guard_pid="$(cat "$pidfile" 2>/dev/null || true)"
}
stop_session_guard() {
    local pid="${guard_pid:-}"

    if [[ -z "$pid" ]]; then
        local pf
        pf="$(find "${tmp_folder}" -maxdepth 3 -name '._guard.pid' 2>/dev/null | head -n1 || true)"
        [[ -n "$pf" ]] && pid="$(cat "$pf" 2>/dev/null || true)"
    fi

    [[ -z "$pid" ]] && return 0

    kill -TERM "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || { unset guard_pid; return 0; }
        sleep 0.2
    done
    kill -KILL "$pid" 2>/dev/null || true
    unset guard_pid
}
cleanup_all() {
    set +e

    stop_session_guard
    cleanup_project "${rnd_proj_name}" "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"

    local f d
    if [[ ${_tmp_files+x} ]]; then
        for f in "${_tmp_files[@]}"; do
            [[ -n "$f" ]] && rm -f "$f" 2>/dev/null || true
        done
    fi
    if [[ ${_tmp_dirs+x} ]]; then
        for d in "${_tmp_dirs[@]}"; do
            [[ -n "$d" ]] && rm -rf "$d" 2>/dev/null || true
        done
    fi

    rm -rf -- "${tmp_folder:-}" 2>/dev/null || true

    if ${SUDO} docker info >/dev/null 2>&1; then
        prune_build_caches

        if [[ "${STRICT_CLEANUP:-0}" == "1" ]]; then
            warn "Performing system-wide prune (--all --volumes)."
            ${SUDO} docker system prune -af --volumes >/dev/null 2>&1 || true
        fi
    fi

    sudo_keepalive_stop
    set -e
}
check_pkg() {
    local os=""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        info "Docker on macOS is ready."
        return 0
    fi

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os="$ID"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        case "$os" in
            debian)
                info "installing docker (Debian)…"
                sudo install -d -m 0755 -o root -g root /etc/apt/keyrings
                local arch codename
                arch="$(dpkg --print-architecture)"
                codename="$(lsb_release -cs 2>/dev/null || true)"
                : "${codename:=stable}"
                curl -fsSL --proto '=https' --tlsv1.3 https://download.docker.com/linux/debian/gpg | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
                sudo sh -c "printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.gpg\n' '$codename' '$arch' > /etc/apt/sources.list.d/docker.sources"
                sudo sh -c "printf 'Package: *\nPin: origin download.docker.com\nPin-Priority: 900\n' > /etc/apt/preferences.d/docker"
                sudo apt-get update >/dev/null 2>&1
                sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1
                ;;
            arch|manjaro)
                info "installing docker (Arch/Manjaro)…"
                sudo pacman -Sy --needed --noconfirm docker docker-compose >/dev/null 2>&1
                ;;
            *)
                warn "unsupported distro '$os' – install docker manually."
                return 1
                ;;
        esac
    else
        info "docker is present."
    fi

    if command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | grep -q '^docker\.service' ); then
        sudo systemctl enable --now docker 2>/dev/null || true
    fi
}
run_build_proxy() {
    local proj_dir="${tmp_folder}/${rnd_proj_name}"
    mkdir -p "${tmp_folder}/${rnd_proj_name}"/{exit_a,exit_b,haproxy,bitlaunch}

cat <<EOF > "${tmp_folder}/${rnd_proj_name}/.env"
int_network_container_subnet_cidr_ipv4="$int_network_container_subnet_cidr_ipv4"
int_network_container_gateway_ipv4="$int_network_container_gateway_ipv4"
int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
int_network_container_bitlaunch_ipv4="${int_network_container_bitlaunch_ipv4}"
ext_network_container_subnet_cidr_ipv4="$ext_network_container_subnet_cidr_ipv4"
ext_network_container_gateway_ipv4="$ext_network_container_gateway_ipv4"
ext_network_container_exit_a_ipv4="$ext_network_container_exit_a_ipv4"
ext_network_container_exit_b_ipv4="$ext_network_container_exit_b_ipv4"
tor_ctrl_pass="${tor_ctrl_pass}"
tor_ctrl_hash="${tor_ctrl_hash}"
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
services:
  exit_a:
    container_name: exit_a
    build:
      context: ./exit_a
      dockerfile: Dockerfile
      args:
        int_network_container_exit_a_ipv4: "${int_network_container_exit_a_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
        tor_ctrl_hash: "${tor_ctrl_hash}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "/usr/local/bin/healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    logging: { driver: "none" }
    networks:
      external_network:
        ipv4_address: ${ext_network_container_exit_a_ipv4}
      internal_network:
        ipv4_address: ${int_network_container_exit_a_ipv4}

  exit_b:
    container_name: exit_b
    build:
      context: ./exit_b
      dockerfile: Dockerfile
      args:
        int_network_container_exit_b_ipv4: "${int_network_container_exit_b_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
        tor_ctrl_hash: "${tor_ctrl_hash}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "/usr/local/bin/healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    logging: { driver: "none" }
    networks:
      external_network:
        ipv4_address: ${ext_network_container_exit_b_ipv4}
      internal_network:
        ipv4_address: ${int_network_container_exit_b_ipv4}

  haproxy:
    container_name: haproxy
    build:
      context: ./haproxy
      dockerfile: Dockerfile
      args:
        int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
        int_network_container_exit_a_ipv4: "${int_network_container_exit_a_ipv4}"
        int_network_container_exit_b_ipv4: "${int_network_container_exit_b_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    restart: always
    logging: { driver: "none" }
    depends_on:
      - exit_a
      - exit_b
    networks:
      internal_network:
        ipv4_address: ${int_network_container_haproxy_ipv4}

  bitlaunch:
    container_name: bitlaunch
    build:
      context: ./bitlaunch
      dockerfile: Dockerfile
      args:
        int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
        int_network_container_exit_a_ipv4: "${int_network_container_exit_a_ipv4}"
        int_network_container_exit_b_ipv4: "${int_network_container_exit_b_ipv4}"
        tor_ctrl_pass: "${tor_ctrl_pass}"
    runtime: runc
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    logging: { driver: "none" }
    networks:
      internal_network:
        ipv4_address: ${int_network_container_bitlaunch_ipv4}

networks:
  external_network:
    driver: bridge
    ipam:
      config:
        - subnet: ${ext_network_container_subnet_cidr_ipv4}
          gateway: ${ext_network_container_gateway_ipv4}
  internal_network:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${int_network_container_subnet_cidr_ipv4}
          gateway: ${int_network_container_gateway_ipv4}
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/exit_a/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_exit_a_ipv4
ARG tor_ctrl_pass
ARG tor_ctrl_hash

ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"
ENV tor_ctrl_hash="${tor_ctrl_hash}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl lsb-release gnupg2 netcat-openbsd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN ASC=$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/" | grep -oP '(?<=href=")[^"]+\.asc' | head -n 1) && \
    curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/${ASC}" | gpg --yes --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg && \
    echo "Types: deb deb-src\nComponents: main\nSuites: $(lsb_release -cs)\nURIs: https://deb.torproject.org/torproject.org\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/tor-archive-keyring.gpg" > /etc/apt/sources.list.d/tor.sources && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y tor deb.torproject.org-keyring

RUN mkdir -p /run/tor /var/lib/tor /usr/local/bin && \
    chown -R debian-tor:debian-tor /run/tor /var/lib/tor && \
    chmod 700 /run/tor /var/lib/tor

RUN cat > /etc/tor/torrc <<EOL
Log notice file /dev/null
SocksPort ${int_network_container_exit_a_ipv4}:9095
ControlPort ${int_network_container_exit_a_ipv4}:9051
HashedControlPassword ${tor_ctrl_hash}
CookieAuthentication 0
DataDirectory /var/lib/tor
CircuitBuildTimeout 40
NewCircuitPeriod 30
EnforceDistinctSubnets 1
EOL

RUN cat > /usr/local/bin/healthcheck <<'EOL'
#!/bin/bash
set -e
host="${int_network_container_exit_a_ipv4}"
pass="${tor_ctrl_pass}"
nc -z "$host" 9095 >/dev/null 2>&1 || exit 1
nc -z "$host" 9051 >/dev/null 2>&1 || exit 1
resp=$(printf 'AUTHENTICATE "%s"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$pass" | nc -w 6 "$host" 9051 | tr -d '\r') || true
echo "$resp" | grep -q 'PROGRESS=100' || true
exit 0
EOL
RUN chmod +x /usr/local/bin/healthcheck

RUN apt-get purge -y lsb-release gnupg2 curl  && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER debian-tor
ENTRYPOINT ["tor","-f","/etc/tor/torrc"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/exit_b/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_exit_b_ipv4
ARG tor_ctrl_pass
ARG tor_ctrl_hash

ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"
ENV tor_ctrl_hash="${tor_ctrl_hash}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl lsb-release gnupg2 netcat-openbsd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN ASC=$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/" | grep -oP '(?<=href=")[^"]+\.asc' | head -n 1) && \
    curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/${ASC}" | gpg --yes --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg && \
    echo "Types: deb deb-src\nComponents: main\nSuites: $(lsb_release -cs)\nURIs: https://deb.torproject.org/torproject.org\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/tor-archive-keyring.gpg" > /etc/apt/sources.list.d/tor.sources && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y tor deb.torproject.org-keyring

RUN mkdir -p /run/tor /var/lib/tor /usr/local/bin && \
    chown -R debian-tor:debian-tor /run/tor /var/lib/tor && \
    chmod 700 /run/tor /var/lib/tor

RUN cat > /etc/tor/torrc <<EOL
Log notice file /dev/null
SocksPort ${int_network_container_exit_b_ipv4}:9095
ControlPort ${int_network_container_exit_b_ipv4}:9051
HashedControlPassword ${tor_ctrl_hash}
CookieAuthentication 0
DataDirectory /var/lib/tor
CircuitBuildTimeout 40
NewCircuitPeriod 30
EnforceDistinctSubnets 1
EOL

RUN cat > /usr/local/bin/healthcheck <<'EOL'
#!/bin/bash
set -e
host="${int_network_container_exit_b_ipv4}"
pass="${tor_ctrl_pass}"
nc -z "$host" 9095 >/dev/null 2>&1 || exit 1
nc -z "$host" 9051 >/dev/null 2>&1 || exit 1
resp=$(printf 'AUTHENTICATE "%s"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$pass" | nc -w 6 "$host" 9051 | tr -d '\r') || true
echo "$resp" | grep -q 'PROGRESS=100' || true
exit 0
EOL
RUN chmod +x /usr/local/bin/healthcheck

RUN apt-get purge -y lsb-release gnupg2 curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER debian-tor
ENTRYPOINT ["tor","-f","/etc/tor/torrc"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/haproxy/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ARG int_network_container_exit_a_ipv4
ARG int_network_container_exit_b_ipv4
ARG tor_ctrl_pass

ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata haproxy curl netcat-openbsd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN cat > /usr/local/bin/check-exit-control.sh <<'EOL'
#!/bin/bash
set -e
host="$3"
pass="${tor_ctrl_pass}"

if nc -z "$host" 9051 >/dev/null 2>&1; then
    resp=$(printf 'AUTHENTICATE "%s"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$pass" | nc -w 6 "$host" 9051 | tr -d '\r') || true
    echo "$resp" | grep -q 'PROGRESS=100' || true
    exit 0
fi

exit 1
EOL
RUN chmod +x /usr/local/bin/check-exit-control.sh

RUN cat <<EOL > /etc/haproxy/haproxy.cfg
global
    log stdout format raw local0
    maxconn 4096
    user haproxy
    group haproxy
    external-check
    insecure-fork-wanted

defaults
    log global
    mode tcp
    option  dontlognull
    retries 3
    timeout connect 5s
    timeout client  60s
    timeout server  60s

frontend socks_proxy
    bind ${int_network_container_haproxy_ipv4}:9095
    default_backend socks_pool

backend socks_pool
    balance roundrobin
    option external-check
    external-check path "/usr/bin:/bin:/usr/local/bin"
    external-check command "/usr/local/bin/check-exit-control.sh"
    server exit_a ${int_network_container_exit_a_ipv4}:9095 check inter 20s rise 1 fall 2
    server exit_b ${int_network_container_exit_b_ipv4}:9095 check inter 20s rise 1 fall 2
EOL

RUN apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["haproxy","-f","/etc/haproxy/haproxy.cfg","-db"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/bitlaunch/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ARG int_network_container_exit_a_ipv4
ARG int_network_container_exit_b_ipv4
ARG tor_ctrl_pass

ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
ENV tor_ctrl_pass="${tor_ctrl_pass}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata bash bc jq curl netcat-openbsd bsdextrautils && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN useradd -m user && chown -R user:user /home/user

RUN cat <<'EOL' > /home/user/bitlaunch
#!/bin/bash
set -Eeuo pipefail

API_TOKEN=""
HTTP_HEADERS=()
PROXY_ARGS=(--proxy "socks5h://${int_network_container_haproxy_ipv4}:9095")

# ----- Global traps & helpers (clear UI but keep final message) -----

# Hide ^C echo on TTY and remember original stty flags
tty_is_tty=0
if [[ -t 1 ]]; then
    tty_is_tty=1
    __orig_stty="$(stty -g 2>/dev/null || true)"
    stty -echoctl 2>/dev/null || true
fi

cleanup() {
    # Always restore cursor if it was hidden
    tput cnorm 2>/dev/null || true

    # Restore TTY flags
    if [[ "${tty_is_tty}" -eq 1 ]]; then
        [[ -n "${__orig_stty:-}" ]] && stty "${__orig_stty}" 2>/dev/null || true
    fi
}

safe_fmt_date() {
    # Safe date format helper: if parsing fails, return the input as-is
    local _in="${1:-}"
    local _fmt="${2:-+%d.%m.%Y}"
    date -d "$_in" "$_fmt" 2>/dev/null || echo "$_in"
}
on_sigint() {
    # Clear previous UI (screen + scrollback), then show final message once
    if [[ -t 1 ]]; then
        printf '\e[2J\e[3J\e[H'
    fi
    echo "Interrupted by Ctrl+C. Exiting..."
    cleanup
    exit 130
}
on_sigterm() {
    if [[ -t 1 ]]; then
        printf '\e[2J\e[3J\e[H'
    fi
    echo "Received SIGTERM. Exiting..."
    cleanup
    exit 143
}

trap on_sigint INT
trap on_sigterm TERM
trap 'cleanup' EXIT

delay() {
    local min="${1:-1.5}"
    local max="${2:-2.0}"
    local seed rand
    seed="${RANDOM}$(od -An -N2 -i /dev/urandom 2>/dev/null || echo 0)"
    rand=$(awk -v min="$min" -v max="$max" -v seed="$seed" 'BEGIN{srand(systime() + seed); print min + rand() * (max - min)}')
    [[ -n "$rand" ]] && sleep "$rand"
}
validate_api_token() {
    local token="${1:-$API_TOKEN}"
    local expected_prefix="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    if [[ -z "$token" ]]; then
        echo "API Token is empty." >&2
        return 1
    fi
    if [[ "$token" != "$expected_prefix"* ]]; then
        echo "Invalid API Token." >&2
        return 1
    fi
}

# Prompt user for API Token, up to 3 attempts. Sets global $API_TOKEN
prompt_for_api_token() {
    local attempt=0
    local max_attempts=3

    while (( attempt < max_attempts )); do
        printf "Enter your API Token: "
        read -r API_TOKEN || true
        if validate_api_token "$API_TOKEN"; then
            echo "API Token accepted."
            return 0
        else
            echo "Invalid API Token. Please try again." >&2
            ((attempt++))
        fi
    done
    echo "You have reached the maximum number of attempts." >&2
    return 1
}

# Rotate Tor exit circuits for both exits (safe if env vars are missing)
tor_newnym() {
    local pass="${tor_ctrl_pass:-}"
    local exit_a="${int_network_container_exit_a_ipv4:-}"
    local exit_b="${int_network_container_exit_b_ipv4:-}"

    if [[ -z "$pass" || -z "$exit_a" || -z "$exit_b" ]]; then
        echo "Tor control parameters are not set; skipping circuit rotation."
        return 0
    fi

    local ok=0
    local resp_a
    resp_a="$(printf 'AUTHENTICATE "%s"\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$pass" | nc -w 3 "$exit_b" 9051 2>/dev/null || true)"
    echo "$resp_a" | grep -q '250 OK' && ok=$((ok+1))
    local resp_b
    resp_b="$(printf 'AUTHENTICATE "%s"\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$pass" | nc -w 3 "$exit_a" 9051 2>/dev/null || true)"
    echo "$resp_b" | grep -q '250 OK' && ok=$((ok+1))
    if [[ "$ok" -eq 2 ]]; then
        echo "Tor exit circuit rotated."
    else
        echo "Tor NEWNYM signal sent."
    fi
}

# Start fresh: ask for another API Token, new UA, rotate Tor
sign_in_to_another_account() {
    clear
    echo "Sign in to another account"
    if prompt_for_api_token; then
        HTTP_HEADERS=($(generate_http_headers))
        tor_newnym
        show_main_menu
    else
        echo "Invalid API Token."
        sleep 1
        show_main_menu
    fi
}

# Remove consecutive repeated characters (case-insensitive)
fix_repeats() {
    local temp_pass="$1"
    local adjusted_pass=""
    local prev_char=""
    local current_char=""
    local len=${#temp_pass}
    local i
    for ((i=0; i<len; i++)); do
        current_char="${temp_pass:i:1}"
        if [[ "${prev_char,,}" == "${current_char,,}" ]]; then
            while [[ "${prev_char,,}" == "${current_char,,}" ]]; do
                current_char=$(LC_ALL=C tr -dc 'A-Za-z0-9<>*+!?_=#@%^&' </dev/urandom | head -c 1)
            done
        fi
        adjusted_pass+="$current_char"
        prev_char="$current_char"
    done
    echo "$adjusted_pass"
}

# Generate a strong password: 45+2 chars, at least 7 unique special chars, no consecutive repeats
generate_password() {
    local special_chars='<>*+!?_=#@%^&'
    local required_specials=7
    local special_count=0
    local first_char last_char new_char password
    local length=45
    local total_length=$((length + 2))
    declare -A used_specials

    first_char=$(LC_ALL=C tr -dc 'A-Za-z' </dev/urandom | head -c 1)
    last_char=$(LC_ALL=C tr -dc 'A-Za-z' </dev/urandom | head -c 1)
    password="$first_char"

    while [[ ${#password} -lt $total_length ]] || [[ $special_count -lt $required_specials ]]; do
        new_char=$(LC_ALL=C tr -dc 'A-Za-z0-9<>*+!?_=#@%^&' </dev/urandom | head -c 1)
        if [[ "$special_chars" == *"$new_char"* ]]; then
            if [[ -n "${used_specials[$new_char]:-}" ]]; then
                continue
            fi
            used_specials[$new_char]=1
            ((special_count++))
        fi
        password+="$new_char"
        if [[ ${#password} -eq $total_length ]] && [[ $special_count -lt $required_specials ]]; then
            password="$first_char"
            special_count=0
            unset used_specials
            declare -A used_specials
        fi
    done
    password+="$last_char"

    local mixed
    local _
    for _ in {1..5}; do
        mixed=$(echo "${password:1:$((${#password}-2))}" | fold -w1 | shuf --random-source=/dev/urandom | tr -d '\n')
        mixed=$(fix_repeats "$mixed")
        password="$first_char$mixed$last_char"
    done

    echo "$password"
}

# Generates HTTP headers for API requests
generate_http_headers() {
    local -a user_agents=(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/90.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/92.0.902.62 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 11; Pixel 4a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Mobile Safari/537.36"
        "Mozilla/5.0 (X11; CrOS x86_64 13729.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (PlayStation 4 7.51) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.10 Safari/605.1.15"
        "Mozilla/5.0 (PlayStation 5 21.01-03.20.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15"
        "Mozilla/5.0 (Xbox One; Xbox OS 10.0.19041.3068) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.146 Safari/537.36"
        "Mozilla/5.0 (Xbox Series X; Xbox OS 10.0.19041.3068) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.146 Safari/537.36"
        "Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/6.0 Chrome/79.0.3945.146 TV Safari/537.36"
        "Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Version/2.1 TV Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        "Mozilla/5.0 (Linux; Android 11; SM-T860) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Linux; Android 10; SM-R800) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; LG-W200S) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; Nexus 6P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/92.0.902.67 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0 Mobile Safari/537.36"
        "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.37 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.37 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
    )

    local idx=$(( RANDOM % ${#user_agents[@]} ))
    local ua="${user_agents[$idx]}"
    local header_string=""
    if [[ "$ua" == *"Chrome"* && "$ua" != *"Edge"* ]]; then
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    elif [[ "$ua" == *"Firefox"* ]]; then
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    elif [[ "$ua" == *"Safari"* && "$ua" != *"Chrome"* ]]; then
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\" -H \"Accept-Encoding: gzip, deflate\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    elif [[ "$ua" == *"Edge"* ]]; then
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    else
        header_string="-A \"$ua\" -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\" -H \"Accept-Encoding: gzip, deflate, br\" -H \"Accept-Language: en-US,en;q=0.9\" -H \"Connection: keep-alive\" -H \"Upgrade-Insecure-Requests: 1\""
    fi
    echo "$header_string"
}

# Lists all virtual machines in your account
list_vms() {
    clear
    echo "Listing VMs..."

    local i=0
    local user_data
    until ((i++ >= 3)) || { user_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/user"); [[ -n "$user_data" ]]; }; do delay; done
    delay

    i=0
    local server_data
    until ((i++ >= 3)) || { server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/servers"); [[ -n "$server_data" ]]; }; do delay; done

    if [[ "$user_data" != "null" && -n "$user_data" ]]; then
        local account_creation_date balance email email_confirmed
        account_creation_date=$(echo "$user_data" | jq -r '.created')
        balance=$(echo "$user_data" | jq -r '.balance / 1000')
        balance=${balance:-0}
        email=$(echo "$user_data" | jq -r '.email')
        email_confirmed=$(echo "$user_data" | jq -r '.emailConfirmed')

        if [[ "$(echo "$server_data" | jq -r '. | length')" -eq 0 ]]; then
            clear; printf '\e[3J'
            printf "%-25s %s\n" "Created On:" "$(safe_fmt_date "$account_creation_date" "+%d.%m.%Y")"
            printf "%-25s %s\n" "Account ID:" "$email"
            if [[ "$email_confirmed" == "true" ]]; then
                printf "%-25s %s\n" "Email confirmed:" "+"
            else
                printf "%-25s %s\n" "Email confirmed:" "-"
            fi
            printf "%-25s %s USD\n\n" "Balance:" "$balance"
            echo
            echo "No VM available."
        else
            clear; printf '\e[3J'
            printf "%-25s %s\n" "Created On:" "$(safe_fmt_date "$account_creation_date" "+%d.%m.%Y")"
            printf "%-25s %s\n" "Account ID:" "$email"
            if [[ "$email_confirmed" == "true" ]]; then
                printf "%-25s %s\n" "Email confirmed:" "+"
            else
                printf "%-25s %s\n" "Email confirmed:" "-"
            fi
            printf "%-25s %s USD\n\n" "Balance:" "$balance"

            local vm_ids
            IFS=$'\n' read -rd '' -a vm_ids < <(echo "$server_data" | jq -r '.[].id' && printf '\0')
            for vm_id in "${vm_ids[@]}"; do
                local server creation_date cost_per_hour vm_ip host host_image_id size name status errortext image_description
                server=$(echo "$server_data" | jq -r --arg vm_id "$vm_id" '.[] | select(.id == $vm_id)')
                creation_date=$(echo "$server" | jq -r '.created')
                cost_per_hour=$(echo "$server" | jq -r '.rate / 1000')
                vm_ip=$(echo "$server" | jq -r '.ipv4')
                host=$(echo "$server" | jq -r '.host')
                host_image_id=$(echo "$server" | jq -r '.image')
                size=$(echo "$server" | jq -r '.size')
                name=$(echo "$server" | jq -r '.name')
                status=$(echo "$server" | jq -r '.status')
                errortext=$(echo "$server" | jq -r '.errorText')
                image_description=$(echo "$server" | jq -r '.imageDescription')

                if [[ -z "$cost_per_hour" || -z "$balance" || ! "$cost_per_hour" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                    echo "Error when retrieving cost per hour or balance for VM ID: $vm_id"
                    continue
                fi

                local remaining_hours remaining_days monthly_cost host_name end_date
                remaining_hours=$(echo "$balance / $cost_per_hour" | bc)
                remaining_days=$(echo "$remaining_hours / 24" | bc)
                monthly_cost=$(echo "$cost_per_hour * 730" | bc)
                host_name=$( [[ "$host" -eq 4 ]] && echo "Bitlaunch" || ( [[ "$host" -eq 0 ]] && echo "Digital Ocean" ) )
                errortext=${errortext:-"No errors"}

                if [[ -z "$creation_date" ]]; then
                    echo "Creation date not found for VM ID: $vm_id"
                    end_date="--.--.--"
                else
                    end_date=$(safe_fmt_date "$(date -d "$creation_date + $remaining_hours hours" "+%Y-%m-%d")" "+%d.%m.%Y")
                fi

                printf "%-25s %s\n" "Host:" "$host_name"
                printf "%-25s %s\n" "VM ID:" "$vm_id"
                printf "%-25s %s\n" "VM Created On:" "$(safe_fmt_date "$creation_date" "+%d.%m.%Y")"
                printf "%-25s %s\n" "IP Address:" "$vm_ip"
                printf "%-25s %s\n" "Status:" "$status"
                printf "%-25s %s\n" "Error Text:" "$errortext"
                if [[ "$name" =~ ^[^_]+_[^_]+_[^_]+$ ]]; then
                    local plan_type plan_spec region
                    IFS='_' read -r plan_type plan_spec region <<< "$name"
                    plan_spec=$(echo "$plan_spec" | sed 's/-/\//g')
                    plan_type=$(echo "$plan_type" | sed 's/-/ /g')
                    region=$(echo "$region" | sed 's/-/ /g')
                    printf "%-25s %s\n" "Region:" "$region"
                    printf "%-25s %s\n" "Plan:" "$plan_type"
                    printf "%-25s %s\n" "Specs:" "$plan_spec"
                else
                    printf "%-25s %s\n" "VM Name:" "$name"
                fi
                printf "%-25s %s\n" "OS:" "$image_description"
                printf "%-25s %s\n" "Expires On:" "$end_date"
                printf "%-25s %s days\n" "Time Left:" "$remaining_days"
                printf "%-25s %s USD\n\n" "Monthly Cost:" "$monthly_cost"
            done
        fi
    else
        echo 'Your API Token is not valid or response is empty'
    fi

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Creates a new VM on Bitlaunch
create_vm_bitlaunch() {
    clear
    echo "Creating VM on Bitlaunch..."

    local i=0 user_data
    until ((i++ >= 3)) || { user_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/user"); [[ -n "$user_data" ]]; }; do delay; done
    local balance=$(echo "$user_data" | jq -r '.balance / 1000')
    [[ "$balance" == "0" ]] && { clear; printf '\e[3J'; printf "It is impossible to create a virtual machine because there are insufficient funds in your account.\nPlease top up your account and try again.\n"; show_server_menu; return; }

    i=0
    local bit_json
    until ((i++ >= 3)) || { bit_json=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/hosts-create-options/4"); [[ -n "$bit_json" ]] && [[ "$bit_json" != "{}" ]] && [[ "$(echo "$bit_json" | jq -r '. | length')" -gt 0 ]]; }; do delay; done
    [[ -z "$bit_json" ]] || [[ "$bit_json" == "{}" ]] || [[ "$(echo "$bit_json" | jq -r '. | length')" -eq 0 ]] && { echo "API Token is not valid"; show_server_menu; return; }

    local standard=$(echo "$bit_json" | jq -r '.size | map(select(.planType == "standard")) | .[0:6] | map("\(.id) \(.cpuCount)CPU/\(.memoryMB / 1024)GB \(.diskGB)GB \(.disks[].type) \(.costPerMonth) USD/Month") | join("\n")')
    local plan_ids=$(echo "$bit_json" | jq -r '.size | map(select(.planType == "standard")) | .[0:6] | map(.id) | join(" ")')
    local image_id=$(echo "$bit_json" | jq -r '.image[] | select(.name == "Debian" and .version.description == "Debian 13").version.id')
    local available_regions=$(echo "$bit_json" | jq --argjson ids "$(echo $plan_ids | jq -sR 'split(" ")')" -r '.region[] as $region | $region.name as $region_name | $region.subregions[] as $subregion | $subregion.unavailableSizes as $unavailable | $ids | map(. as $id | if ($unavailable | index($id)) then empty else $id end) as $availableIds | { region: $region_name,subregion: $subregion.slug,availableSizes: $availableIds } | "\(.region), \(.subregion), \(.availableSizes | if . == [] then "None" else join(", ") end)\n"' | sed '/^$/d')
    local plan_type_standard=$(echo "$bit_json" | jq -r '.planTypes[0].name')
    local password="$(generate_password)"
    local host_name="Bitlaunch"
    local IFS=$'\n'
    local options=($standard)

    echo "Please select a plan:"
    for index in "${!options[@]}"; do
        local display_text=$(echo "${options[index]}" | cut -d ' ' -f2-)
        printf "%d\t%s\n" $((index + 1)) "$display_text"
    done | column -t

    local plan_attempt=0 choice
    while ((plan_attempt++ < 3)); do
        echo
        echo "b. Back"
        echo "m. Main"
        echo "x. Exit"
        echo
        echo -n "Enter the number of the VM you choose: "
        read -r choice || true
        case "$choice" in
            b|B) show_server_menu; return ;;
            m|M) show_main_menu; return ;;
            x|X) exit_program ;;
        esac

        if [[ -n "${choice:-}" ]] && [[ "$choice" -gt 0 ]] && [[ "$choice" -le "${#options[@]}" ]]; then
            local chosen_plan_info=${options[$choice-1]}
            local selected_plan_id=$(echo "$chosen_plan_info" | awk '{print $1}')
            echo "You have chosen the plan: $(echo "$chosen_plan_info" | cut -d ' ' -f2-)"
            local selected_plan_spec=$(echo "$chosen_plan_info" | awk '{print $2}' | sed 's/\//-/g')

            echo "Available region for the chosen plan:"
            local regions
            IFS=$'\n' read -rd '' -a regions < <(echo "$available_regions" | jq -R -s "split(\"\n\") | .[] | select(contains(\"$selected_plan_id\")) | split(\", \") | .[0]" | tr -d '"' | sort | uniq && printf '\0')
            for index in "${!regions[@]}"; do
                echo "$((index + 1)) ${regions[index]}"
            done

            local region_attempt=0 region_choice
            while ((region_attempt++ < 3)); do
                echo -n "Choose the region by number: "
                read -r region_choice || true
                case "$region_choice" in
                    b|B) show_server_menu; return ;;
                    m|M) show_main_menu; return ;;
                    x|X) exit_program ;;
                esac

                if [[ -n "${region_choice:-}" ]] && [[ "$region_choice" -gt 0 ]] && [[ "$region_choice" -le "${#regions[@]}" ]]; then
                    local selected_region="${regions[$region_choice-1]}"
                    local selected_subregion=$(echo "$available_regions" | jq -R -s "split(\"\n\") | .[] | select(contains(\"$selected_region\") and contains(\"$selected_plan_id\")) | split(\", \") | .[1]" | shuf -n 1 | tr -d '"')
                    selected_region=$(echo "$selected_region" | sed 's/ /-/g; s/-$//')
                    local vm_name="${plan_type_standard}_${selected_plan_spec}_${selected_region}"
                    local plan_spec=$(echo "$selected_plan_spec" | sed 's/-/\//g')
                    local region=$(echo "$selected_region" | sed 's/-/ /g')
                    local max_attempts=2 attempt=0 vm_created=false

                    while [[ $attempt -lt $max_attempts && "$vm_created" == false ]]; do
                        local response j=0
                        until ((j++ >= 2)) || {
                            response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" -d '{"server": {"name": "'"$vm_name"'", "hostID": 4, "hostImageID": "'"$image_id"'", "sizeID": "'"$selected_plan_id"'", "regionID": "'"$selected_subregion"'", "password": "'"$password"'"}}' -X POST "https://app.bitlaunch.io/api/servers")
                            [[ -n "$response" ]] && [[ "$response" != "{}" ]] && [[ "$(echo "$response" | jq -r '. | length')" -gt 0 ]]
                        }; do delay; done
                        [[ -z "$response" ]] || [[ "$response" == "{}" ]] || [[ "$(echo "$response" | jq -r '. | length')" -eq 0 ]] && { echo "API Token is not valid or server is not responding"; show_server_menu; return; }

                        local vm_id=$(echo "$response" | jq -r '.id')
                        clear; printf '\e[3J'
                        echo "Creating VM ..."
                        sleep 60

                        local server_data
                        j=0
                        until ((j++ >= 3)) || { server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/servers"); [[ -n "$server_data" ]]; }; do delay; done
                        local last_vm=$(echo "$server_data" | jq --arg vm_id "$vm_id" -r '.[] | select(.id == $vm_id)')
                        local status=$(echo "$last_vm" | jq -r '.status')
                        local vm_ip=$(echo "$last_vm" | jq -r '.ipv4')

                        if [[ "$status" == "error" ]] || [[ -z "$vm_ip" ]]; then
                            j=0
                            until ((j++ >= 2)) || {
                                response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" -X DELETE "https://app.bitlaunch.io/api/servers/${vm_id}")
                                [[ -n "$response" ]]
                            }; do delay; done
                            if [[ "$(echo "$response" | jq '.')" == "null" ]] || [[ "$(echo "$response" | jq '.')" == "{}" ]]; then
                                clear; printf '\e[3J'
                                echo "The virtual machine has been successfully deleted."
                            else
                                clear; printf '\e[3J'
                                echo "There was an issue deleting the virtual machine:"
                            fi
                            echo "Attempt $((attempt + 1)) failed, retrying..."
                            ((attempt++))
                        else
                            vm_created=true
                            clear; printf '\e[3J'
                            echo
                            printf "%-25s %s\n" "Host Name:" "$host_name"
                            printf "%-25s %s\n" "Specs:" "$plan_spec"
                            printf "%-25s %s\n" "Region:" "$region"
                            printf "%-25s %s\n" "IP:" "$vm_ip"
                            printf "%-25s %s\n" "Password:" "$password"
                            echo
                            break
                        fi
                    done

                    if [[ "$vm_created" == false ]]; then
                        echo "Failed to create VM after $max_attempts attempts."
                    fi
                    break
                else
                    echo "Invalid region choice. Try again."
                fi
            done
            break
        else
            echo "Invalid selection. Try again."
        fi
    done

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Creates a new VM on Digital Ocean
create_vm_digital_ocean() {
    clear
    echo "Creating VM on Digital Ocean..."

    local i=0 user_data
    until ((i++ >= 3)) || { user_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/user"); [[ -n "$user_data" ]]; }; do delay; done
    local balance=$(echo "$user_data" | jq -r '.balance / 1000')
    [[ "$balance" == "0" ]] && { clear; printf '\e[3J'; printf "It is impossible to create a virtual machine because there are insufficient funds in your account.\nPlease top up your account and try again.\n"; show_server_menu; return; }

    delay

    i=0
    local do_json
    until ((i++ >= 3)) || { do_json=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/hosts-create-options/0"); [[ -n "$do_json" ]] && [[ "$do_json" != "{}" ]] && [[ "$(echo "$do_json" | jq -r '. | length')" -gt 0 ]]; }; do delay; done
    [[ -z "$do_json" ]] || [[ "$do_json" == "[]" ]] || [[ "$(echo "$do_json" | jq -r '. | length')" -eq 0 ]] && { echo "API Token is not valid"; show_server_menu; return; }

    local unavailable_sizes unavailable_regions
    unavailable_sizes=$(echo "$do_json" | jq -r '.region[] | .subregions[] | select(.unavailableSizes[] | startswith("s-")) | .unavailableSizes | join(" ")')
    unavailable_regions=$(echo "$do_json" | jq -r '[.image[] | select(.name == "Debian" and any(.versions[]; .description == "Debian 13 x64"))] | .[].unavailableRegions | join(" ")')

    local standard nvme regions image_id password host_name plan_type_standard plan_type_nvme
    standard=$(echo "$do_json" | jq -r --arg unavailable_sizes "$unavailable_sizes" '.size | map(select(.planType != "cpu" and .planType == "standard")) | map(select(.id as $id | ($unavailable_sizes | split(" ")) | index($id) | not)) | .[0:6] | map("\(.id) \(.cpuCount)CPU/\(.memoryMB / 1024)GB \(.diskGB)GB \(.disks[].type) \(.costPerMonth) USD/Month") | join("\n")')
    nvme=$(echo "$do_json" | jq -r --arg unavailable_sizes "$unavailable_sizes" '.size | map(select(.planType != "cpu" and .planType == "nvme")) | map(select(.id as $id | ($unavailable_sizes | split(" ")) | index($id) | not)) | .[0:6] | map("\(.id) \(.cpuCount)CPU/\(.memoryMB / 1024)GB \(.diskGB)GB \(.disks[].type) \(.costPerMonth) USD/Month") | join("\n")')
    regions=$(echo "$do_json" | jq -r --arg unavailable_regions "$unavailable_regions" '.region[] | .name as $name | .subregions | [$name, (map(select(.id as $id | ($unavailable_regions | split(" ")) | index($id) | not) | .id) | join(" "))] | @tsv')
    image_id=$(echo "$do_json" | jq -r '.image[] | select(.name == "Debian" and .version.description == "Debian 13 x64").version.id')
    password="$(generate_password)"
    host_name="Digital Ocean"
    plan_type_standard="$(echo "$do_json" | jq -r '.planTypes[0].name')"
    plan_type_nvme="$(echo "$do_json" | jq -r '.planTypes[1].name' | sed -e 's/ *+ */-/')"

    local IFS=$'\n'
    local standard_options=()
    local nvme_options=()
    local a=1
    for plan in $standard; do
        standard_options+=("$a $plan")
        a=$((a + 1))
    done

    local b=1
    for plan in $nvme; do
        nvme_options+=("$((a + b - 1)) $plan")
        b=$((b + 1))
    done

    echo "Please select a plan:"
    echo "$host_name: $plan_type_standard"
    for index in "${!standard_options[@]}"; do
        local display_text
        display_text=$(echo "${standard_options[index]}" | cut -d ' ' -f3-)
        printf "%d\t%s\n" $((index + 1)) "$display_text"
    done | column -t
    echo
    echo "$host_name: $plan_type_nvme"
    for index in "${!nvme_options[@]}"; do
        local display_text
        display_text=$(echo "${nvme_options[index]}" | cut -d ' ' -f3-)
        printf "%d\t%s\n" $((index + 1 + ${#standard_options[@]})) "$display_text"
    done | column -t

    local plan_attempt=0
    local choice
    local total_options=$(( ${#standard_options[@]} + ${#nvme_options[@]} ))

    while ((plan_attempt++ < 3)); do
        echo
        echo "b. Back"
        echo "m. Main"
        echo "x. Exit"
        echo
        echo -n "Enter the number of the VM you choose: "
        read -r choice || true

        case "$choice" in
            b|B) show_server_menu; return ;;
            m|M) show_main_menu; return ;;
            x|X) exit_program ;;
        esac

        if [[ -n "${choice:-}" ]] && [[ "$choice" -gt 0 ]] && [[ "$choice" -le "$total_options" ]]; then
            local chosen_plan plan_type chosen_plan_info
            if [[ "$choice" -le "${#standard_options[@]}" ]]; then
                chosen_plan=${standard_options[$choice-1]}
                plan_type="$plan_type_standard"
                chosen_plan_info=$(echo "$standard" | sed -n "${choice}p")
            else
                local local_index=$((choice - ${#standard_options[@]}))
                chosen_plan=${nvme_options[$local_index-1]}
                plan_type="$plan_type_nvme"
                chosen_plan_info=$(echo "$nvme" | sed -n "${local_index}p")
            fi
            local selected_plan_id selected_plan_spec
            selected_plan_id=$(echo "$chosen_plan_info" | awk '{print $1}')
            selected_plan_spec=$(echo "$chosen_plan_info" | awk '{print $2}' | sed 's/\//-/g')

            echo "You have chosen the plan: $(echo "$chosen_plan" | cut -d ' ' -f3-)"
            echo "This corresponds to: $plan_type Plan ID $selected_plan_id"

            local region_attempt=0
            local region_choice

            echo "Available region for the chosen plan:"
            local i=1
            local region_ids=()
            local region_names=()
            while read -r line; do
                local region subregions
                region=$(echo "$line" | cut -f1)
                subregions=$(echo "$line" | cut -f2-)
                if [ -n "$subregions" ]; then
                    echo "$i $region"
                    region_names+=("$region")
                    region_ids+=("$subregions")
                    i=$((i + 1))
                fi
            done <<< "$regions"

            while ((region_attempt++ < 3)); do
                echo -n "Enter the number of the region you choose: "
                read -r region_choice || true
                case "$region_choice" in
                    b|B) show_server_menu; return ;;
                    m|M) show_main_menu; return ;;
                    x|X) exit_program ;;
                esac

                local selected_region_index=$((region_choice-1))
                if [[ -n "${region_choice:-}" ]] && [[ "$region_choice" -gt 0 ]] && [[ "$region_choice" -le "${#region_ids[@]}" ]]; then
                    IFS=', ' read -ra selected_subregions <<< "${region_ids[$selected_region_index]}"
                    local selected_subregion selected_region vm_name plan_spec region max_attempts attempt vm_created
                    selected_subregion=${selected_subregions[$RANDOM % ${#selected_subregions[@]}]}
                    selected_region=$(echo "${region_names[$selected_region_index]}" | sed 's/ /-/g; s/-$//')
                    vm_name="${plan_type}_${selected_plan_spec}_${selected_region}"
                    plan_spec=$(echo "$selected_plan_spec" | sed 's/-/\//g')
                    region=$(echo "$selected_region" | sed 's/-/ /g')
                    max_attempts=2
                    attempt=0
                    vm_created=false

                    while [[ $attempt -lt $max_attempts && "$vm_created" == false ]]; do
                        local response
                        local j=0
                        until ((j++ >= 2)) || {
                            response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" -d '{"server": {"name": "'"$vm_name"'","hostID": 0,"hostImageID": "'"$image_id"'","sizeID": "'"$selected_plan_id"'","regionID": "'"$selected_subregion"'","password": "'"$password"'"}}' -X POST "https://app.bitlaunch.io/api/servers")
                            [[ -n "$response" ]] && [[ "$response" != "{}" ]] && [[ "$(echo "$response" | jq -r '. | length')" -gt 0 ]]
                        }; do delay; done
                        [[ -z "$response" ]] || [[ "$response" == "{}" ]] || [[ "$(echo "$response" | jq -r '. | length')" -eq 0 ]] && { echo "API Token is not valid or server is not responding"; show_server_menu; return; }

                        local vm_id
                        vm_id=$(echo "$response" | jq -r '.id')
                        clear; printf '\e[3J'
                        echo "Creating VM ..."
                        sleep 60

                        local server_data
                        j=0
                        until ((j++ >= 3)) || { server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" "https://app.bitlaunch.io/api/servers"); [[ -n "$server_data" ]]; }; do delay; done
                        local last_vm status vm_ip
                        last_vm=$(echo "$server_data" | jq --arg vm_id "$vm_id" -r '.[] | select(.id == $vm_id)')
                        status=$(echo "$last_vm" | jq -r '.status')
                        vm_ip=$(echo "$last_vm" | jq -r '.ipv4')

                        if [[ "$status" == "error" ]] || [[ -z "$vm_ip" ]]; then
                            j=0
                            until ((j++ >= 2)) || {
                                response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" -X DELETE "https://app.bitlaunch.io/api/servers/${vm_id}")
                                [[ -n "$response" ]]
                            }; do delay; done
                            if [[ "$(echo "$response" | jq '.')" == "null" ]] || [[ "$(echo "$response" | jq '.')" == "{}" ]]; then
                                clear; printf '\e[3J'
                                echo "The VM with error has been successfully deleted."
                            else
                                clear; printf '\e[3J'
                                echo "There was an issue deleting the VM:"
                            fi
                            echo "Attempt $((attempt + 1)) failed, retrying..."
                            ((attempt++))
                        else
                            vm_created=true
                            clear; printf '\e[3J'
                            echo
                            printf "%-25s %s\n" "Host Name:" "$host_name"
                            printf "%-25s %s\n" "Specs:" "$plan_spec"
                            printf "%-25s %s\n" "Region:" "$region"
                            printf "%-25s %s\n" "IP:" "$vm_ip"
                            printf "%-25s %s\n" "Password:" "$password"
                            echo
                            break
                        fi
                    done

                    if [[ "$vm_created" == false ]]; then
                        echo "Failed to create VM after $max_attempts attempts."
                    fi
                    break
                else
                    echo "Invalid region choice. Try again."
                fi
            done
            break
        else
            echo "Invalid selection. Try again."
        fi
    done

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Deletes a virtual machine
remove_vm() {
    clear
    echo "Removing VM..."
    local i=0 server_data
    until ((i++ >= 3)); do
        server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
            "https://app.bitlaunch.io/api/servers")
        [[ -n "$server_data" ]] && break
        delay
    done

    if [[ "$(echo "$server_data" | jq -r '. | length')" -gt 0 ]]; then
        local vm_ids=($(echo "$server_data" | jq -r '.[].id'))
        local vm_choices=()
        local vm_index=1

        clear; printf '\e[3J'
        for vm_id in "${vm_ids[@]}"; do
            local server=$(echo "$server_data" | jq -r --arg VM_ID "$vm_id" '.[] | select(.id == $VM_ID)')
            local vm_ip=$(echo "$server" | jq -r '.ipv4')
            local host=$(echo "$server" | jq -r '.host')
            local host_image_id=$(echo "$server" | jq -r '.image')
            local name=$(echo "$server" | jq -r '.name')
            local status=$(echo "$server" | jq -r '.status')
            local image_description=$(echo "$server" | jq -r '.imageDescription')
            local host_name=$( [[ "$host" -eq 4 ]] && echo "Bitlaunch" || ([[ "$host" -eq 0 ]] && echo "Digital Ocean" ) )

            printf "%-25s %s\n" "VM:" "$vm_index"
            printf "%-25s %s\n" "Host:" "$host_name"
            printf "%-25s %s\n" "VM ID:" "$vm_id"
            printf "%-25s %s\n" "IP Address:" "$vm_ip"
            printf "%-25s %s\n" "Status:" "$status"
            if [[ "$name" =~ ^[^_]+_[^_]+_[^_]+$ ]]; then
                IFS='_' read -r plan_type plan_spec region <<< "$name"
                plan_spec=$(echo "$plan_spec" | sed 's/-/\//g')
                plan_type=$(echo "$plan_type" | sed 's/-/ /g')
                region=$(echo "$region" | sed 's/-/ /g')
                printf "%-25s %s\n" "Region:" "$region"
                printf "%-25s %s\n" "Plan:" "$plan_type"
                printf "%-25s %s\n" "Specs:" "$plan_spec"
            else
                printf "%-25s %s\n" "VM Name:" "$name"
            fi
            printf "%-25s %s\n" "OS:" "$image_description"
            echo

            vm_choices+=("$vm_id|$host_image_id|$image_description")
            vm_index=$((vm_index + 1))
        done

        local attempt=0 choice
        while ((attempt++ < 3)); do
            echo "b. Back"
            echo "m. Main"
            echo "x. Exit"
            echo -n "?: "
            read -r choice || true

            case "$choice" in
                b|B) show_server_menu; return ;;
                m|M) show_main_menu; return ;;
                x|X) exit_program ;;
            esac

            if [[ -n "${choice:-}" ]] && [[ $choice =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#vm_ids[@]}" ]]; then
                local vm_id="${vm_ids[$((choice-1))]}"
                echo
                echo -n "Are you sure you want to delete the VM? (y/n): "
                read -r confirmation || true
                case "$confirmation" in
                    y|Y)
                        clear; printf '\e[3J'
                        echo "Proceeding with VM deletion..."
                        local j=0 response
                        until ((j++ >= 2)); do
                            response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
                                --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
                                -H "Content-Type: application/json" -X DELETE \
                                "https://app.bitlaunch.io/api/servers/${vm_id}")
                            [[ -n "$response" ]] && break
                            delay
                        done
                        if [[ "$(echo "$response" | jq '.')" == "null" ]] || [[ "$(echo "$response" | jq '.')" == "{}" ]]; then
                            clear; printf '\e[3J'
                            echo "The virtual machine has been successfully deleted."
                        else
                            clear; printf '\e[3J'
                            echo "There was an issue deleting the virtual machine:"
                            echo "$response" | jq .
                        fi
                        break
                        ;;
                    n|N)
                        clear; printf '\e[3J'
                        echo "VM deletion canceled."
                        break
                        ;;
                    *)
                        echo "Invalid input. Please enter 'y' or 'n'."
                        ;;
                esac
            else
                echo "Invalid selection. Please try again."
            fi
        done
    else
        echo "No VM available."
    fi

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Restarts a virtual machine
restart_vm() {
    clear
    echo "Restarting VM..."
    local i=0 server_data
    until ((i++ >= 3)); do
        server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
            "https://app.bitlaunch.io/api/servers")
        [[ -n "$server_data" ]] && break
        delay
    done

    if [[ "$(echo "$server_data" | jq -r '. | length')" -gt 0 ]]; then
        local vm_ids=($(echo "$server_data" | jq -r '.[].id'))
        local vm_choices=()
        local vm_index=1

        clear; printf '\e[3J'
        for vm_id in "${vm_ids[@]}"; do
            local server=$(echo "$server_data" | jq -r --arg VM_ID "$vm_id" '.[] | select(.id == $VM_ID)')
            local vm_ip=$(echo "$server" | jq -r '.ipv4')
            local host=$(echo "$server" | jq -r '.host')
            local name=$(echo "$server" | jq -r '.name')
            local status=$(echo "$server" | jq -r '.status')
            local image_description=$(echo "$server" | jq -r '.imageDescription')
            local host_name=$( [[ "$host" -eq 4 ]] && echo "Bitlaunch" || ([[ "$host" -eq 0 ]] && echo "Digital Ocean" ) )

            printf "%-25s %s\n" "VM:" "$vm_index"
            printf "%-25s %s\n" "Host:" "$host_name"
            printf "%-25s %s\n" "VM ID:" "$vm_id"
            printf "%-25s %s\n" "IP Address:" "$vm_ip"
            printf "%-25s %s\n" "Status:" "$status"
            if [[ "$name" =~ ^[^_]+_[^_]+_[^_]+$ ]]; then
                IFS='_' read -r plan_type plan_spec region <<< "$name"
                plan_spec=$(echo "$plan_spec" | sed 's/-/\//g')
                plan_type=$(echo "$plan_type" | sed 's/-/ /g')
                region=$(echo "$region" | sed 's/-/ /g')
                printf "%-25s %s\n" "Region:" "$region"
                printf "%-25s %s\n" "Plan:" "$plan_type"
                printf "%-25s %s\n" "Specs:" "$plan_spec"
            else
                printf "%-25s %s\n" "VM Name:" "$name"
            fi
            printf "%-25s %s\n" "OS:" "$image_description"
            echo

            vm_choices+=("$vm_id")
            vm_index=$((vm_index + 1))
        done

        local attempt=0 choice
        while ((attempt++ < 3)); do
            echo "b. Back"
            echo "m. Main"
            echo "x. Exit"
            echo -n "?: "
            read -r choice || true

            case "$choice" in
                b|B) show_server_menu; return ;;
                m|M) show_main_menu; return ;;
                x|X) exit_program ;;
            esac

            if [[ -n "${choice:-}" ]] && [[ $choice =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#vm_ids[@]}" ]]; then
                vm_id="${vm_choices[$((choice-1))]}"
                clear; printf '\e[3J'
                echo "Proceeding with VM restarting..."
                local j=0 response
                until ((j++ >= 2)); do
                    response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
                        --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
                        -X POST "https://app.bitlaunch.io/api/servers/${vm_id}/restart")
                    [[ -n "$response" ]] && break
                    delay
                done
                if [[ "$(echo "$response" | jq '.')" == "null" ]] || [[ "$(echo "$response" | jq '.')" == "{}" ]]; then
                    clear; printf '\e[3J'
                    echo "The virtual machine has been successfully restarted."
                else
                    clear; printf '\e[3J'
                    echo "There was an issue restarting the virtual machine:"
                    echo "$response" | jq .
                fi
                break
            else
                echo "Invalid selection. Please try again."
            fi
        done
    else
        echo
        echo "No VM available."
    fi

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Rebuilds a virtual machine (reinstall OS)
rebuild_vm() {
    clear
    echo "Rebuilding VM..."
    local i=0 server_data
    until ((i++ >= 3)); do
        server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
            "https://app.bitlaunch.io/api/servers")
        [[ -n "$server_data" ]] && break
        delay
    done

    if [[ "$(echo "$server_data" | jq -r '. | length')" -gt 0 ]]; then
        local vm_ids=($(echo "$server_data" | jq -r '.[].id'))
        local vm_choices=()
        local vm_index=1

        clear; printf '\e[3J'
        for vm_id in "${vm_ids[@]}"; do
            local server=$(echo "$server_data" | jq -r --arg VM_ID "$vm_id" '.[] | select(.id == $VM_ID)')
            local vm_ip=$(echo "$server" | jq -r '.ipv4')
            local host=$(echo "$server" | jq -r '.host')
            local host_image_id=$(echo "$server" | jq -r '.image')
            local name=$(echo "$server" | jq -r '.name')
            local status=$(echo "$server" | jq -r '.status')
            local image_description=$(echo "$server" | jq -r '.imageDescription')
            local host_name=$( [[ "$host" -eq 4 ]] && echo "Bitlaunch" || ([[ "$host" -eq 0 ]] && echo "Digital Ocean" ) )

            printf "%-25s %s\n" "VM:" "$vm_index"
            printf "%-25s %s\n" "Host:" "$host_name"
            printf "%-25s %s\n" "VM ID:" "$vm_id"
            printf "%-25s %s\n" "IP Address:" "$vm_ip"
            printf "%-25s %s\n" "Status:" "$status"
            if [[ "$name" =~ ^[^_]+_[^_]+_[^_]+$ ]]; then
                IFS='_' read -r plan_type plan_spec region <<< "$name"
                plan_spec=$(echo "$plan_spec" | sed 's/-/\//g')
                plan_type=$(echo "$plan_type" | sed 's/-/ /g')
                region=$(echo "$region" | sed 's/-/ /g')
                printf "%-25s %s\n" "Region:" "$region"
                printf "%-25s %s\n" "Plan:" "$plan_type"
                printf "%-25s %s\n" "Specs:" "$plan_spec"
            else
                printf "%-25s %s\n" "VM Name:" "$name"
            fi
            printf "%-25s %s\n" "OS:" "$image_description"
            echo

            vm_choices+=("$vm_id|$host_image_id|$image_description|$status")
            vm_index=$((vm_index + 1))
        done

        local attempt=0 choice
        while ((attempt++ < 3)); do
            echo "b. Back"
            echo "m. Main"
            echo "x. Exit"
            echo -n "?: "
            read -r choice || true

            case "$choice" in
                b|B) show_server_menu; return ;;
                m|M) show_main_menu; return ;;
                x|X) exit_program ;;
            esac

            if [[ -n "${choice:-}" ]] && [[ $choice =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#vm_ids[@]}" ]]; then
                IFS='|' read -r vm_id host_image_id image_description vm_status <<< "${vm_choices[$((choice-1))]}"
                if [[ "$vm_status" != "ok" ]]; then
                    echo "Error: Selected VM cannot be rebuilt because it does not have an 'ok' status."
                    break
                fi
                local confirm_attempt=0 confirmation
                while ((confirm_attempt++ < 3)); do
                    echo
                    echo "Are you sure you want to rebuild the VM? (y/n)"
                    echo "b. Back"
                    echo "m. Main"
                    echo "x. Exit"
                    echo -n "?: "
                    read -r confirmation || true
                    case "$confirmation" in
                        y|Y)
                            clear; printf '\e[3J'
                            echo "Proceeding with VM rebuilding..."
                            local j=0 response
                            until ((j++ >= 2)); do
                                response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
                                    --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
                                    -d '{"hostImageID": "'"$host_image_id"'", "imageDescription": "'"$image_description"'"}' \
                                    -X POST "https://app.bitlaunch.io/api/servers/${vm_id}/rebuild")
                                [[ -n "$response" ]] && break
                                delay
                            done
                            if [[ "$(echo "$response" | jq '.')" == "null" ]] || [[ "$(echo "$response" | jq '.')" == "{}" ]]; then
                                clear; printf '\e[3J'
                                echo "The virtual machine has been successfully rebuilt."
                            else
                                clear; printf '\e[3J'
                                echo "There was an issue rebuilding the virtual machine:"
                                echo "$response" | jq .
                            fi
                            break 2
                            ;;
                        n|N)
                            clear; printf '\e[3J'
                            echo "VM rebuilding canceled."
                            break
                            ;;
                        b|B)
                            break
                            ;;
                        m|M)
                            show_main_menu; return ;;
                        x|X)
                            exit_program ;;
                        *)
                            echo "Invalid input. Please enter 'y', 'n', 'b', 'm' or 'x'."
                            ;;
                    esac
                done
                break
            else
                echo "Invalid selection. Please try again."
            fi
        done
        echo "Returning to menu."
    else
        echo
        echo "No VM available."
    fi

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Stops (powers off) a virtual machine
stop_vm() {
    clear
    echo "Stopping VM..."
    local i=0 server_data
    until ((i++ >= 3)); do
        server_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
            "https://app.bitlaunch.io/api/servers")
        [[ -n "$server_data" ]] && break
        delay
    done

    if [[ "$(echo "$server_data" | jq -r '. | length')" -gt 0 ]]; then
        local vm_ids=($(echo "$server_data" | jq -r '.[].id'))
        local vm_choices=()
        local vm_index=1

        clear; printf '\e[3J'
        for vm_id in "${vm_ids[@]}"; do
            local server=$(echo "$server_data" | jq -r --arg VM_ID "$vm_id" '.[] | select(.id == $VM_ID)')
            local vm_ip=$(echo "$server" | jq -r '.ipv4')
            local host=$(echo "$server" | jq -r '.host')
            local host_image_id=$(echo "$server" | jq -r '.image')
            local name=$(echo "$server" | jq -r '.name')
            local status=$(echo "$server" | jq -r '.status')
            local image_description=$(echo "$server" | jq -r '.imageDescription')
            local host_name=$( [[ "$host" -eq 4 ]] && echo "Bitlaunch" || ([[ "$host" -eq 0 ]] && echo "Digital Ocean" ) )

            printf "%-25s %s\n" "VM:" "$vm_index"
            printf "%-25s %s\n" "Host:" "$host_name"
            printf "%-25s %s\n" "VM ID:" "$vm_id"
            printf "%-25s %s\n" "IP Address:" "$vm_ip"
            printf "%-25s %s\n" "Status:" "$status"

            if [[ "$name" =~ ^[^_]+_[^_]+_[^_]+$ ]]; then
                IFS='_' read -r plan_type plan_spec region <<< "$name"
                plan_spec=$(echo "$plan_spec" | sed 's/-/\//g')
                plan_type=$(echo "$plan_type" | sed 's/-/ /g')
                region=$(echo "$region" | sed 's/-/ /g')
                printf "%-25s %s\n" "Region:" "$region"
                printf "%-25s %s\n" "Plan:" "$plan_type"
                printf "%-25s %s\n" "Specs:" "$plan_spec"
            else
                printf "%-25s %s\n" "VM Name:" "$name"
            fi
            printf "%-25s %s\n" "OS:" "$image_description"
            echo

            vm_choices+=("$vm_id|$host_image_id|$image_description|$status")
            vm_index=$((vm_index + 1))
        done

        local attempt=0 choice
        while ((attempt++ < 3)); do
            echo "b. Back"
            echo "m. Main"
            echo "x. Exit"
            echo -n "?: "
            read -r choice || true

            case "$choice" in
                b|B) show_server_menu; return ;;
                m|M) show_main_menu; return ;;
                x|X) exit_program ;;
            esac

            if [[ -n "${choice:-}" ]] && [[ $choice =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#vm_ids[@]}" ]]; then
                IFS='|' read -r vm_id host_image_id image_description vm_status <<< "${vm_choices[$((choice-1))]}"
                if [[ "$vm_status" == "stopped" ]]; then
                    echo "Error: Selected VM is already stopped."
                    break
                fi
                local confirm_attempt=0 confirmation
                while ((confirm_attempt++ < 3)); do
                    echo
                    echo "Are you sure you want to stop the VM? (y/n)"
                    echo "b. Back"
                    echo "m. Main"
                    echo "x. Exit"
                    echo -n "?: "
                    read -r confirmation || true
                    case "$confirmation" in
                        y|Y)
                            clear; printf '\e[3J'
                            echo "Proceeding with VM stopping..."
                            local j=0 response
                            until ((j++ >= 2)); do
                                response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
                                    --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
                                    -X POST "https://app.bitlaunch.io/api/servers/${vm_id}/stop")
                                [[ -n "$response" ]] && break
                                delay
                            done
                            if [[ "$(echo "$response" | jq '.')" == "null" ]] || [[ "$(echo "$response" | jq '.')" == "{}" ]]; then
                                clear; printf '\e[3J'
                                echo "The virtual machine has been successfully stopped."
                            else
                                clear; printf '\e[3J'
                                echo "There was an issue stopping the virtual machine:"
                                echo "$response" | jq .
                            fi
                            break 2
                            ;;
                        n|N)
                            clear; printf '\e[3J'
                            echo "VM stopping canceled."
                            break
                            ;;
                        b|B)
                            break
                            ;;
                        m|M)
                            show_main_menu; return ;;
                        x|X)
                            exit_program ;;
                        *)
                            echo "Invalid input. Please enter 'y', 'n', 'b', 'm' or 'x'."
                            ;;
                    esac
                done
                break
            else
                echo "Invalid selection. Please try again."
            fi
        done
        echo "Returning to menu."
    else
        echo
        echo "No VM available."
    fi

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_server_menu ;;
    esac
}

# Creates a new account transaction (deposit/crypto payment)
create_transaction() {
    # Hide cursor; global EXIT trap will restore it via cleanup()
    tput civis 2>/dev/null || true
    clear
    echo "Creating Transaction..."

    local amount crypto_symbol attempt=0
    local -a valid_crypto=('BTC' 'LTC' 'ETH')

    # --- Ask amount ---
    while ((attempt < 3)); do
        echo -n "Enter the amount to transfer in USD (minimum amount is 30 USD): "
        read -r amount || true
        if [[ -n "${amount:-}" ]] && [[ "$amount" =~ ^[0-9]+$ ]] && [[ "$amount" -ge 30 ]]; then
            break
        else
            if [[ -z "${amount:-}" ]]; then
                echo "No input provided. Please enter a valid amount."
            elif ! [[ "$amount" =~ ^[0-9]+$ ]]; then
                echo "The entered value is not a valid number. Please try again."
            else
                echo "The entered amount is less than 30 USD. Please try again."
            fi
            ((attempt++))
        fi
    done
    if ((attempt == 3)); then
        echo "You have entered an incorrect value 3 times."
        return 1
    fi

    # --- Ask crypto ---
    printf 'The cryptocurrency to use when sending payment. Valid values are:\n1. BTC\n2. LTC\n3. ETH\n'
    attempt=0
    local choice
    while ((attempt < 3)); do
        echo -n "Enter the number of the cryptocurrency: "
        read -r choice || true
        if [[ -n "${choice:-}" ]] && [[ $choice =~ ^[1-3]$ ]]; then
            crypto_symbol="${valid_crypto[$((choice-1))]}"
            echo "You have selected: $crypto_symbol"
            break
        else
            echo "Invalid selection. Please enter a number from 1 to 3."
            ((attempt++))
        fi
    done
    if ((attempt == 3)); then
        echo "You have entered an incorrect value 3 times."
        return 1
    fi

    # --- Create transaction ---
    local i=0 response
    until ((i++ >= 3)) || {
        response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 10 --max-time 10 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
            -d '{ "amountUsd": '"$amount"', "cryptoSymbol": "'"$crypto_symbol"'" }' -X POST \
            "https://app.bitlaunch.io/api/transactions")
        [[ -n "$response" ]] && [[ "$response" != "{}" ]] && [[ "$(echo "$response" | jq -r '. | length')" -gt 0 ]]
    }; do delay; done

    if [[ -z "$response" || "$response" == "{}" || "$(echo "$response" | jq -r '. | length')" -eq 0 ]]; then
        echo "Failed to retrieve valid response"
        return 1
    fi

    # --- Extract initial data ---
    local tx_id tx_addr transaction_date tx_amount_usd tx_amount_crypto tx_status
    tx_id="$(echo "$response" | jq -r '.id')"
    if [[ "$crypto_symbol" == "ETH" ]]; then
        tx_addr="0x$(echo "$response" | jq -r '.address')"
    else
        tx_addr="$(echo "$response" | jq -r '.address')"
    fi
    transaction_date="$(safe_fmt_date "$(echo "$response" | jq -r '.date')" "+%d.%m.%Y %H:%M")"
    tx_amount_usd="$(echo "$response" | jq -r '.amountUsd')"
    tx_amount_crypto="$(echo "$response" | jq -r '.amountCrypto')"
    tx_status="$(echo "$response" | jq -r '.status')"

    # --- Initial draw (fixed layout) ---
    clear; printf '\e[3J'
    printf "%-25s %s\n" "Transaction ID:" "$tx_id"                       # row 1
    printf "%-25s %s\n" "Date of payment:" "$transaction_date"           # row 2
    printf "%-25s %s\n" "Amount USD:" "$tx_amount_usd"                   # row 3
    printf "%-25s %s\n" "Amount $crypto_symbol:" "$tx_amount_crypto"     # row 4
    printf "%-25s %s\n" "Address:" "$tx_addr"                            # row 5
    printf "%-25s %s\n" "Status:" "$tx_status"                           # row 6
    printf "%-25s %02d:%02d\n" "Time left:" 30 00                        # row 7 (placeholder)
    echo                                                                 # row 8
    echo "b. Back"                                                       # row 9
    echo "m. Main"                                                       # row 10
    echo "x. Exit"                                                       # row 11
    echo                                                                 # row 12
    printf "?: "                                                         # row 13

    # Row anchors
    local status_row=6
    local timer_row=7
    local prompt_row=13

    # Helpers
    _goto() { printf '\e[%d;%dH' "$1" "$2"; }

    render_status() {
        _goto "$status_row" 1
        printf "%-25s %s\e[K" "Status:" "$tx_status"
    }
    render_timer() {
        local remaining=$(( END_TIME - SECONDS ))
        (( remaining < 0 )) && remaining=0
        local mm=$(( remaining / 60 ))
        local ss=$(( remaining % 60 ))
        _goto "$timer_row" 1
        printf "%-25s %02d:%02d\e[K" "Time left:" "$mm" "$ss"
    }

    render_status
    render_timer
    _goto "$prompt_row" 4

    # --- Live loop ---
    local END_TIME=$((SECONDS + 1800))
    local transaction_completed=false
    local poll_interval=15
    local last_poll=$SECONDS

    while (( SECONDS <= END_TIME )); do
        # Update status every poll_interval
        if (( SECONDS - last_poll >= poll_interval )); then
            local list_json j=0
            until ((j++ >= 3)) || {
                list_json=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
                    --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
                    "https://app.bitlaunch.io/api/transactions?page=1&items=25")
                [[ -n "$list_json" ]]
            }; do delay; done

            if [[ -n "$list_json" && "$list_json" != "{}" ]]; then
                local tx_json new_status new_amount_crypto
                tx_json="$(echo "$list_json" | jq --arg id "$tx_id" -c '.history[] | select(.id == $id)')"
                if [[ -n "$tx_json" ]]; then
                    new_status="$(echo "$tx_json" | jq -r '.status')"
                    new_amount_crypto="$(echo "$tx_json" | jq -r '.amountCrypto')"
                    if [[ "$new_status" != "$tx_status" || "$new_amount_crypto" != "$tx_amount_crypto" ]]; then
                        tx_status="$new_status"
                        tx_amount_crypto="$new_amount_crypto"
                        render_status
                    fi
                    if [[ "$tx_status" == "Complete" ]]; then
                        transaction_completed=true
                        END_TIME=$SECONDS
                    fi
                fi
            fi
            last_poll=$SECONDS
        fi

        # Update only timer line
        render_timer

        # Read a single key without Enter (non-blocking 1s)
        _goto "$prompt_row" 4
        local key=""
        read -rsn1 -t 1 key || true
        case "$key" in
            b|B)
                echo
                show_transactions_menu
                return
                ;;
            m|M)
                echo
                show_main_menu
                return
                ;;
            x|X)
                echo
                exit_program
                ;;
            "" ) : ;;   # no key
            * )  : ;;   # ignore others
        esac
    done

    # Timeout or completed; keep screen content, then classic prompt as a fallback
    if ! $transaction_completed; then
        echo
        echo "30 minutes passed without transaction completion."
    fi

    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_transactions_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_transactions_menu ;;
    esac
}

# Lists all account transactions
list_transactions() {
    clear
    echo "Listing Transactions..."
    clear; printf '\e[3J'

    local i=0
    local response user_data
    until ((i++ >= 2)) || {
        response=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
            "https://app.bitlaunch.io/api/transactions?page=1&items=25" | jq .)
        [[ -n "$response" ]] && [[ "$response" != "{}" ]] && [[ "$(echo "$response" | jq -r '. | length')" -gt 0 ]]
    }; do delay; done

    [[ -z "$response" || "$response" == "{}" || "$(echo "$response" | jq -r '. | length')" -eq 0 ]] && {
        echo "Failed to retrieve valid response"
        return 1
    }

    delay

    i=0
    until ((i++ >= 2)) || {
        user_data=$(curl "${PROXY_ARGS[@]}" -sf --tlsv1.3 --http2 --proto '=https' \
            --connect-timeout 6 --max-time 6 "${HTTP_HEADERS[@]}" -H "Authorization: Bearer $API_TOKEN" \
            "https://app.bitlaunch.io/api/user")
        [[ -n "$user_data" ]]
    }; do delay; done

    local account_creation_date=$(echo "$user_data" | jq -r '.created')
    local balance=$(echo "$user_data" | jq -r '.balance / 1000')
    local balance=${balance:-0}
    local email=$(echo "$user_data" | jq -r '.email')

    clear; printf '\e[3J'
    printf "%-25s %s\n" "Created On:" "$(safe_fmt_date "$account_creation_date" "+%d.%m.%Y")"
    printf "%-25s %s\n" "Account ID:" "$email"
    printf "%-25s %s USD\n\n" "Balance:" "$balance"
    echo

    echo "$response" | jq -c '.history[]' | while IFS= read -r transaction; do
        local transaction_id=$(echo "$transaction" | jq -r '.id')
        local date=$(echo "$transaction" | jq -r '.date')
        local formatted_date=$(safe_fmt_date "$date" "+%d.%m.%Y %H:%M")
        local crypto_symbol=$(echo "$transaction" | jq -r '.cryptoSymbol')
        local amount_usd=$(echo "$transaction" | jq -r '.amountUsd')
        local amount_crypto=$(echo "$transaction" | jq -r '.amountCrypto')
        [[ "$crypto_symbol" == "ETH" ]] && local crypto_address="0x$(echo "$transaction" | jq -r '.address')" || crypto_address="$(echo "$transaction" | jq -r '.address')"
        local status=$(echo "$transaction" | jq -r '.status')
        printf "%-25s %s\n" "Transaction ID:" "$transaction_id"
        printf "%-25s %s\n" "Date of payment:" "$formatted_date"
        printf "%-25s %s\n" "Amount USD:" "$amount_usd"
        printf "%-25s %s\n" "Amount $crypto_symbol:" "$amount_crypto"
        printf "%-25s %s\n" "Address:" "$crypto_address"
        printf "%-25s %s\n" "Status:" "$status"
        echo
    done

    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        b|B) show_transactions_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) show_transactions_menu ;;
    esac
}

# Shows the main application menu
show_main_menu() {
    if [ -z "$API_TOKEN" ]; then
        prompt_for_api_token
        HTTP_HEADERS=($(generate_http_headers))
        tor_newnym
    fi
    clear
    echo "Main Menu"
    echo "1. Server"
    echo "2. Transactions"
    echo
    echo "s. Sign in to another account"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        1) show_server_menu ;;
        2) show_transactions_menu ;;
        s|S) sign_in_to_another_account ;;
        x|X) exit_program ;;
        *) echo "Invalid option" && show_main_menu ;;
    esac
}

# Shows the server management menu
show_server_menu() {
    clear
    echo "Server Menu"
    echo "1. List VMs"
    echo "2. Create VM"
    echo "3. Remove VM"
    echo "4. Restart VM"
    echo "5. Rebuild VM"
    echo "6. Stop VM"
    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        1) list_vms ;;
        2) create_vm ;;
        3) remove_vm ;;
        4) restart_vm ;;
        5) rebuild_vm ;;
        6) stop_vm ;;
        b|B) show_main_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) echo "Invalid option" && show_server_menu ;;
    esac
}

# Shows the transactions menu
show_transactions_menu() {
    clear
    echo "Transactions Menu"
    echo "1. Create Transaction"
    echo "2. List Transactions"
    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        1) create_transaction ;;
        2) list_transactions ;;
        b|B) show_main_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) echo "Invalid option" && show_transactions_menu ;;
    esac
}

# Shows menu to choose cloud provider for new VM
create_vm() {
    clear
    echo "Create VM"
    echo "1. Bitlaunch"
    echo "2. Digital Ocean"
    echo
    echo "b. Back"
    echo "m. Main"
    echo "x. Exit"
    echo
    echo -n "?: "
    read -r choice || true
    case $choice in
        1) create_vm_bitlaunch ;;
        2) create_vm_digital_ocean ;;
        b|B) show_server_menu ;;
        m|M) show_main_menu ;;
        x|X) exit_program ;;
        *) echo "Invalid option" && create_vm ;;
    esac
}

# Gracefully exits the program
exit_program() {
    clear
    echo "Exiting..."
    exit 0
}

# Entry point
show_main_menu
EOL

RUN chown -R user:user /home/user && \
    chmod +x /home/user/bitlaunch

USER user
WORKDIR /home/user
CMD ["sleep","infinity"]
EOF
}
wait_health() {
    local name="$1" timeout="${2:-180}" id hs run i
    for ((i=0; i<timeout; i++)); do
        id="$(${SUDO:-} docker ps --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
        if [[ -n "$id" ]]; then
            hs="$(${SUDO:-} docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{""}}{{end}}' "$id" 2>/dev/null || true)"
            run="$(${SUDO:-} docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || true)"
            if [[ "$hs" == "healthy" || ( -z "$hs" && "$run" == "true" ) ]]; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}
print_health_log() {
    local name="$1" id
    id="$(${SUDO:-} docker ps --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
    [[ -n "$id" ]] || return 0

    ${SUDO:-} docker inspect -f '{{range .State.Health.Log}}{{printf "[%s] code=%d %s\n" .Start .ExitCode .Output}}{{end}}' "$id" 1>&2 || true
}
wait_stack_ready() {
    info "Waiting for exit_a health"
    if ! wait_health exit_a 180; then
        err "exit_a did not become healthy. Health log:"
        print_health_log exit_a
        die "Startup failed"
    fi
    info "Waiting for exit_b health"
    if ! wait_health exit_b 180; then
        err "exit_b did not become healthy. Health log:"
        print_health_log exit_b
        die "Startup failed"
    fi
    info "Waiting for haproxy health"
    if ! wait_health haproxy 180; then
        err "haproxy did not become healthy. Health log:"
        print_health_log haproxy
        die "Startup failed"
    fi
    info "All proxy containers are healthy."
}

ext_network_container_subnet_cidr_ipv4="10.16.85.0/29"
ext_base=${ext_network_container_subnet_cidr_ipv4%/*}
ext_base=${ext_base%.*}.
ext_network_container_gateway_ipv4="${ext_base}1"
ext_network_container_exit_a_ipv4="${ext_base}2"
ext_network_container_exit_b_ipv4="${ext_base}3"
int_network_container_subnet_cidr_ipv4="172.16.85.0/29"
int_base=${int_network_container_subnet_cidr_ipv4%/*}
int_base=${int_base%.*}.
int_network_container_gateway_ipv4="${int_base}1"
int_network_container_exit_a_ipv4="${int_base}2"
int_network_container_exit_b_ipv4="${int_base}3"
int_network_container_haproxy_ipv4="${int_base}4"
int_network_container_bitlaunch_ipv4="${int_base}5"

tmp_folder="$(mktemp -d -t bitlaunchstack.XXXXXXXX)"
append_tmp_dir "$tmp_folder"
rnd_proj_name="bitlaunchstack_$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
sudo_keepalive_start 90
trap 'cleanup_all; exit 130' INT
trap 'cleanup_all' EXIT TERM HUP QUIT
check_pkg
preclean_patterns
tor_ctrl_pass="$(LC_ALL=C tr -dc 'A-Za-z0-9!?+=_' </dev/urandom | head -c 32 || true)"
tor_ctrl_hash="$(
    ${SUDO} docker run --rm debian:trixie-slim bash -ceu '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y --no-install-recommends tor >/dev/null
        tor --hash-password "'"$tor_ctrl_pass"'"
    ' | tail -n 1
)"
run_build_proxy
__compose -p "${rnd_proj_name}" -f "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml" build --no-cache
__compose -p "${rnd_proj_name}" -f "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml" up -d --force-recreate
wait_stack_ready
start_session_guard "${rnd_proj_name}" "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
sleep 2

tty_flag="-i"
if [ -t 1 ]; then
    tty_flag="-it"
fi
clear_scr
${SUDO} docker exec $tty_flag bitlaunch /bin/bash -lc 'exec ./bitlaunch'
