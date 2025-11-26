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

    for name in exit_a exit_b haproxy support; do
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

    for name in exit_a exit_b haproxy support; do
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
    mkdir -p "${tmp_folder}/${rnd_proj_name}"/{exit_a,exit_b,haproxy,support}

cat <<EOF > "${tmp_folder}/${rnd_proj_name}/.env"
int_network_container_subnet_cidr_ipv4="$int_network_container_subnet_cidr_ipv4"
int_network_container_gateway_ipv4="$int_network_container_gateway_ipv4"
int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
int_network_container_support_ipv4="${int_network_container_support_ipv4}"
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

  support:
    container_name: support
    build:
      context: ./support
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
        ipv4_address: ${int_network_container_support_ipv4}

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

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/support/Dockerfile"
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
    apt-get install -y --no-install-recommends tzdata bash openssh-client socat xz-utils libdigest-sha-perl gnupg2 && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN useradd -m user && chown -R user:user /home/user

RUN cat <<'EOL' > /home/user/support
#!/bin/bash
set -Eeuo pipefail

export NO_AT_BRIDGE=1
ssh_key=""
ssh_user=""
ssh_port=""
srv_ip=""
ssh_raw=""

tty_is_tty=0
if [[ -t 1 ]]; then
    tty_is_tty=1
    __orig_stty="$(stty -g 2>/dev/null || true)"
    stty -echoctl 2>/dev/null || true
fi
clear_screen() { 
    clear 2>/dev/null || true
    printf '\e[3J' 2>/dev/null || true
}
cleanup() {
    tput cnorm 2>/dev/null || true
    if [[ "${tty_is_tty}" -eq 1 ]]; then
        [[ -n "${__orig_stty:-}" ]] && stty "${__orig_stty}" 2>/dev/null || true
    fi
    clear_screen
}
safe_fmt_date() {
    local _in="${1:-}"
    local _fmt="${2:-+%d.%m.%Y}"
    date -d "$_in" "$_fmt" 2>/dev/null || echo "$_in"
}
on_sigint() {
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

tor_newnym() {
    local pass="${tor_ctrl_pass:-}"
    local exit_a="${int_network_container_exit_a_ipv4:-}"
    local exit_b="${int_network_container_exit_b_ipv4:-}"
    [[ -z "$pass" || -z "$exit_a" || -z "$exit_b" ]] && return 0
    local cmd
    cmd=$(printf 'AUTHENTICATE "%s"\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$pass")
    printf '%s' "$cmd" | socat - "TCP:${exit_a}:9051,connect-timeout=3" >/dev/null 2>&1 || true
    printf '%s' "$cmd" | socat - "TCP:${exit_b}:9051,connect-timeout=3" >/dev/null 2>&1 || true
}
prompt_tokens() {
    local attempts=0 s pass tail hdr="jA0ECQMK" k v line
    while (( attempts < 3 )); do
        printf "Enter Support Token: " >&2
        IFS= read -r s
        s="${s%\"}"; s="${s#\"}"; s="${s%\'}"; s="${s#\'}"
        s="$(printf '%s' "$s" | tr -d '\r\n \t')"

        local s1_bin s1_txt
        s1_bin="$(mktemp)"; s1_txt="$(mktemp)"

        if (( ${#s} > 45 )) && [[ "${s:0:45}" =~ ^[A-Za-z0-9]{45}$ ]]; then
            pass="${s:0:45}"; tail="${s:45}"

            # >>> тут была проблема, теперь stderr от gpg уходит в /dev/null
            if ! printf '%s' "${hdr}${tail}" \
                | base64 -d 2>/dev/null \
                | gpg --quiet --batch --yes --no-tty \
                      --pinentry-mode loopback \
                      --passphrase "$pass" \
                      --decrypt >"$s1_bin" 2>/dev/null
            then
                clear_screen
                echo "decrypt failed"
                attempts=$((attempts+1))
                continue
            fi
        else
            if ! printf '%s' "$s" | base64 -d >"$s1_bin" 2>/dev/null; then
                clear_screen
                echo "bad input"
                attempts=$((attempts+1))
                continue
            fi
        fi

        if xz -t "$s1_bin" >/dev/null 2>&1; then
            if ! xz -dc <"$s1_bin" >"$s1_txt" 2>/dev/null; then
                clear_screen
                echo "xz decompress failed"
                attempts=$((attempts+1))
                continue
            fi
        else
            cat <"$s1_bin" >"$s1_txt"
        fi

        local text_raw text
        text_raw="$(cat "$s1_txt")"
        text="$(printf '%b' "$text_raw")"

        unset ssh_raw ssh_user ssh_port srv_ip ssh_user_password
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            k="${line%%=*}"; v="${line#*=}"
            v="${v%$'\r'}"; v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
            case "$k" in
                ssh_raw) ssh_raw="$v" ;;
                ssh_user) ssh_user="$v" ;;
                ssh_port) ssh_port="$v" ;;
                srv_ip) srv_ip="$v" ;;
                ssh_user_password) ssh_user_password="$v" ;;
            esac
        done <<< "$text"

        ssh_key="$(mktemp)"
        local tmp; tmp="$(mktemp)"
        if printf '%s' "${ssh_raw:-}" | tr -d '\r\n \t' | base64 -d >"$tmp" 2>/dev/null; then
            if xz -t "$tmp" >/dev/null 2>&1; then
                if ! xz -dc <"$tmp" >"$ssh_key" 2>/dev/null; then
                    clear_screen
                    echo "ssh_raw decompress failed"
                    attempts=$((attempts+1))
                    continue
                fi
            else
                cp "$tmp" "$ssh_key"
            fi
        else
            printf '%s' "${ssh_raw:-}" >"$ssh_key"
        fi

        chmod 600 "$ssh_key" 2>/dev/null || true
        if ! grep -q "BEGIN OPENSSH PRIVATE KEY" "$ssh_key" 2>/dev/null; then
            clear_screen
            echo "final payload is not an OpenSSH private key"
            attempts=$((attempts+1))
            continue
        fi
        if [[ ! "${ssh_port:-}" =~ ^[0-9]{1,5}$ || "${ssh_port:-0}" -lt 1 || "${ssh_port:-0}" -gt 65535 ]]; then
            clear_screen
            echo "bad ssh_port"
            attempts=$((attempts+1))
            continue
        fi
        if [[ -z "${ssh_user:-}" || -z "${srv_ip:-}" ]]; then
            clear_screen
            echo "missing ssh_user/srv_ip"
            attempts=$((attempts+1))
            continue
        fi

        clear_screen
        return 0
    done
    echo "too many attempts"
    return 1
}
ssh_exec() {
    ssh \
        -q \
        -t \
        -i "$ssh_key" \
        -p "$ssh_port" \
        -o Ciphers=aes256-gcm@openssh.com \
        -o MACs=hmac-sha2-512-etm@openssh.com \
        -o KexAlgorithms=sntrup761x25519-sha512@openssh.com \
        -o LogLevel=error \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ProxyCommand="socat -T 59 - SOCKS4A:${int_network_container_haproxy_ipv4}:%h:%p,socksport=9095" \
        "${ssh_user}@${srv_ip}" "$@"
}
main() {
    prompt_tokens || exit 1
    tor_newnym || true
    clear_screen
    ssh_exec "printf '%s\n' \"$ssh_user_password\" | sudo -S -p '' -v && exec sudo -i"
}
main "$@"
EOL

RUN chown -R user:user /home/user && \
    chmod +x /home/user/support

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
int_network_container_support_ipv4="${int_base}5"

tmp_folder="$(mktemp -d -t supportstack.XXXXXXXX)"
append_tmp_dir "$tmp_folder"
rnd_proj_name="supportstack_$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
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
${SUDO} docker exec $tty_flag support /bin/bash -lc 'exec ./support'
