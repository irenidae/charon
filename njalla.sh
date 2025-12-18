#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

info() { printf "[info] %s\n" "$*"; }
warn() { printf "[warn] %s\n" "$*"; }
err()  { printf "[error] %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }
clear_scr() { clear 2>/dev/null || true; printf '\e[3J' 2>/dev/null || true; }

if [[ "$(id -u)" -eq 0 ]]; then
    err "This script must be run as a regular user (not root)."
    exit 1
fi

if [[ "$OSTYPE" == "darwin"* ]]; then
    export LC_ALL=C
    export LANG=C
    export LC_CTYPE=C
fi

DOCKER_OK=0

require_docker_access() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v docker >/dev/null 2>&1; then
            clear_scr
            err "Docker is not installed."
            info "hint: Install Docker Desktop, launch it, then re-run this script."
            exit 1
        fi

        if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix://* ]]; then
            local sock
            sock="${DOCKER_HOST#unix://}"
            if [[ ! -S "$sock" ]]; then
                clear_scr
                err  "DOCKER_HOST points to '$sock', but that socket does not exist."
                info "hint: Start Docker Desktop, or run: unset DOCKER_HOST ; docker context use default"
                exit 1
            fi
        fi

        if ! docker info >/dev/null 2>&1; then
            clear_scr
            err  "Docker is installed but not running."
            info "hint: Open 'Docker.app' and wait until the whale icon stops animating, then re-run this script."
            info "hint: If you use custom contexts, try: unset DOCKER_HOST ; docker context use default"
            exit 1
        fi

        DOCKER_OK=1
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        clear_scr
        err "Docker is not installed."
        info "hint: install docker, then re-run this script."
        exit 1
    fi

    local cur_user
    cur_user="${USER:-$(id -un 2>/dev/null || true)}"
    [[ -n "$cur_user" ]] || cur_user="$(whoami 2>/dev/null || true)"
    [[ -n "$cur_user" ]] || { clear_scr; err "Unable to determine current user."; exit 1; }

    # Linux: require docker group membership; do not call docker if not in group.
    if ! id -nG "$cur_user" | tr ' ' '\n' | grep -qx docker; then
        clear_scr
        err "Your user is not in the 'docker' group."
        info "Please add your user to the docker group to run docker without sudo (and avoid root-owned bind mounts)."
        echo
        echo "Paste these commands into your terminal:"
        echo
        echo "sudo groupadd docker 2>/dev/null || true"
        echo "sudo usermod -aG docker \$USER"
        echo
        info "Then close this terminal and open a new one (or run: newgrp docker), and run this script again."
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        clear_scr
        err "Docker is installed but not accessible without sudo."
        info "hint: start docker daemon (systemd): sudo systemctl enable --now docker"
        info "hint: if you just added yourself to the docker group, re-login or run: newgrp docker"
        exit 1
    fi

    DOCKER_OK=1
    return 0
}

declare -a _tmp_files=()
declare -a _tmp_dirs=()
declare -a _tmp_images=()
append_tmp_file() { _tmp_files+=("$1"); }
append_tmp_dir() { _tmp_dirs+=("$1"); }
append_tmp_image() { _tmp_images+=("$1"); }

__compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        err "docker compose is not available."
        return 1
    fi
}

prune_build_caches() {
    docker builder prune -af >/dev/null 2>&1 || true
    docker image prune -f >/dev/null 2>&1 || true

    if docker buildx ls >/dev/null 2>&1; then
        if docker buildx ls --format '{{.Name}}' >/dev/null 2>&1; then
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(docker buildx ls --format '{{.Name}}')
        else
            while IFS= read -r bname; do
                [[ -z "$bname" ]] && continue
                bname="${bname%\*}"
                docker buildx prune --builder "$bname" -af >/dev/null 2>&1 || true
            done < <(docker buildx ls | awk 'NR>1{print $1}')
        fi
    fi
}

preclean_patterns() {
    for name in exit_a exit_b haproxy njalla; do
        docker ps -aq -f "name=^${name}$" | xargs -r docker rm -f >/dev/null 2>&1 || true
    done

    local nets=()
    [[ -n "${ext_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$ext_network_container_subnet_cidr_ipv4" )
    [[ -n "${int_network_container_subnet_cidr_ipv4:-}" ]] && nets+=( "$int_network_container_subnet_cidr_ipv4" )

    docker network ls -q | while read -r nid; do
        subnets=$(docker network inspect "$nid" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
        for net in "${nets[@]}"; do
            if echo "$subnets" | grep -qw -- "$net"; then
                docker network rm "$nid" >/dev/null 2>&1 || true
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

    for name in exit_a exit_b haproxy njalla; do
        docker ps -aq -f "name=^${name}$" | xargs -r docker rm -f >/dev/null 2>&1 || true
    done

    docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs -r docker network rm >/dev/null 2>&1 || true
    docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs -r docker volume rm -f >/dev/null 2>&1 || true

    if [[ -z "$(docker ps -aq --filter ancestor=debian:trixie-slim 2>/dev/null || true)" ]]; then
        docker rmi -f debian:trixie-slim >/dev/null 2>&1 || true
    fi
}

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

__compose_guard() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        return 1
    fi
}

on_term() {
    if [[ -f "$yml" ]]; then
        __compose_guard -p "$proj" -f "$yml" down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
    fi

    for name in exit_a exit_b haproxy njalla; do
        docker ps -aq -f "name=^${name}$" | xargs ${xargs_r:-} docker rm -f >/dev/null 2>&1 || true
    done

    docker network ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} docker network rm >/dev/null 2>&1 || true
    docker volume ls -q --filter "label=com.docker.compose.project=${proj}" | xargs ${xargs_r:-} docker volume rm -f >/dev/null 2>&1 || true

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

    # If docker is not accessible, do not call docker at all (avoids permission spam).
    if [[ "${DOCKER_OK:-0}" == "1" ]]; then
        cleanup_project "${rnd_proj_name}" "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
        prune_build_caches

        if [[ "${STRICT_CLEANUP:-0}" == "1" ]]; then
            warn "Performing system-wide prune (--all --volumes)."
            docker system prune -af --volumes >/dev/null 2>&1 || true
        fi
    fi

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
    set -e
}

check_pkg() {
    local os=""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "Docker on macOS is ready."
        return 0
    fi

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os="$ID"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        case "$os" in
            debian)
                [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "installing docker (Debian)…"
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
                [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "installing docker (Arch/Manjaro)…"
                sudo pacman -Sy --needed --noconfirm docker docker-compose >/dev/null 2>&1
                ;;
            *)
                warn "unsupported distro '$os' – install docker manually."
                return 1
                ;;
        esac
    else
        [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "docker is present."
    fi

    if command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | grep -q '^docker\.service' ); then
        sudo systemctl enable --now docker 2>/dev/null || true
    fi
}

wait_health() {
    local name="$1" timeout="${2:-420}" id hs run i
    for ((i=0; i<timeout; i++)); do
        id="$(docker ps -a --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
        if [[ -n "$id" ]]; then
            hs="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{""}}{{end}}' "$id" 2>/dev/null || true)"
            run="$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || true)"
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
    id="$(docker ps -a --filter "name=^${name}$" --format '{{.ID}}' | head -n1)"
    [[ -n "$id" ]] || return 0
    docker inspect -f '{{range .State.Health.Log}}{{printf "[%s] code=%d %s\n" .Start .ExitCode .Output}}{{end}}' "$id" 1>&2 || true
}

wait_stack_ready() {
    info "Waiting for exit_a health"
    if ! wait_health exit_a 420; then
        err "exit_a did not become healthy. Health log:"
        print_health_log exit_a
        die "Startup failed"
    fi

    info "Waiting for exit_b health"
    if ! wait_health exit_b 420; then
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

run_build_proxy() {
    local proj_dir="${tmp_folder}/${rnd_proj_name}"
    mkdir -p "${tmp_folder}/${rnd_proj_name}"/{exit,haproxy,njalla}

cat <<EOF > "${tmp_folder}/${rnd_proj_name}/.env"
int_network_container_subnet_cidr_ipv4="$int_network_container_subnet_cidr_ipv4"
int_network_container_gateway_ipv4="$int_network_container_gateway_ipv4"
int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"
int_network_container_njalla_ipv4="${int_network_container_njalla_ipv4}"
ext_network_container_subnet_cidr_ipv4="$ext_network_container_subnet_cidr_ipv4"
ext_network_container_gateway_ipv4="$ext_network_container_gateway_ipv4"
ext_network_container_exit_a_ipv4="$ext_network_container_exit_a_ipv4"
ext_network_container_exit_b_ipv4="$ext_network_container_exit_b_ipv4"
exit_image="${rnd_proj_name}-exit"
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/docker-compose.yaml"
services:
  exit_a:
    container_name: exit_a
    image: ${exit_image}
    pull_policy: never
    build:
      context: ./exit
      dockerfile: Dockerfile
    runtime: runc
    security_opt:
      - no-new-privileges:true
    environment:
      int_network_container_exit_ipv4: "${int_network_container_exit_a_ipv4}"
      int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
    healthcheck:
      test: ["CMD", "/usr/local/bin/healthcheck"]
      interval: 30s
      timeout: 15s
      retries: 6
      start_period: 180s
    restart: unless-stopped
    logging: { driver: "none" }
    volumes:
      - exit_a:/run/tor
    networks:
      external_network:
        ipv4_address: ${ext_network_container_exit_a_ipv4}
      internal_network:
        ipv4_address: ${int_network_container_exit_a_ipv4}

  exit_b:
    container_name: exit_b
    image: ${exit_image}
    pull_policy: never
    runtime: runc
    security_opt:
      - no-new-privileges:true
    environment:
      int_network_container_exit_ipv4: "${int_network_container_exit_b_ipv4}"
      int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
    healthcheck:
      test: ["CMD", "/usr/local/bin/healthcheck"]
      interval: 30s
      timeout: 15s
      retries: 6
      start_period: 180s
    restart: unless-stopped
    logging: { driver: "none" }
    volumes:
      - exit_b:/run/tor
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
    runtime: runc
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    logging: { driver: "none" }
    depends_on:
      - exit_a
      - exit_b
    networks:
      internal_network:
        ipv4_address: ${int_network_container_haproxy_ipv4}

  njalla:
    container_name: njalla
    build:
      context: ./njalla
      dockerfile: Dockerfile
      args:
        int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
    runtime: runc
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    logging: { driver: "none" }
    volumes:
      - exit_a:/run/tor_a:ro
      - exit_b:/run/tor_b:ro
    networks:
      internal_network:
        ipv4_address: ${int_network_container_njalla_ipv4}

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

volumes:
  exit_a:
  exit_b:
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/exit/Dockerfile"
# syntax=docker/dockerfile:1.7
FROM debian:trixie-slim AS build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl lsb-release gnupg2 && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN install -d -m 0755 -o root -g root /usr/share/keyrings && \
    asc="$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/" | grep -oP '(?<=href=")[^"]+\.asc' | head -n 1)" && \
    curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/${asc}" | gpg --batch --yes --dearmor -o /dev/stdout | install -D -m 0644 -o root -g root /dev/stdin /usr/share/keyrings/deb.torproject.org-keyring.gpg && \
    printf '%b' "Types: deb deb-src\nURIs: https://deb.torproject.org/torproject.org\nSuites: $(lsb_release -cs)\nComponents: main\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/deb.torproject.org-keyring.gpg\n" > /etc/apt/sources.list.d/tor.sources && \
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources

RUN set -Eeuo pipefail; \
    arch="$(dpkg --print-architecture)"; \
    mkdir -p /out; \
    apt-get update -qq; \
    if apt-cache madison tor | awk -v a="$arch" '$0 ~ /deb\.torproject\.org/ && $0 ~ /Packages/ {ok=1} END{exit !ok}'; then \
        echo "torproject binary exists for ${arch}; skip source build"; \
    else \
        ver="$(apt-cache madison tor | awk '$0 ~ /deb\.torproject\.org/ && $0 ~ /Sources/ {print $3; exit}')"; \
        test -n "$ver"; \
        apt-get install -y --no-install-recommends build-essential devscripts fakeroot dpkg-dev pkg-config xz-utils python3 perl && \
        apt-get build-dep -y tor; \
        mkdir -p /build && cd /build; \
        apt-get source "tor=$ver"; \
        cd tor-*; \
        dpkg-buildpackage -b -uc -us; \
        mv -v /build/*.deb /out/; \
    fi; \
    rm -rf /var/lib/apt/lists/* /build

FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl lsb-release gnupg2 netcat-openbsd xxd procps && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN install -d -m 0755 -o root -g root /usr/share/keyrings && \
    asc="$(curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/" | grep -oP '(?<=href=")[^"]+\.asc' | head -n 1)" && \
    curl -sSfL --tlsv1.3 --http2 --proto '=https' "https://deb.torproject.org/torproject.org/${asc}" | gpg --batch --yes --dearmor -o /dev/stdout | install -D -m 0644 -o root -g root /dev/stdin /usr/share/keyrings/deb.torproject.org-keyring.gpg && \
    printf '%b' "Types: deb deb-src\nURIs: https://deb.torproject.org/torproject.org\nSuites: $(lsb_release -cs)\nComponents: main\nArchitectures: amd64\nSigned-By: /usr/share/keyrings/deb.torproject.org-keyring.gpg\n" > /etc/apt/sources.list.d/tor.sources && \
    arch="$(dpkg --print-architecture)"; \
    if [ "$arch" = "amd64" ]; then \
        printf '%b' "Package: tor tor-geoipdb tor-dbgsym nyx deb.torproject.org-keyring\nPin: origin deb.torproject.org\nPin-Priority: 990\n" > /etc/apt/preferences.d/99-torproject; \
    else \
        printf '%b' "# no torproject pin on non-amd64\n" > /etc/apt/preferences.d/99-torproject; \
    fi && \
    printf '%b' "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: forky\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n" > /etc/apt/sources.list.d/forky.sources && \
    printf '%b' "Package: *\nPin: release n=forky\nPin-Priority: 100\n\nPackage: vanguards python3-stem python3-pkg-resources\nPin: release n=forky\nPin-Priority: 990\n" > /etc/apt/preferences.d/99-vanguards && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y tor deb.torproject.org-keyring nyx vanguards

COPY --from=build /out/ /tmp/torbuild/
RUN if ls /tmp/torbuild/*.deb >/dev/null 2>&1; then \
        apt-get update -qq && \
        apt-get install -y --no-install-recommends /tmp/torbuild/*.deb && \
        rm -rf /tmp/torbuild; \
    fi

RUN mkdir -p /run/tor /var/lib/tor /usr/local/bin && \
    chown -R debian-tor:debian-tor /run/tor /var/lib/tor && \
    chmod 750 /run/tor && \
    chmod 700 /var/lib/tor

RUN cat > /etc/tor/vanguards.conf <<EOL
[Global]
control_socket = /run/tor/control.sock
control_cookie = /run/tor/control.authcookie
enable_vanguards = True
enable_bandguards = True
enable_cbtverify = False
enable_rendguard = True
close_circuits = True
one_shot_vanguards = False
loglevel = NOTICE
logfile = /dev/null
state_file = /var/lib/tor/vanguards.state

[Vanguards]
layer1_lifetime_days = 0
max_layer2_lifetime_hours = 1080
max_layer3_lifetime_hours = 48
min_layer2_lifetime_hours = 24
min_layer3_lifetime_hours = 1
num_layer1_guards = 2
num_layer2_guards = 3
num_layer3_guards = 8

[Bandguards]
circ_max_age_hours = 24
circ_max_hsdesc_kilobytes = 30
circ_max_megabytes = 0
circ_max_disconnected_secs = 30
conn_max_disconnected_secs = 15

[Rendguard]
rend_use_max_use_to_bw_ratio = 5.0
rend_use_max_consensus_weight_churn = 1.0
rend_use_close_circuits_on_overuse = True
rend_use_global_start_count = 1000
rend_use_relay_start_count = 100
rend_use_scale_at_count = 20000
EOL

RUN install -m 0755 -o root -g root /dev/stdin /usr/local/bin/healthcheck <<'EOL'
#!/bin/bash
set -Eeuo pipefail
[ -S /run/tor/control.sock ] || exit 1
[ -r /run/tor/control.authcookie ] || exit 1
cookie="$(xxd -p /run/tor/control.authcookie | tr -d '\n')"
printf "AUTHENTICATE $cookie\r\ngetinfo status/bootstrap-phase\r\nquit\r\n" | nc -U /run/tor/control.sock | grep -q 'PROGRESS=100' || exit 1
printf "AUTHENTICATE $cookie\r\ngetinfo circuit-status\r\nquit\r\n" | nc -U /run/tor/control.sock | grep -q 'BUILT' || exit 1
ps aux | grep '[v]anguards' > /dev/null || exit 1
exit 0
EOL

RUN install -m 0755 -o root -g root /dev/stdin /usr/local/bin/entrypoint-docker.sh <<'EOL'
#!/bin/bash
set -Eeuo pipefail

cat > /run/tor/torrc <<TORRC
Log notice file /dev/null
Log warn file /dev/null
SocksPort ${int_network_container_exit_ipv4}:9095
SocksPolicy accept ${int_network_container_haproxy_ipv4}/32
SocksPolicy reject *
ControlSocket /run/tor/control.sock
ControlSocketsGroupWritable 1
CookieAuthentication 1
CookieAuthFile /run/tor/control.authcookie
CookieAuthFileGroupReadable 1
DataDirectory /var/lib/tor
CircuitBuildTimeout 60
NewCircuitPeriod 30
EnforceDistinctSubnets 1
ConnectionPadding 1
ReducedConnectionPadding 0
BandwidthRate 100 KB
BandwidthBurst 150 KB
ConfluxEnabled 0
SafeSocks 1
ClientRejectInternalAddresses 1
DisableDebuggerAttachment 1
ClientUseIPv6 0
TORRC

tor -f /run/tor/torrc &
tor_pid=$!

term() { kill -TERM "$tor_pid" 2>/dev/null || true; }
trap term TERM INT

for _ in $(seq 1 240); do
    if [ -S /run/tor/control.sock ] && [ -r /run/tor/control.authcookie ]; then
        cookie="$(xxd -p /run/tor/control.authcookie | tr -d '\n')"
        resp="$(printf "AUTHENTICATE $cookie\r\ngetinfo status/bootstrap-phase\r\nquit\r\n" | nc -U /run/tor/control.sock -w 5 -q 1 || true)"
        echo "$resp" | grep -q 'PROGRESS=100' && break
    fi
    sleep 1
done

exec vanguards --config /etc/tor/vanguards.conf
EOL

RUN apt-get purge -y lsb-release gnupg2 curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER debian-tor
ENTRYPOINT ["entrypoint-docker.sh"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/haproxy/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ARG int_network_container_exit_a_ipv4
ARG int_network_container_exit_b_ipv4
ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"
ENV int_network_container_exit_a_ipv4="${int_network_container_exit_a_ipv4}"
ENV int_network_container_exit_b_ipv4="${int_network_container_exit_b_ipv4}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata haproxy && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN cat > /etc/haproxy/haproxy.cfg <<EOL
global
    log stdout format raw local0
    maxconn 4096
    user haproxy
    group haproxy

defaults
    log global
    mode tcp
    option  dontlognull
    retries 3
    timeout connect 5s
    timeout client 60s
    timeout server 60s

frontend socks_proxy
    bind ${int_network_container_haproxy_ipv4}:9095
    default_backend socks_pool

backend socks_pool
    balance roundrobin

    option tcp-check
    tcp-check connect
    tcp-check send-binary 050100
    tcp-check expect binary 0500

    server exit_a ${int_network_container_exit_a_ipv4}:9095 check inter 20s rise 1 fall 2
    server exit_b ${int_network_container_exit_b_ipv4}:9095 check inter 20s rise 1 fall 2
EOL

RUN apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["haproxy","-f","/etc/haproxy/haproxy.cfg","-db"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/njalla/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata bash curl jq socat xxd && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN groupadd -g 101 user && \
    useradd -u 1000 -g 101 -r -M -s /usr/sbin/nologin user && \
    mkdir -p /opt/njalla
    
RUN cat > /opt/njalla/njalla <<'EOL'
#!/bin/bash
set -Eeuo pipefail

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
    local exit_a_sock="/run/tor_a/control.sock"
    local exit_b_sock="/run/tor_b/control.sock"
    local exit_a_cookie="/run/tor_a/control.authcookie"
    local exit_b_cookie="/run/tor_b/control.authcookie"
    local cookie cmd

    if [[ -S "$exit_a_sock" && -f "$exit_a_cookie" ]]; then
        cookie="$(xxd -p "$exit_a_cookie" | tr -d '\n')"
        cmd=$(printf 'AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$cookie")
        printf '%s' "$cmd" | socat -T 3 - "UNIX-CONNECT:${exit_a_sock}" >/dev/null 2>&1 || true
    fi

    if [[ -S "$exit_b_sock" && -f "$exit_b_cookie" ]]; then
        cookie="$(xxd -p "$exit_b_cookie" | tr -d '\n')"
        cmd=$(printf 'AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$cookie")
        printf '%s' "$cmd" | socat -T 3 - "UNIX-CONNECT:${exit_b_sock}" >/dev/null 2>&1 || true
    fi
}
delay() {
    local urand
    urand="$(od -An -N2 -i /dev/urandom 2>/dev/null | tr -d ' ' || echo 0)"
    local seed="${RANDOM}${urand}"
    local delay_s
    delay_s="$(awk -v min=0.8 -v max=1.8 -v seed="$seed" 'BEGIN{srand(systime() + seed); print min + rand() * (max - min)}')"
    sleep "$delay_s"
}
send_request() {
    local method=$1
    local params_json=$2
    local quiet="${3:-0}"

    local json_string
    json_string="{\"jsonrpc\": \"2.0\", \"method\": \"$method\", \"params\": $params_json, \"id\": 1}"

    local i=0
    local response=""
    local processed_response=""

    for ((i=0; i<3; i++)); do
        delay

        response="$(
            curl -sf \
                --proxy "socks5h://${int_network_container_haproxy_ipv4}:9095" \
                -H "Authorization: Njalla $nj_api_token" \
                -H "Content-Type: application/json" \
                -d "$json_string" \
                -X POST "$api_url" \
            || true
        )"

        processed_response="$(
            jq -er 'if .error then .error.message else .result end' \
                <<<"$response" 2>/dev/null || true
        )"

        if [[ "$processed_response" == *"Permission denied"* ]]; then
            return 2
        fi

        if [[ -n "$processed_response" ]]; then
            echo "$processed_response"
            return 0
        fi
    done

    if [[ "$quiet" != "1" ]]; then
        echo "Failed to complete request after 3 attempts." >&2
    fi
    return 1
}

validate_api_token() {
    local token_body="$nj_api_token"

    if [[ -n "${expected_prefix:-}" ]]; then
        if [[ "$nj_api_token" != "$expected_prefix"* ]]; then
            return 10
        fi
        token_body="${nj_api_token#"$expected_prefix"}"
    fi

    if [[ ! "$token_body" =~ ^[0-9a-z]{40}$ ]]; then
        return 11
    fi

    return 0
}

prompt_for_api_token() {
    local attempts=0
    local max_attempts=3
    local rc=0

    while :; do
        clear_screen

        read -r -p "Enter your Njalla API Token: " nj_api_token || continue
        nj_api_token="${nj_api_token//$'\r'/}"
        nj_api_token="${nj_api_token//$'\n'/}"
        nj_api_token="${nj_api_token//[[:space:]]/}"

        if ! validate_api_token; then
            rc=$?
            clear_screen
            if (( rc == 10 )); then
                echo "Invalid Njalla API Token: expected prefix '$expected_prefix'."
            else
                echo "Invalid Njalla API Token: must be 40 lowercase alphanumeric characters${expected_prefix:+ after the prefix}."
            fi
            attempts=$((attempts + 1))
        else
            if send_request "list-domains" "{}" 1 >/dev/null 2>&1; then
                clear_screen
                echo "Njalla API Token accepted."
                return 0
            else
                rc=$?
                clear_screen
                if (( rc == 2 )); then
                    echo "Invalid Njalla API Token. Please try again."
                else
                    echo "Njalla API request failed. Please check connectivity and try again."
                fi
                attempts=$((attempts + 1))
            fi
        fi

        if (( attempts >= max_attempts )); then
            clear_screen
            echo "Too many attempts. Try again, or press Ctrl+C to exit."
            attempts=0
            sleep 1
        else
            sleep 1
        fi
    done
}
user_confirm() {
    local prompt="$1"
    local attempt=0
    local input=""

    while (( attempt < 3 )); do
        read -r -p "$prompt" input || return 1
        case "$input" in
            y|Y) return 0 ;;
            n|N) return 1 ;;
            *)
                echo "Invalid input. Please enter 'y' or 'n'."
                (( attempt++ ))
                if (( attempt == 3 )); then
                    echo "Too many incorrect attempts. Exiting."
                    exit 1
                fi
            ;;
        esac
    done
}
add_a_records() {
    local response
    if ! response="$(send_request "list-domains" "{}")"; then
        echo "Failed to list domains."
        return 1
    fi

    local domains_json
    domains_json="$(jq -c '.domains // []' <<<"$response" 2>/dev/null || echo '[]')"

    local domains_len
    domains_len="$(jq -r 'length' <<<"$domains_json" 2>/dev/null || echo 0)"

    if (( domains_len == 0 )); then
        echo "No domains available."
        return 1
    fi

    echo "Available Domains:"
    jq -r '.[].name' <<<"$domains_json" | nl -w2 -s'. '

    local domain_name=""
    if (( domains_len == 1 )); then
        domain_name="$(jq -r '.[0].name' <<<"$domains_json")"
    else
        local domain_index=""
        read -r -p "Enter the number of the domain you want to manage: " domain_index || return 1

        if [[ ! "$domain_index" =~ ^[0-9]+$ ]] || (( domain_index < 1 || domain_index > domains_len )); then
            echo "Invalid selection."
            return 1
        fi

        domain_name="$(jq -r --argjson index $((domain_index-1)) '.[$index].name' <<<"$domains_json")"
        printf "\nYou selected: %s\n" "$domain_name"
    fi

    local params_json
    params_json="$(jq -n --arg domain "$domain_name" '{"domain": $domain}')"

    local domain_info_json
    if ! domain_info_json="$(send_request "get-domain" "$params_json")"; then
        echo "Failed to get domain info for $domain_name."
        return 1
    fi

    local nameservers
    nameservers="$(jq -r '.nameservers // empty | join(", ")' <<<"$domain_info_json" 2>/dev/null || true)"

    local list_records_response
    if ! list_records_response="$(send_request "list-records" "$params_json")"; then
        echo "Failed to list records for $domain_name."
        return 1
    fi

    local records_json
    records_json="$(jq -c '.records // []' <<<"$list_records_response" 2>/dev/null || echo '[]')"

    local has_records=false
    if (( $(jq -r 'length' <<<"$records_json" 2>/dev/null || echo 0) > 0 )); then
        has_records=true
    fi

    if [[ -n "$nameservers" ]]; then
        echo "Nameservers for $domain_name: $nameservers"
    elif $has_records; then
        echo "Records for $domain_name:"
        local records_count
        records_count="$(jq -r 'length' <<<"$records_json")"

        for (( j=0; j<records_count; j++ )); do
            local record_details
            record_details="$(jq -r ".[$j] |
                \"ID:\" + (.id|tostring) +
                \" Type:\" + (.type|tostring) +
                \" Name:\" + (.name|tostring) +
                \" Content:\" + (.content|tostring) +
                \" TTL:\" + (.ttl|tostring)
            " <<<"$records_json" 2>/dev/null || true)"
            [[ -n "$record_details" ]] && echo "$record_details"
        done
    else
        echo "No records or nameservers available for domain: $domain_name"
    fi

    if [[ -n "$nameservers" || $has_records == true ]]; then
        local confirm_removal=""
        while true; do
            read -r -p "Do you want to remove all existing records or nameservers for $domain_name? (y/n): " confirm_removal || return 1
            if [[ "$confirm_removal" == "y" || "$confirm_removal" == "n" ]]; then
                break
            else
                echo "Invalid input. Please enter 'y' or 'n'."
            fi
        done

        if [[ "$confirm_removal" == "y" ]]; then
            if [[ -n "$nameservers" ]]; then
                local remove_ns_json
                remove_ns_json="$(jq -n --arg domain "$domain_name" '{"domain": $domain, "nameservers": []}')"

                if ! send_request "edit-domain" "$remove_ns_json" >/dev/null; then
                    echo "Failed to remove nameservers for $domain_name."
                    return 1
                fi

                echo "Nameservers removed. Waiting for propagation..."
                sleep 5
            fi

            if $has_records; then
                local records_count
                records_count="$(jq -r 'length' <<<"$records_json" 2>/dev/null || echo 0)"

                for (( k=0; k<records_count; k++ )); do
                    local record_id
                    record_id="$(jq -r ".[$k].id" <<<"$records_json" 2>/dev/null || true)"

                    [[ -z "$record_id" ]] && continue

                    local remove_json
                    remove_json="$(jq -n --arg domain "$domain_name" --arg id "$record_id" '{"domain": $domain, "id": $id}')"

                    if ! send_request "remove-record" "$remove_json" >/dev/null; then
                        echo "Record removal failed for ID $record_id."
                        continue
                    fi

                    echo "Record ID $record_id has been successfully removed."
                done
            fi
        else
            echo "Operation canceled. Exiting..."
            return 0
        fi
    fi

    local ip_address=""
    while true; do
        read -r -p "Enter the IP address for $domain_name the A record: " ip_address || return 1

        if [[ "$ip_address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            if [[ "$ip_address" == 127.* || "$ip_address" == 0.* || "$ip_address" =~ 25[6-9]|2[6-9][0-9]|[3-9][0-9][0-9] ]]; then
                echo "Invalid IP address entered. Please enter a valid IPv4 address."
            else
                break
            fi
        else
            echo "Invalid format. Please enter a valid IPv4 address."
        fi
    done

    local a_json
    a_json="$(jq -n \
        --arg domain  "$domain_name" \
        --arg name    "@" \
        --arg content "$ip_address" \
        --argjson ttl 3600 \
        --arg type    "A" \
        '{"domain": $domain, "name": $name, "content": $content, "ttl": $ttl, "type": $type}'
    )"

    echo "Adding A record..."
    if ! send_request "add-record" "$a_json" >/dev/null; then
        echo "Failed to add A record."
        return 1
    fi
    
    echo "A record added successfully."
    sleep 3
}
domain_info() {
    local response
    if ! response="$(send_request "list-domains" "{}")"; then
        echo "No domains found."
        return 1
    fi

    local domains_json
    domains_json="$(jq -c '.domains // []' <<<"$response" 2>/dev/null || echo '[]')"

    if (( $(jq -r 'length' <<<"$domains_json" 2>/dev/null || echo 0) == 0 )); then
        echo "No domains found."
        return 1
    fi

    clear
    printf '\e[3J'

    while IFS= read -r domain; do
        local name
        name="$(jq -r '.name' <<<"$domain" 2>/dev/null || true)"
        [[ -z "$name" ]] && continue

        local params_json
        params_json="$(jq -n --arg domain "$name" '{"domain": $domain}')"

        local d_info
        if ! d_info="$(send_request "get-domain" "$params_json")"; then
            echo "Domain not found or error occurred for $name."
            continue
        fi

        local status expiry formatted_expiry nameservers
        status="$(jq -r '.status // empty' <<<"$d_info" 2>/dev/null || true)"
        expiry="$(jq -r '.expiry // empty' <<<"$d_info" 2>/dev/null || true)"
        formatted_expiry="$(date -d "$expiry" "+%d.%m.%y" 2>/dev/null || echo "$expiry")"
        nameservers="$(jq -r '.nameservers // empty | join(", ")' <<<"$d_info" 2>/dev/null || true)"

        echo
        printf "%-15s %s\n" "Name:" "$name"
        printf "%-15s %s\n" "Status:" "$status"
        printf "%-15s %s\n" "Expiry:" "$formatted_expiry"
        [[ -n "$nameservers" ]] && printf "%-15s %s\n" "Nameservers:" "$nameservers"

        while IFS= read -r record; do
            [[ -n "$record" ]] && printf "%-15s %s\n" "Record:" "$record"
        done < <(
            jq -r '
                .records
                | if . != null then
                    .[]
                    | select(.type == "A" or .type == "AAAA" or .type == "CNAME" or .type == "MX" or .type == "TXT" or .type == "SRV")
                    | "\(.type): \(.value // .content // "")"
                  else empty end
            ' <<<"$d_info" 2>/dev/null
        )

        echo
    done < <(jq -c '.[]' <<<"$domains_json" 2>/dev/null)
}

api_url="https://njallalafimoej5i4eg7vlnqjvmb6zhdh27qxcatdn647jtwwwui3nad.onion/api/1/"
expected_prefix="${expected_prefix:-}"
prompt_for_api_token
domain_info
tor_newnym
add_a_records
EOL

RUN chown -R 1000:101 /opt/njalla && \
    chmod +x /opt/njalla/njalla

USER 1000:101
WORKDIR /opt/njalla
CMD ["sleep","infinity"]
EOF
}

main() {
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
    int_network_container_njalla_ipv4="${int_base}5"

    tmp_folder="$(mktemp -d -t njallastack.XXXXXXXX)"
    append_tmp_dir "$tmp_folder"
    rnd_proj_name="njallastack_$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
    trap 'cleanup_all; exit 130' INT
    trap 'cleanup_all' EXIT TERM HUP QUIT
    check_pkg
    require_docker_access
    preclean_patterns
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
    docker exec $tty_flag njalla /bin/bash -lc 'exec ./njalla'
}

if [[ "${BASH_SOURCE[0]-$0}" == "$0" ]]; then
    main "$@"
fi