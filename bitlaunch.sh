#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

info() { printf "[info] %s\n" "$*"; }
warn() { printf "[warn] %s\n" "$*"; }
err() { printf "[error] %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }
wipe() { clear 2>/dev/null || true; printf '\e[3J' 2>/dev/null || true; }

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
            wipe
            err "Docker is not installed."
            info "hint: Install Docker Desktop, launch it, then re-run this script."
            exit 1
        fi

        if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" == unix://* ]]; then
            local sock
            sock="${DOCKER_HOST#unix://}"
            if [[ ! -S "$sock" ]]; then
                wipe
                err  "DOCKER_HOST points to '$sock', but that socket does not exist."
                info "hint: Start Docker Desktop, or run: unset DOCKER_HOST ; docker context use default"
                exit 1
            fi
        fi

        if ! docker info >/dev/null 2>&1; then
            wipe
            err  "Docker is installed but not running."
            info "hint: Open 'Docker.app' and wait until the whale icon stops animating, then re-run this script."
            info "hint: If you use custom contexts, try: unset DOCKER_HOST ; docker context use default"
            exit 1
        fi

        DOCKER_OK=1
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        wipe
        err "Docker is not installed."
        info "hint: install docker, then re-run this script."
        exit 1
    fi

    local cur_user
    cur_user="${USER:-$(id -un 2>/dev/null || true)}"
    [[ -n "$cur_user" ]] || cur_user="$(whoami 2>/dev/null || true)"
    [[ -n "$cur_user" ]] || { wipe; err "Unable to determine current user."; exit 1; }

    # Linux: require docker group membership; do not call docker if not in group.
    if ! id -nG "$cur_user" | tr ' ' '\n' | grep -qx docker; then
        wipe
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
        wipe
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
    for name in exit_a exit_b haproxy bitlaunch; do
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

    for name in exit_a exit_b haproxy bitlaunch; do
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

    cat >"$guard" <<'EOF'
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

    for name in exit_a exit_b haproxy bitlaunch; do
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
EOF

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
on_host_sigint() {
    wipe
    echo
    warn "Interrupted by Ctrl+C. Cleaning up..."
    cleanup_all
    exit 130
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
                sudo groupadd docker 2>/dev/null || true
                sudo usermod -aG docker $USER
                ;;
            arch|manjaro)
                [[ "${QUIET_CHECK_PKG:-0}" == "1" ]] || info "installing docker (Arch/Manjaro)…"
                sudo pacman -Sy --needed --noconfirm docker docker-compose >/dev/null 2>&1
                sudo groupadd docker 2>/dev/null || true
                sudo usermod -aG docker $USER
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
    mkdir -p "${tmp_folder}/${rnd_proj_name}"/{exit,haproxy,bitlaunch}

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
    init: true
    stop_signal: SIGTERM
    stop_grace_period: 5s
    cap_drop: ["ALL"]
    read_only: true
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,mode=1777
      - /var/lib/tor:rw,nosuid,nodev,noexec,mode=0700,uid=100,gid=101
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
    init: true
    stop_signal: SIGTERM
    stop_grace_period: 5s
    cap_drop: ["ALL"]
    read_only: true
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,mode=1777
      - /var/lib/tor:rw,nosuid,nodev,noexec,mode=0700,uid=100,gid=101
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
    init: true
    stop_signal: SIGTERM
    stop_grace_period: 2s
    cap_drop: ["ALL"]
    read_only: true
    pids_limit: 100
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,mode=1777
      - /run:rw,nosuid,nodev,noexec,mode=0755
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

  bitlaunch:
    container_name: bitlaunch
    build:
      context: ./bitlaunch
      dockerfile: Dockerfile
      args:
        int_network_container_haproxy_ipv4: "${int_network_container_haproxy_ipv4}"
    runtime: runc
    init: true
    stop_signal: SIGTERM
    stop_grace_period: 2s
    cap_drop: ["ALL"]
    read_only: true
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,mode=1777
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
    logging: { driver: "none" }
    volumes:
      - exit_a:/run/tor_a:ro
      - exit_b:/run/tor_b:ro
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
        printf '%b' "Package: tor tor-geoipdb deb.torproject.org-keyring\nPin: origin deb.torproject.org\nPin-Priority: 990\n" > /etc/apt/preferences.d/99-torproject; \
    else \
        printf '%b' "# no torproject pin on non-amd64\n" > /etc/apt/preferences.d/99-torproject; \
    fi && \
    printf '%b' "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: forky\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n" > /etc/apt/sources.list.d/forky.sources && \
    printf '%b' "Package: *\nPin: release n=forky\nPin-Priority: 100\n\nPackage: vanguards python3-stem python3-pkg-resources\nPin: release n=forky\nPin-Priority: 990\n" > /etc/apt/preferences.d/99-vanguards && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y tor deb.torproject.org-keyring nyx vanguards

COPY --from=build /out/ /tmp/torbuild/
RUN set -Eeuo pipefail; \
    if ls /tmp/torbuild/*.deb >/dev/null 2>&1; then \
        apt-get update -qq; \
        apt-get install -y --no-install-recommends /tmp/torbuild/*.deb; \
    fi; \
    apt-get update -qq; \
    apt-get install -y --no-install-recommends tor-geoipdb; \
    rm -rf /tmp/torbuild; \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/tor /var/lib/tor /usr/local/bin && \
    chown -R debian-tor:debian-tor /run/tor /var/lib/tor && \
    chmod 750 /run/tor && \
    chmod 700 /var/lib/tor

RUN cat > /etc/tor/vanguards.conf <<'EOS'
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
EOS

RUN install -m 0755 -o root -g root /dev/stdin /usr/local/bin/healthcheck <<'EOS'
#!/bin/bash
set -Eeuo pipefail
[ -S /run/tor/control.sock ] || exit 1
[ -r /run/tor/control.authcookie ] || exit 1
cookie="$(xxd -p /run/tor/control.authcookie | tr -d '\n')"
printf "AUTHENTICATE $cookie\r\ngetinfo status/bootstrap-phase\r\nquit\r\n" | nc -U /run/tor/control.sock | grep -q 'PROGRESS=100' || exit 1
printf "AUTHENTICATE $cookie\r\ngetinfo circuit-status\r\nquit\r\n" | nc -U /run/tor/control.sock | grep -q 'BUILT' || exit 1
ps aux | grep '[v]anguards' > /dev/null || exit 1
exit 0
EOS

RUN install -m 0755 -o root -g root /dev/stdin /usr/local/bin/entrypoint-docker.sh <<'EOS'
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

shutdown() {
    kill -TERM "$vg_pid" 2>/dev/null || true
    kill -TERM "$tor_pid" 2>/dev/null || true

    for _ in $(seq 1 50); do
        kill -0 "$vg_pid" 2>/dev/null || vg_dead=1
        kill -0 "$tor_pid" 2>/dev/null || tor_dead=1
        if [[ "${vg_dead:-0}" == "1" && "${tor_dead:-0}" == "1" ]]; then
            exit 0
        fi
        sleep 0.1
    done

    kill -KILL "$vg_pid" 2>/dev/null || true
    kill -KILL "$tor_pid" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

for _ in $(seq 1 240); do
    kill -0 "$tor_pid" 2>/dev/null || exit 1
    if [ -S /run/tor/control.sock ] && [ -r /run/tor/control.authcookie ]; then
        cookie="$(xxd -p /run/tor/control.authcookie | tr -d '\n')"
        resp="$(printf "AUTHENTICATE %s\r\ngetinfo status/bootstrap-phase\r\nquit\r\n" "$cookie" | nc -U /run/tor/control.sock -w 5 -q 1 || true)"
        echo "$resp" | grep -q 'PROGRESS=100' && break
    fi
    sleep 1
done

if ! ( [ -S /run/tor/control.sock ] && [ -r /run/tor/control.authcookie ] ); then
    exit 1
fi

vanguards --config /etc/tor/vanguards.conf &
vg_pid=$!
wait -n "$tor_pid" "$vg_pid" || true
shutdown
EOS

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

RUN cat > /etc/haproxy/haproxy.cfg <<EOS
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
EOS

RUN apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER haproxy:haproxy
CMD ["haproxy","-f","/etc/haproxy/haproxy.cfg","-db"]
EOF

cat <<'EOF'> "${tmp_folder}/${rnd_proj_name}/bitlaunch/Dockerfile"
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

ARG int_network_container_haproxy_ipv4
ENV int_network_container_haproxy_ipv4="${int_network_container_haproxy_ipv4}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's|http://deb.debian.org/debian|https://deb.debian.org/debian|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata bash curl jq socat xxd bc bsdextrautils && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN groupadd -g 101 user && \
    useradd -u 1000 -g 101 -r -M -s /usr/sbin/nologin user && \
    mkdir -p /opt/bitlaunch
    
RUN cat > /opt/bitlaunch/bitlaunch <<'EOS'
#!/bin/bash
set -Eeuo pipefail

# Ensure variables exist under `set -u`
: "${API_TOKEN:=}"
: "${int_network_container_haproxy_ipv4:=}"

# Trim API_TOKEN if it was provided via env
API_TOKEN="${API_TOKEN#"${API_TOKEN%%[![:space:]]*}"}"
API_TOKEN="${API_TOKEN%"${API_TOKEN##*[![:space:]]}"}"

HTTP_HEADERS=()
PROXY_ARGS=(--proxy "socks5h://${int_network_container_haproxy_ipv4}:9095")

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

restore_tty() {
    tput cnorm 2>/dev/null || true
    if [[ "${tty_is_tty}" -eq 1 ]]; then
        [[ -n "${__orig_stty:-}" ]] && stty "${__orig_stty}" 2>/dev/null || true
    fi
}

cleanup() { restore_tty; }

on_sigint() {
    clear_screen
    restore_tty
    echo
    echo "Interrupted by Ctrl+C. Exiting..."
    exit 130
}

on_sigterm() {
    restore_tty
    echo
    echo "Received SIGTERM. Exiting..."
    exit 143
}

safe_fmt_date() {
    # Safe date format helper: if parsing fails, return the input as-is
    local _in="${1:-}"
    local _fmt="${2:-+%d.%m.%Y}"
    date -d "$_in" "$_fmt" 2>/dev/null || echo "$_in"
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
    local min="${1:-1.5}"
    local max="${2:-2.0}"
    local seed rand
    seed="${RANDOM}$(od -An -N2 -i /dev/urandom 2>/dev/null || echo 0)"
    rand=$(awk -v min="$min" -v max="$max" -v seed="$seed" 'BEGIN{srand(systime() + seed); print min + rand() * (max - min)}')
    [[ -n "$rand" ]] && sleep "$rand"
}

token_format_ok() {
    local t="$1"

    [[ -n "$t" ]] || return 1
    [[ "$t" != *$' '* && "$t" != *$'\t'* && "$t" != *$'\n'* && "$t" != *$'\r'* ]] || return 1

    [[ "$t" == eyJ* ]] || return 1
    [[ "$t" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] || return 1

    return 0
}

bitlaunch_check_token() {
    local token="$1" out http body email
    out="$(curl "${PROXY_ARGS[@]}" -sS --tlsv1.3 --http2 --proto '=https' --connect-timeout 6 --max-time 6 -H "Authorization: Bearer ${token}" -H "Accept: application/json" "https://app.bitlaunch.io/api/user" -w $'\n%{http_code}' || true)"
    http="${out##*$'\n'}"
    body="${out%$'\n'*}"

    [[ -n "${http:-}" ]] || { echo "Token check failed: network/proxy/timeout." >&2; return 1; }
    [[ "$http" == "200" ]] || { echo "Invalid API Token (HTTP $http)." >&2; return 1; }

    jq -e . >/dev/null 2>&1 <<<"$body" || { echo "Token check failed: invalid JSON." >&2; return 1; }
    [[ "$body" != "null" ]] || { echo "Invalid API Token (null user)." >&2; return 1; }

    email="$(jq -r '.email // empty' <<<"$body")"
    [[ -n "$email" ]] || { echo "Token check failed: user email missing." >&2; return 1; }

    return 0
}

validate_api_token() {
    local token="${1:-${API_TOKEN:-}}"

    if ! token_format_ok "$token"; then
        echo "Invalid API Token format (expected JWT like eyJ...x.y.z)." >&2
        return 1
    fi

    bitlaunch_check_token "$token"
}

prompt_for_api_token() {
    local attempt=0
    local max_attempts=3

    while (( attempt < max_attempts )); do
        clear_screen

        if (( attempt > 0 )); then
            echo "Invalid API Token. Please try again."
            echo
        fi

        printf "Enter Bitlaunch API Token: "
        read -r API_TOKEN || true

        API_TOKEN="${API_TOKEN#"${API_TOKEN%%[![:space:]]*}"}"
        API_TOKEN="${API_TOKEN%"${API_TOKEN##*[![:space:]]}"}"

        if validate_api_token "$API_TOKEN"; then
            clear_screen
            echo "API Token accepted."
            return 0
        fi

        ((attempt++))
        delay 0.4 0.8
    done

    clear_screen
    echo "You have reached the maximum number of attempts." >&2
    return 1
}
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
                local server creation_date cost_per_hour vm_ipv4 vm_ipv6 host host_image_id size name status errortext image_description
                server=$(echo "$server_data" | jq -r --arg vm_id "$vm_id" '.[] | select(.id == $vm_id)')
                creation_date=$(echo "$server" | jq -r '.created')
                cost_per_hour=$(echo "$server" | jq -r '.rate / 1000')
                vm_ipv4=$(echo "$server" | jq -r '.ipv4 // empty')
                vm_ipv6=$(echo "$server" | jq -r '(.ipv6 // .ipV6 // .ipv6Address // empty) | if type=="array" then .[0] else . end')
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
                [[ -n "$vm_ipv4" ]] && printf "%-25s %s\n" "IPv4:" "$vm_ipv4"
                [[ -n "$vm_ipv6" ]] && printf "%-25s %s\n" "IPv6:" "$vm_ipv6"
                [[ -z "$vm_ipv4" && -z "$vm_ipv6" ]] && printf "%-25s %s\n" "IP Address:" "-"
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
    local image_id=$(echo "$bit_json" | jq -r '.image[] | select(.name == "Debian" and .version.description == "Debian 12").version.id')
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
                        local vm_ipv4=$(echo "$last_vm" | jq -r '.ipv4 // empty')
                        local vm_ipv6=$(echo "$last_vm" | jq -r '(.ipv6 // .ipV6 // .ipv6Address // empty) | if type=="array" then .[0] else . end')
                        
                        if [[ "$status" == "error" ]] || { [[ -z "$vm_ipv4" ]] && [[ -z "$vm_ipv6" ]]; }; then
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
                            [[ -n "$vm_ipv4" ]] && printf "%-25s %s\n" "IPv4:" "$vm_ipv4"
                            [[ -n "$vm_ipv6" ]] && printf "%-25s %s\n" "IPv6:" "$vm_ipv6"
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
                        
                        local last_vm=$(echo "$server_data" | jq --arg vm_id "$vm_id" -r '.[] | select(.id == $vm_id)')
                        local status=$(echo "$last_vm" | jq -r '.status')
                        local vm_ipv4=$(echo "$last_vm" | jq -r '.ipv4 // empty')
                        local vm_ipv6=$(echo "$last_vm" | jq -r '(.ipv6 // .ipV6 // .ipv6Address // empty) | if type=="array" then .[0] else . end')
                        
                        if [[ "$status" == "error" ]] || { [[ -z "$vm_ipv4" ]] && [[ -z "$vm_ipv6" ]]; }; then
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
                            [[ -n "$vm_ipv4" ]] && printf "%-25s %s\n" "IPv4:" "$vm_ipv4"
                            [[ -n "$vm_ipv6" ]] && printf "%-25s %s\n" "IPv6:" "$vm_ipv6"
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
    if [[ -z "${API_TOKEN:-}" ]]; then
        if prompt_for_api_token; then
            HTTP_HEADERS=($(generate_http_headers))
            tor_newnym
        else
            echo "Invalid Bitlaunch API Token. Exiting..." >&2
            exit 1
        fi
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
EOS

RUN chown -R 1000:101 /opt/bitlaunch && \
    chmod +x /opt/bitlaunch/bitlaunch

USER 1000:101
WORKDIR /opt/bitlaunch
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
    int_network_container_bitlaunch_ipv4="${int_base}5"

    tmp_folder="$(mktemp -d -t bitlaunchstack.XXXXXXXX)"
    append_tmp_dir "$tmp_folder"
    rnd_proj_name="bitlaunchstack_$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
    trap on_host_sigint INT
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
    wipe
    docker exec $tty_flag bitlaunch /bin/bash -lc 'exec ./bitlaunch'
}

if [[ "${BASH_SOURCE[0]-$0}" == "$0" ]]; then
    main "$@"
fi