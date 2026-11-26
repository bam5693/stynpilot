#!/bin/sh
# Fetch Ubuntu lab dependencies into an owner-only cache. Apt runs in download-only mode.
set -eu
umask 077
if [ "$(id -u)" -eq 0 ]; then
    echo 'Run bootstrap without sudo.' >&2
    exit 1
fi
dev_dir=${STYNPILOT_DEV_DIR:-"$HOME/.local/share/stynpilot-dev"}
case "$dev_dir" in
    /*) ;;
    *) echo 'STYNPILOT_DEV_DIR must be absolute' >&2; exit 1 ;;
esac
cache="$dev_dir/cache"
mkdir -p "$cache" "$dev_dir/work"
if [ ! -x "$cache/qemu/usr/bin/qemu-system-x86_64" ]; then
    mkdir -p "$cache/qemu-debs" "$cache/qemu"
    (
        cd "$cache/qemu-debs"
        apt-get download qemu-system-x86 qemu-utils qemu-system-common qemu-system-data seabios ipxe-qemu \
            libcacard0 libdaxctl1 libfdt1 libmpathcmd0 libmpathpersist0 libmultipath0 libndctl6 libpmem1 \
            librdmacm1t64 libslirp0 libusbredirparser1t64 ovmf-generic
        for package in ./*.deb; do dpkg-deb -x "$package" ../qemu; done
        sha256sum ./*.deb > SHA256SUMS.local
    )
fi
(
    mkdir -p "$cache/ubuntu-resolute"
    cd "$cache/ubuntu-resolute"
    image=ubuntu-26.04-server-cloudimg-amd64.img
    origin=https://cloud-images.ubuntu.com/releases/resolute/release
    if [ ! -f "$image" ]; then
        for file in SHA256SUMS SHA256SUMS.gpg; do
            curl --proto '=https' --fail --silent --show-error --location -o "$file" "$origin/$file"
        done
    fi
    gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS
    if [ ! -f "$image" ]; then
        curl --proto '=https' --fail --silent --show-error --location -o "$image.partial" "$origin/$image"
        awk -v file="*$image" '$2==file {print $1 " *" substr(file, 2) ".partial"}' SHA256SUMS | sha256sum --strict -c
        chmod a-w "$image.partial"
        mv "$image.partial" "$image"
    fi
    awk -v file="*$image" '$2==file' SHA256SUMS | sha256sum --strict -c
)
if [ "${1:-}" = "--guest-deps" ]; then
    guest="$cache/guest-debs"
    mkdir -p "$guest/partial"
    touch "$guest/status.empty"
    apt-get -o "Dir::State::status=$guest/status.empty" -o "Dir::Cache::archives=$guest" \
        -o Debug::NoLocking=true --yes --download-only --no-install-recommends install \
        python3-cryptography python3-jwt python3-starlette python3-uvicorn python3-httpx python3-pydantic \
        python3-pydantic-settings python3-sse-starlette python3-httpx-sse python3-jsonschema python3-multipart \
        python3-anyio python3-typing-extensions python3-typing-inspection polkitd ca-certificates acl python3-seccomp
    (cd "$guest" && sha256sum ./*.deb > SHA256SUMS.local)
fi
if [ ! -x "$dev_dir/venv/bin/python" ]; then
    python3 -m venv --system-site-packages "$dev_dir/venv"
fi
LD_LIBRARY_PATH="$cache/qemu/usr/lib/x86_64-linux-gnu" "$cache/qemu/usr/bin/qemu-system-x86_64" --version
"$dev_dir/venv/bin/python" -B -c 'import pytest, cryptography; print("pytest", pytest.__version__, "cryptography", cryptography.__version__)'
