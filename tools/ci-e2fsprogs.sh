#!/usr/bin/env bash
# Build a pinned e2fsprogs into a prefix (idempotent; cache the prefix).
#
# The differential tests are oracle-version-sensitive: DESIGN.md's
# [verified] claims are against e2fsprogs 1.47.4 exactly, so CI must not
# float with distro/brew packaging.
#
# Usage: tools/ci-e2fsprogs.sh <version> <prefix>

set -euo pipefail

VER=$1
PREFIX=$2

if [ -x "$PREFIX/sbin/mke2fs" ] && "$PREFIX/sbin/mke2fs" -V 2>&1 | head -1 | grep -qF "$VER"; then
    echo "e2fsprogs $VER already present at $PREFIX (cached)"
    exit 0
fi

SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT

URL="https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$VER/e2fsprogs-$VER.tar.gz"
echo "downloading $URL"
# kernel.org mirrors intermittently reset HTTP/2 streams from CI runners;
# force HTTP/1.1 and retry hard.
curl -fsSL --http1.1 --retry 8 --retry-all-errors --retry-delay 5 \
    "$URL" -o "$SRC/e2fsprogs.tar.gz"
tar -xzf "$SRC/e2fsprogs.tar.gz" -C "$SRC"

cd "$SRC/e2fsprogs-$VER"
# =no on the system-integration dirs keeps `make install` inside the
# prefix (otherwise install-udev writes to /usr/lib/udev and fails).
./configure --prefix="$PREFIX" --disable-nls --disable-fuse2fs \
    --with-udev-rules-dir=no --with-systemd-unit-dir=no --with-crond-dir=no >/dev/null
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null
make install >/dev/null
echo "installed e2fsprogs $VER to $PREFIX"
"$PREFIX/sbin/mke2fs" -V
