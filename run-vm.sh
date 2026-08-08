#!/bin/bash
#
# run-vm.sh - build, boot, test and collect, unattended.
#
# Downloads a cloud image, overlays it, drops this source tree in over 9p,
# boots QEMU, builds the module inside the guest, runs qemu-tests.sh, copies
# the results back out and shuts down. Nothing touches the host kernel.
#
#   ./run-vm.sh                          smoke test on the cloud image's kernel
#   ./run-vm.sh --kdir ~/linux           boot your own kernel - use this one
#   ./run-vm.sh --soak --keep
#   ./run-vm.sh --shell                  drop to a guest shell instead
#
# Two modes, and the difference matters:
#
#   default    Boots the image's own distro kernel. No KASAN, no lockdep -
#              distro kernels do not ship them. You get functional coverage
#              and nothing more. Fine as a smoke test.
#
#   --kdir     Direct-boots a kernel you built, so you can turn on KASAN,
#              PROVE_LOCKING, PROVE_RCU, DEBUG_OBJECTS and kmemleak. This is
#              the configuration the tests were written for; everything else
#              is a weaker version of it.
#
#              ./run-vm.sh --print-kconfig > /tmp/frag
#              cd ~/linux && ./scripts/kconfig/merge_config.sh .config /tmp/frag
#              make -j$(nproc)
#              ./run-vm.sh --kdir ~/linux
#
# Results land in ./vm-results/ : the full console, the guest's own log, the
# test output and the guest dmesg. Exit status is the test suite's.
#
# Requires: qemu-system-x86_64, qemu-img, curl or wget, and one of
# cloud-localds / genisoimage / xorriso. KVM is used when available.
#

set -u

SRCDIR=$(cd "$(dirname "$0")" && pwd)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/xt_NAT-vm
RESULTS=$SRCDIR/vm-results
RUNDIR=""

# Current LTS. cloud-images.ubuntu.com serves releases under the version number
# as well as the codename, so there is no codename to keep up to date here.
# Override with UBUNTU_RELEASE=24.04, or --image for something else entirely.
UBUNTU_RELEASE=${UBUNTU_RELEASE:-26.04}
IMAGE_URL=${IMAGE_URL:-https://cloud-images.ubuntu.com/releases/$UBUNTU_RELEASE/release/ubuntu-$UBUNTU_RELEASE-server-cloudimg-amd64.img}
CPUS=4
MEMORY=4096
TIMEOUT=1800
KDIR=""
KERNEL=""
SOAK=0
KEEP=0
SHELL_MODE=0

if [ -t 1 ]; then
    C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
    C_G=""; C_R=""; C_Y=""; C_B=""; C_0=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
warn() { printf '%s warn:%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%serror:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0; }

# The guest needs netfilter, veth, namespaces and 9p; a plain defconfig has
# none of the netfilter pieces. The debug options are the reason to be here.
print_kconfig() {
cat <<'EOF'
# --- required for the test rig to work at all ---
CONFIG_NET_NS=y
CONFIG_VETH=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NETFILTER_XTABLES=y
CONFIG_NF_CONNTRACK=y
CONFIG_NETFILTER_XT_TARGET_CT=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_RAW=y
CONFIG_IP_NF_FILTER=y
CONFIG_NF_DEFRAG_IPV4=y
CONFIG_PACKET=y
# --- 9p, for getting the sources in and the results out ---
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
# --- virtio, for direct kernel boot with no initrd ---
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_EXT4_FS=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
# --- the point of the exercise ---
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_DEBUG_KERNEL=y
CONFIG_PROVE_LOCKING=y
CONFIG_PROVE_RCU=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_DEBUG_OBJECTS=y
CONFIG_DEBUG_OBJECTS_FREE=y
CONFIG_DEBUG_OBJECTS_TIMERS=y
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_SPINLOCK=y
CONFIG_SLUB_DEBUG=y
CONFIG_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=y
CONFIG_LOCK_STAT=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
EOF
}

# --------------------------------------------------------------- arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --kdir)    shift; KDIR=${1:-} ;;
        --kernel)  shift; KERNEL=${1:-} ;;
        --image)   shift; IMAGE_URL=${1:-} ;;
        --cpus)    shift; CPUS=${1:-4} ;;
        --memory)  shift; MEMORY=${1:-4096} ;;
        --timeout) shift; TIMEOUT=${1:-1800} ;;
        --soak)    SOAK=1 ;;
        --keep)    KEEP=1 ;;
        --shell)   SHELL_MODE=1 ;;
        --print-kconfig) print_kconfig; exit 0 ;;
        -h|--help) usage ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# ------------------------------------------------------------ dependencies ---

need() { command -v "$1" >/dev/null 2>&1; }

need qemu-system-x86_64 || die "qemu-system-x86_64 not installed"
need qemu-img           || die "qemu-img not installed"

# a progress bar redrawn with \r is noise in a log file or a CI job
if [ -t 1 ]; then CURL_P=--progress-bar; WGET_P=--show-progress
else            CURL_P=--no-progress-meter; WGET_P=--no-verbose; fi

if need curl; then FETCH="curl -fL $CURL_P -o"
elif need wget; then FETCH="wget -q $WGET_P -O"
else die "need curl or wget"; fi

MKISO=""
if   need cloud-localds; then MKISO=cloud-localds
elif need genisoimage;   then MKISO=genisoimage
elif need xorriso;       then MKISO=xorriso
else die "need one of cloud-localds, genisoimage or xorriso to build the cloud-init seed"
fi

if [ -n "$KDIR" ]; then
    [ -d "$KDIR" ] || die "--kdir: no such directory: $KDIR"
    [ -f "$KDIR/.config" ] || die "--kdir: $KDIR is not a configured kernel tree"
    [ -n "$KERNEL" ] || KERNEL=$KDIR/arch/x86/boot/bzImage
fi
if [ -n "$KERNEL" ]; then
    [ -f "$KERNEL" ] || die "kernel image not found: $KERNEL (build it first)"
fi

# ------------------------------------------------------------------- image ---

mkdir -p "$CACHE"
IMAGE=$CACHE/$(basename "$IMAGE_URL")

fetch_image() {
    if [ -f "$IMAGE" ]; then
        say "using cached image: $IMAGE"
        return
    fi
    step "downloading $(basename "$IMAGE_URL") (once, cached in $CACHE)"
    $FETCH "$IMAGE.part" "$IMAGE_URL" || die "download failed"

    # verify against the SHA256SUMS next to it, if we can get it
    local sums="${IMAGE_URL%/*}/SHA256SUMS" want have
    if need sha256sum && $FETCH "$CACHE/SHA256SUMS" "$sums" 2>/dev/null; then
        want=$(grep -F " *$(basename "$IMAGE_URL")" "$CACHE/SHA256SUMS" 2>/dev/null | cut -d' ' -f1)
        if [ -n "$want" ]; then
            have=$(sha256sum "$IMAGE.part" | cut -d' ' -f1)
            [ "$want" = "$have" ] || { rm -f "$IMAGE.part"; die "checksum mismatch on downloaded image"; }
            say "sha256 verified"
        else
            warn "image not listed in SHA256SUMS, skipping verification"
        fi
    else
        warn "could not fetch SHA256SUMS, skipping verification"
    fi
    mv "$IMAGE.part" "$IMAGE"
}

# ------------------------------------------------------------- guest runner ---

# Written into the share and executed by cloud-init. Everything it prints goes
# to the serial console, so a host-side tee is the full record even if the
# guest never gets far enough to write a file back.
write_guest_runner() {
cat >"$RUNDIR/share/guest-run.sh" <<'GUEST'
#!/bin/bash
set -u
SHARE=/mnt/xtnat
ART=$SHARE/artifacts
mkdir -p "$ART"
exec > >(tee -a "$ART/guest.log") 2>&1

echo "### guest kernel: $(uname -r)"
echo "### $(head -1 /etc/os-release 2>/dev/null)"

fatal() { echo "### GUEST FATAL: $*"; echo 90 > "$ART/exit-code"; finish; }
finish() {
    dmesg > "$ART/dmesg.txt" 2>/dev/null
    [ -r /proc/lock_stat ] && cp /proc/lock_stat "$ART/lock_stat.txt" 2>/dev/null
    sync
    echo "### XTNAT-DONE rc=$(cat "$ART/exit-code" 2>/dev/null || echo 91)"
    exit 0
}

export DEBIAN_FRONTEND=noninteractive
PKGS="build-essential pkg-config libxtables-dev iptables tcpdump ethtool python3 kmod"
[ "${BUILD_MODULE_IN_GUEST:-0}" = 1 ] && PKGS="$PKGS linux-headers-$(uname -r)"

echo "### installing: $PKGS"
apt-get update -qq          || echo "### apt update failed, continuing"
apt-get install -y -qq $PKGS || fatal "could not install build dependencies"

# 9p is fine for reading, but build somewhere native
rm -rf /root/src && mkdir -p /root/src
cp -a "$SHARE"/src/. /root/src/
cd /root/src || fatal "no source"

if [ "${BUILD_MODULE_IN_GUEST:-0}" = 1 ]; then
    echo "### building xt_NAT.ko against $(uname -r)"
    make -C "/lib/modules/$(uname -r)/build" M=/root/src modules \
        || fatal "module build failed"
else
    echo "### using xt_NAT.ko built on the host"
    [ -f /root/src/xt_NAT.ko ] || fatal "no prebuilt xt_NAT.ko in the share"
fi

echo "### building libxt_NAT.so"
make libxt_NAT.so || fatal "userspace extension build failed"

modinfo /root/src/xt_NAT.ko | sed -n '1,6p'

echo "### running qemu-tests.sh ${TEST_ARGS:-}"
chmod +x /root/src/qemu-tests.sh
MODULE=/root/src/xt_NAT.ko /root/src/qemu-tests.sh ${TEST_ARGS:-}
rc=$?
echo $rc > "$ART/exit-code"
echo "### qemu-tests.sh exited $rc"

cp /root/src/xt_NAT.ko "$ART/" 2>/dev/null
finish
GUEST
chmod +x "$RUNDIR/share/guest-run.sh"
}

write_cloud_init() {
    local testargs=""
    [ $SOAK = 1 ] && testargs="--soak"

    cat >"$RUNDIR/meta-data" <<EOF
instance-id: xtnat-$$
local-hostname: xtnat-test
EOF

    if [ $SHELL_MODE = 1 ]; then
        cat >"$RUNDIR/user-data" <<EOF
#cloud-config
password: xtnat
chpasswd: { expire: false }
ssh_pwauth: true
runcmd:
  - [ sh, -c, "mkdir -p /mnt/xtnat && mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 xtnat /mnt/xtnat" ]
  - [ sh, -c, "echo '### share mounted at /mnt/xtnat - log in as ubuntu/xtnat' > /dev/console" ]
EOF
    else
        cat >"$RUNDIR/user-data" <<EOF
#cloud-config
runcmd:
  - [ sh, -c, "mkdir -p /mnt/xtnat && mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 xtnat /mnt/xtnat || echo '### 9p mount FAILED' > /dev/console" ]
  - [ sh, -c, "BUILD_MODULE_IN_GUEST=$BUILD_IN_GUEST TEST_ARGS='$testargs' bash /mnt/xtnat/guest-run.sh > /dev/console 2>&1" ]
power_state:
  mode: poweroff
  timeout: 60
  condition: true
EOF
    fi

    case $MKISO in
        cloud-localds)
            cloud-localds "$RUNDIR/seed.iso" "$RUNDIR/user-data" "$RUNDIR/meta-data" ;;
        genisoimage)
            genisoimage -quiet -output "$RUNDIR/seed.iso" -volid cidata -joliet -rock \
                        "$RUNDIR/user-data" "$RUNDIR/meta-data" ;;
        xorriso)
            xorriso -as mkisofs -quiet -output "$RUNDIR/seed.iso" -volid CIDATA -joliet -rock \
                    "$RUNDIR/user-data" "$RUNDIR/meta-data" ;;
    esac || die "could not build the cloud-init seed image"
}

# -------------------------------------------------------------------- main ---

step "xt_NAT VM test run"

fetch_image

RUNDIR=$(mktemp -d "${TMPDIR:-/tmp}/xtnat-vm.XXXXXX")
mkdir -p "$RUNDIR/share/src"

cleanup() {
    if [ $KEEP = 1 ]; then
        say "--keep: run directory left at $RUNDIR"
    else
        rm -rf "$RUNDIR"
    fi
}
trap cleanup EXIT INT TERM

# ---- assemble the payload

step "assembling the guest payload"
cp "$SRCDIR"/*.c "$SRCDIR"/*.h "$SRCDIR/Makefile" "$SRCDIR/qemu-tests.sh" "$RUNDIR/share/src/" \
    || die "could not copy the source tree"

BUILD_IN_GUEST=1
if [ -n "$KDIR" ]; then
    BUILD_IN_GUEST=0
    step "building xt_NAT.ko on the host against $KDIR"
    make -C "$KDIR" M="$SRCDIR" modules >/dev/null || die "host module build failed"
    cp "$SRCDIR/xt_NAT.ko" "$RUNDIR/share/src/" || die "no xt_NAT.ko produced"
    say "$(modinfo "$SRCDIR/xt_NAT.ko" | sed -n 's/^vermagic: */vermagic: /p')"
fi

write_guest_runner
write_cloud_init

# ---- overlay so the downloaded image is never written to

step "creating overlay disk"
qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$RUNDIR/disk.qcow2" 20G \
    || die "qemu-img create failed"

# ---- boot

QEMU=(qemu-system-x86_64
      -m "$MEMORY" -smp "$CPUS"
      -drive "file=$RUNDIR/disk.qcow2,if=virtio,format=qcow2"
      -drive "file=$RUNDIR/seed.iso,if=virtio,format=raw,readonly=on"
      -virtfs "local,path=$RUNDIR/share,mount_tag=xtnat,security_model=none,id=xtnat"
      -nic user,model=virtio-net-pci
      -nographic -no-reboot)

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    QEMU+=(-enable-kvm -cpu host)
    say "KVM: enabled"
else
    warn "no access to /dev/kvm - falling back to emulation, this will be slow"
    QEMU+=(-cpu max)
fi

if [ -n "$KERNEL" ]; then
    say "kernel: $KERNEL (direct boot)"
    QEMU+=(-kernel "$KERNEL"
           -append "root=LABEL=cloudimg-rootfs rw console=ttyS0 net.ifnames=0 kmemleak=on")
else
    warn "using the cloud image's own kernel: no KASAN, no lockdep."
    warn "for real coverage build a debug kernel and pass --kdir (see --help)."
fi

mkdir -p "$RESULTS"
rm -f "$RESULTS"/*.log "$RESULTS"/*.txt 2>/dev/null
CONSOLE=$RESULTS/console.log

if [ $SHELL_MODE = 1 ]; then
    step "booting to a shell (login ubuntu/xtnat, share at /mnt/xtnat; Ctrl-A X to quit)"
    "${QEMU[@]}"
    exit $?
fi

step "booting (timeout ${TIMEOUT}s; console -> $CONSOLE)"
say "    Ctrl-A X to abort"
timeout --foreground "$TIMEOUT" "${QEMU[@]}" 2>&1 | tee "$CONSOLE"
qemu_rc=${PIPESTATUS[0]}

# ---- collect

step "collecting results"
for f in guest.log dmesg.txt lock_stat.txt exit-code; do
    [ -f "$RUNDIR/share/artifacts/$f" ] && cp "$RUNDIR/share/artifacts/$f" "$RESULTS/"
done

rc=""
[ -f "$RESULTS/exit-code" ] && rc=$(tr -dc '0-9' < "$RESULTS/exit-code")

say ""
if [ "$qemu_rc" = 124 ]; then
    say "${C_R}VM timed out after ${TIMEOUT}s${C_0} - see $CONSOLE"
    exit 124
fi
if [ -z "$rc" ]; then
    say "${C_R}the guest never reported a result${C_0}"
    say "the last of the console follows; full log in $CONSOLE"
    tail -30 "$CONSOLE" | sed 's/^/    | /'
    exit 1
fi

# replay the suite's own summary rather than paraphrasing it
if [ -f "$RESULTS/guest.log" ]; then
    sed -n '/^== summary ==/,$p' "$RESULTS/guest.log" | sed 's/^/    /'
fi

say ""
say "artifacts in $RESULTS/:"
for f in "$RESULTS"/*; do [ -f "$f" ] && printf '    %s (%s)\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)"; done

if [ -f "$RESULTS/dmesg.txt" ]; then
    n=$(grep -cE '\bBUG:|KASAN|UBSAN|WARNING:|INFO: possible|suspicious RCU' "$RESULTS/dmesg.txt")
    [ "${n:-0}" -gt 0 ] && say "" && say "${C_Y}$n suspicious line(s) in guest dmesg - check $RESULTS/dmesg.txt${C_0}"
fi

say ""
if [ "$rc" = 0 ]; then
    say "${C_G}all tests passed${C_0}"
else
    say "${C_R}tests failed (exit $rc)${C_0}"
fi
exit "$rc"
