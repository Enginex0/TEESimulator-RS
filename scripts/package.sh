#!/usr/bin/env bash
# Build, package, deploy, and verify TEESimulator module ZIPs.
# Usage: ./scripts/package.sh [flags]
#
# Examples:
#   ./scripts/package.sh --release                    # build release ZIP
#   ./scripts/package.sh --all --clean                # clean build, both variants
#   ./scripts/package.sh --release --deploy --reboot  # build, push, install, reboot
#   ./scripts/package.sh --deploy --verify            # deploy latest ZIP + verify via logcat
#   ./scripts/package.sh --rust --release             # build Rust crate first, then release
set -euo pipefail

# Gradle's buildRustCertgen resolves `cargo` against the daemon's inherited PATH,
# not the env we inject via gradle's Exec.environment(). Prepend the per-user
# rustup install so non-login shells (CI, IDE-launched terminals, fresh tmux)
# still find it without sourcing /etc/profile.d/cargo-path.sh.
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$PROJECT_ROOT/out"

VARIANT=""
CLEAN=false
DEPLOY=false
REBOOT=false
VERIFY=false
BUILD_RUST=false
CLEAR_KEYS=false
CLEAR_LOGS=false
TRACE=false
ROOT_PROVIDER="ksu"

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Build variants (pick one, or --all):
  --release          Build release variant (default if none specified)
  --debug            Build debug variant
  --all              Build both debug and release

Build options:
  --clean            Run gradle clean before building
  --rust             Build native-certgen Rust crate before Gradle

Deploy options:
  --deploy           Push ZIP to device and install
  --reboot           Reboot device after install
  --clear-keys       Clear persistent_keys before deploy
  --clear-logs       Clear per-UID diagnostic logs before deploy
  --verify           Run logcat verification after deploy
  --root PROVIDER    Root provider: ksu (default), magisk, apatch

Misc:
  -v, --verbose      Print every command as it runs (set -x)
  --help             Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)    VARIANT="release"; shift ;;
        --debug)      VARIANT="debug"; shift ;;
        --all)        VARIANT="all"; shift ;;
        --clean)      CLEAN=true; shift ;;
        --deploy)     DEPLOY=true; shift ;;
        --reboot)     REBOOT=true; shift ;;
        --verify)     VERIFY=true; shift ;;
        --rust)       BUILD_RUST=true; shift ;;
        --clear-keys) CLEAR_KEYS=true; shift ;;
        --clear-logs) CLEAR_LOGS=true; shift ;;
        -v|--verbose) TRACE=true; shift ;;
        --root)       ROOT_PROVIDER="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            red "Unknown flag: $1"; usage ;;
    esac
done

[[ -z "$VARIANT" ]] && VARIANT="release"
[[ "$TRACE" == true ]] && set -x

case "$ROOT_PROVIDER" in
    ksu)     INSTALL_CMD="ksud module install" ;;
    magisk)  INSTALL_CMD="magisk --install-module" ;;
    apatch)  INSTALL_CMD="/data/adb/apd module install" ;;
    *)       red "Unknown root provider: $ROOT_PROVIDER"; exit 1 ;;
esac

build_rust() {
    local cargo_toml="$PROJECT_ROOT/native-certgen/Cargo.toml"
    if [[ ! -f "$cargo_toml" ]]; then
        red "native-certgen/Cargo.toml not found — skipping Rust build"
        return 0
    fi

    bold "==> Building native-certgen (aarch64)"

    if ! command -v cargo-ndk &>/dev/null; then
        red "cargo-ndk not found. Install: cargo install cargo-ndk"
        exit 1
    fi

    (cd "$PROJECT_ROOT/native-certgen" && \
        cargo ndk -t arm64-v8a --platform 29 -- build --release)

    local so="$PROJECT_ROOT/native-certgen/target/aarch64-linux-android/release/libcertgen.so"
    if [[ -f "$so" ]]; then
        local size
        size=$(du -h "$so" | cut -f1)
        green "    libcertgen.so built ($size)"
    else
        red "    libcertgen.so not found after build"
        exit 1
    fi
}

gradle_build() {
    local tasks=()

    [[ "$CLEAN" == true ]] && tasks+=(clean)

    case "$VARIANT" in
        release) tasks+=(zipRelease) ;;
        debug)   tasks+=(zipDebug) ;;
        all)     tasks+=(zipDebug zipRelease) ;;
    esac

    bold "==> Gradle: ${tasks[*]}"
    (cd "$PROJECT_ROOT" && ./gradlew "${tasks[@]}")
}

find_latest_zip() {
    local pattern="$1"
    ls -t "$OUT_DIR"/$pattern 2>/dev/null | head -1
}

deploy_zip() {
    local zip="$1"
    local name
    name=$(basename "$zip")

    if ! adb get-state &>/dev/null; then
        red "No ADB device connected"
        exit 1
    fi

    if [[ "$CLEAR_KEYS" == true ]]; then
        bold "==> Clearing persistent_keys"
        adb shell "rm -rf /data/adb/tricky_store/persistent_keys/*" 2>/dev/null || true
    fi

    if [[ "$CLEAR_LOGS" == true ]]; then
        bold "==> Clearing per-UID diagnostic logs"
        adb shell "rm -rf /data/media/0/TEESimulator /data/local/tmp/teesim" 2>/dev/null || true
    fi

    bold "==> Deploying $name"
    adb push "$zip" /data/local/tmp/module.zip
    adb shell "su -c '$INSTALL_CMD /data/local/tmp/module.zip'"
    green "    Installed via $ROOT_PROVIDER"

    if [[ "$REBOOT" == true ]]; then
        bold "==> Rebooting"
        adb reboot
        echo "    Waiting for device..."
        adb wait-for-device
        sleep 10
        local pid
        pid=$(adb shell "pidof TEESimulator" 2>/dev/null || true)
        if [[ -n "$pid" ]]; then
            green "    Daemon alive (PID $pid)"
        else
            yellow "    Daemon not yet started — check logcat"
        fi
    fi
}

verify_device() {
    bold "==> Verification"

    if ! adb get-state &>/dev/null; then
        red "No ADB device connected"
        exit 1
    fi

    local pid
    pid=$(adb shell "pidof TEESimulator" 2>/dev/null || true)
    if [[ -n "$pid" ]]; then
        green "    Daemon: running (PID $pid)"
    else
        red "    Daemon: not running"
    fi

    local tee_status
    tee_status=$(adb shell "cat /data/adb/tricky_store/tee_status.txt" 2>/dev/null || echo "N/A")
    echo "    TEE status: $tee_status"

    local sec_patch
    sec_patch=$(adb shell "cat /data/adb/tricky_store/security_patch.txt" 2>/dev/null || echo "N/A")
    echo "    Security patch config: $(echo "$sec_patch" | head -1)"

    local errors
    errors=$(adb logcat -d -s TEESimulator 2>/dev/null | \
        grep -iE "error|exception" | \
        grep -v "StrongBox\|SurfaceRuntime\|ClassLoader\|HARDWARE_TYPE_UNAVAILABLE" | \
        wc -l)
    if [[ "$errors" -eq 0 ]]; then
        green "    Logcat errors: 0"
    else
        yellow "    Logcat errors: $errors (run: adb logcat -d -s TEESimulator | grep -iE 'error|exception')"
    fi

    local throttle_events
    throttle_events=$(adb logcat -d -s TEESimulator 2>/dev/null | \
        grep -cE "RATE_LIMITED|CONCURRENT_LIMITED" || true)
    echo "    Rate limit events: $throttle_events"
}

print_summary() {
    echo ""
    bold "==> Build Summary"

    local variants=()
    case "$VARIANT" in
        release) variants=(Release) ;;
        debug)   variants=(Debug) ;;
        all)     variants=(Debug Release) ;;
    esac

    for v in "${variants[@]}"; do
        local zip
        zip=$(find_latest_zip "*-${v}.zip")
        if [[ -n "$zip" ]]; then
            local size
            size=$(du -h "$zip" | cut -f1)
            green "    $v: $(basename "$zip") ($size)"
        else
            red "    $v: ZIP not found"
        fi
    done
}

# --- Main ---
echo ""
bold "TEESimulator-RS package pipeline"
echo ""

[[ "$BUILD_RUST" == true ]] && build_rust

gradle_build
print_summary

if [[ "$DEPLOY" == true ]]; then
    local_variant="$VARIANT"
    [[ "$local_variant" == "all" ]] && local_variant="release"

    cap="${local_variant^}"
    zip=$(find_latest_zip "*-${cap}.zip")
    if [[ -z "$zip" ]]; then
        red "No $cap ZIP found to deploy"
        exit 1
    fi
    deploy_zip "$zip"
fi

[[ "$VERIFY" == true ]] && verify_device

echo ""
green "Done."
