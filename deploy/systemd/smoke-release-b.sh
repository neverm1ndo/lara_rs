#!/bin/sh
set -eu

instance_id=${1:-}
unit=${2:-}

case "$instance_id" in
    ''|*[!a-z0-9-]*|-*|*-)
        echo "usage: $0 <lowercase-instance-id> [systemd-unit]" >&2
        exit 2
        ;;
esac

if [ "${#instance_id}" -gt 64 ]; then
    echo "instance id must not exceed 64 characters" >&2
    exit 2
fi

if [ -z "$unit" ]; then
    unit="lara-game@${instance_id}.service"
fi
case "$unit" in
    -*|*[!A-Za-z0-9_.@:-]*)
        echo "invalid systemd unit: $unit" >&2
        exit 2
        ;;
esac
case "$unit" in
    *.service) ;;
    *)
        echo "systemd unit must end with .service" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "Release B smoke test must run as root (use sudo)" >&2
    exit 2
fi

passed_count=0
failed_count=0

record_pass() {
    passed_count=$((passed_count + 1))
    printf '[PASS] %s\n' "$1"
}

record_fail() {
    failed_count=$((failed_count + 1))
    printf '[FAIL] %s\n' "$1" >&2
}

run_quiet_check() {
    description=$1
    shift
    if "$@" >/dev/null 2>&1; then
        record_pass "$description"
    else
        record_fail "$description"
    fi
}

find_systemd_unit() {
    unit_name=$1
    for directory in /usr/lib/systemd/system /lib/systemd/system; do
        if [ -f "$directory/$unit_name" ]; then
            printf '%s\n' "$directory/$unit_name"
            return 0
        fi
    done
    return 1
}

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/lara-release-b.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

lara_service_file=$(find_systemd_unit lara-rs.service || true)
game_template_file=$(find_systemd_unit lara-game@.service || true)

run_quiet_check "canonical Lara executable is installed" test -x /usr/bin/lara
run_quiet_check "Lara CLI reports its version" /usr/bin/lara --version
run_quiet_check "Lara CLI exposes its command tree" /usr/bin/lara --help

if /usr/bin/lara completions bash >"$temporary_directory/lara.bash" 2>/dev/null &&
   grep -q 'doctor' "$temporary_directory/lara.bash" &&
   grep -q 'render-systemd' "$temporary_directory/lara.bash"; then
    record_pass "generated completion contains Release B commands"
else
    record_fail "generated completion contains Release B commands"
fi

if [ -n "$lara_service_file" ]; then
    record_pass "lara-rs.service is installed"
else
    record_fail "lara-rs.service is installed"
fi
if [ -n "$game_template_file" ]; then
    record_pass "lara-game@.service is installed"
else
    record_fail "lara-game@.service is installed"
fi
run_quiet_check "least-privilege polkit rule is installed" \
    test -r /usr/share/polkit-1/rules.d/49-lara-rs.rules

if [ -n "$lara_service_file" ] && [ -n "$game_template_file" ]; then
    run_quiet_check "packaged systemd units pass verification" \
        systemd-analyze verify "$lara_service_file" "$game_template_file"
fi

run_quiet_check "production configuration passes daemon validation" \
    /usr/bin/lara config validate
run_quiet_check "effective instance registry can be serialized" \
    /usr/bin/lara instance list --output json

printf '\nRunning detailed instance verification for %s...\n' "$instance_id"
if /usr/bin/lara instance verify "$instance_id"; then
    record_pass "instance host definition matches the registry"
else
    record_fail "instance host definition matches the registry"
fi

run_quiet_check "effective instance unit passes systemd verification" \
    systemd-analyze verify "$unit"

if systemctl show "$unit" \
    --property=LoadState \
    --property=ActiveState \
    --property=SubState \
    --property=Result \
    --property=MainPID \
    --property=NRestarts \
    --property=InvocationID \
    --property=ControlGroup \
    --property=FragmentPath >"$temporary_directory/instance-unit" 2>/dev/null &&
   grep -Fx 'LoadState=loaded' "$temporary_directory/instance-unit" >/dev/null; then
    record_pass "instance unit is loaded by systemd"
    cat "$temporary_directory/instance-unit"
else
    record_fail "instance unit is loaded by systemd"
fi

printf '\nRunning full deployment diagnostics...\n'
if /usr/bin/lara doctor --instance "$instance_id"; then
    record_pass "Lara doctor found no blocking deployment problems"
else
    record_fail "Lara doctor found no blocking deployment problems"
fi

if ! command -v pkcheck >/dev/null 2>&1; then
    record_fail "pkcheck is available for effective policy verification"
else
    record_pass "pkcheck is available for effective policy verification"
    lara_pid=$(systemctl show lara-rs.service --property=MainPID --value 2>/dev/null || true)
    case "$lara_pid" in
        ''|*[!0-9]*|0)
            record_fail "lara-rs.service has a running main process for polkit verification"
            ;;
        *)
            if [ ! -r "/proc/$lara_pid/stat" ] || [ ! -r "/proc/$lara_pid/status" ]; then
                record_fail "Lara process identity is readable from /proc"
            else
                stat_line=$(sed -n '1p' "/proc/$lara_pid/stat")
                stat_fields=${stat_line##*) }
                start_time=$(printf '%s\n' "$stat_fields" | awk '{print $20}')
                process_uid=$(awk '/^Uid:/ { print $2; exit }' "/proc/$lara_pid/status")
                lara_uid=$(id -u lara 2>/dev/null || true)

                if [ -n "$start_time" ] && [ -n "$process_uid" ] &&
                   [ "$process_uid" = "$lara_uid" ]; then
                    record_pass "lara-rs.service runs as the dedicated lara account"
                    process_subject="$lara_pid,$start_time,$process_uid"

                    if pkcheck \
                        --action-id org.freedesktop.systemd1.manage-units \
                        --process "$process_subject" \
                        --detail unit "$unit" \
                        --detail verb start >/dev/null 2>&1; then
                        record_pass "polkit permits Lara to start the managed instance unit"
                    else
                        record_fail "polkit permits Lara to start the managed instance unit"
                    fi

                    if pkcheck \
                        --action-id org.freedesktop.systemd1.manage-units \
                        --process "$process_subject" \
                        --detail unit ssh.service \
                        --detail verb start >/dev/null 2>&1; then
                        record_fail "polkit denies Lara access to an unrelated unit"
                    else
                        denial_status=$?
                        if [ "$denial_status" -eq 1 ]; then
                            record_pass "polkit denies Lara access to an unrelated unit"
                        else
                            record_fail "polkit check for an unrelated unit completed correctly"
                        fi
                    fi

                    if pkcheck \
                        --action-id org.freedesktop.systemd1.manage-units \
                        --process "$process_subject" \
                        --detail unit "$unit" \
                        --detail verb enable >/dev/null 2>&1; then
                        record_fail "polkit denies Lara an unsupported lifecycle verb"
                    else
                        denial_status=$?
                        if [ "$denial_status" -eq 1 ]; then
                            record_pass "polkit denies Lara an unsupported lifecycle verb"
                        else
                            record_fail "polkit check for an unsupported verb completed correctly"
                        fi
                    fi
                else
                    record_fail "lara-rs.service runs as the dedicated lara account"
                fi
            fi
            ;;
    esac
fi

printf '\nRelease B smoke result: %s passed, %s failed.\n' \
    "$passed_count" "$failed_count"

if [ "$failed_count" -ne 0 ]; then
    exit 1
fi
