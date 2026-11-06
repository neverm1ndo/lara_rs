#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "usage: $0 <first-instance-id> <base-url> <developer-token-file> [second-instance-id]" >&2
    exit 2
fi

first_id=$1
base_url=${2%/}
token_file=$3
second_id=${4:-}

validate_id() {
    case "$1" in
        ''|*[!a-z0-9-]*|-*|*-) echo "invalid instance id: $1" >&2; exit 2 ;;
    esac
    if [ "${#1}" -gt 64 ]; then
        echo "instance id exceeds 64 characters" >&2
        exit 2
    fi
}
validate_id "$first_id"
if [ -n "$second_id" ]; then
    validate_id "$second_id"
    if [ "$first_id" = "$second_id" ]; then
        echo "the second instance must have a different id" >&2
        exit 2
    fi
fi
case "$base_url" in
    http://*|https://*) ;;
    *) echo "base URL must use http or https" >&2; exit 2 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
    echo "run the package smoke test as root" >&2
    exit 2
fi
for tool in curl jq dpkg-query; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "required tool is missing: $tool" >&2
        exit 2
    fi
done
if [ ! -r "$token_file" ]; then
    echo "developer token file is not readable" >&2
    exit 2
fi
token=$(tr -d '\r\n' < "$token_file")
case "$token" in
    ''|*[!A-Za-z0-9._-]*) echo "developer token is not a JWT token" >&2; exit 2 ;;
esac

umask 077
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/lara-release-c.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
printf 'header = "Authorization: Bearer %s"\n' "$token" > "$temporary_directory/auth.curl"
unset token

passed_count=0
failed_count=0
pass() { passed_count=$((passed_count + 1)); printf '[PASS] %s\n' "$1"; }
fail() { failed_count=$((failed_count + 1)); printf '[FAIL] %s\n' "$1" >&2; }
check_command() {
    description=$1
    shift
    if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}
request_status() {
    curl --silent --show-error --max-time 10 --output "$temporary_directory/response" \
        --write-out '%{http_code}' "$@"
}

if [ "$(dpkg-query -W -f='${Status}' lara-rs 2>/dev/null || true)" = 'install ok installed' ]; then
    pass "Lara package is installed"
else
    fail "Lara package is installed"
fi
check_command "installed CLI exposes configuration diagnostics" /usr/bin/lara instance --help
check_command "production configuration passes startup validation" /usr/bin/lara config validate

status=$(request_status "$base_url/openapi.json") || status=000
if [ "$status" = 200 ] && jq -e '
    .openapi == "3.1.0"
    and .paths["/server-instances/{instance_id}/configuration/tree"].get != null
    and .paths["/server-instances/{instance_id}/configuration/files"].put != null
    and .paths["/server-instances/{instance_id}/configuration/artifacts"].put != null
    and (.paths["/configuration/files"] == null)
' "$temporary_directory/response" >/dev/null 2>&1; then
    pass "published OpenAPI exposes Release C routes without legacy configuration routes"
else
    fail "published OpenAPI exposes Release C routes without legacy configuration routes"
fi

status=$(request_status "$base_url/configuration/tree") || status=000
if [ "$status" = 404 ]; then
    pass "legacy configuration route is absent"
else
    fail "legacy configuration route is absent (HTTP $status)"
fi

status=$(request_status "$base_url/server-instances/$first_id/configuration/tree") || status=000
if [ "$status" = 401 ]; then
    pass "configuration tree rejects a missing session"
else
    fail "configuration tree rejects a missing session (HTTP $status)"
fi

status=$(request_status --config "$temporary_directory/auth.curl" "$base_url/server-instances") || status=000
if [ "$status" = 200 ]; then
    cp "$temporary_directory/response" "$temporary_directory/manifest"
    pass "Developer manifest is available"
else
    fail "Developer manifest is available (HTTP $status)"
    printf '{}\n' > "$temporary_directory/manifest"
fi

check_instance() {
    instance_id=$1
    check_command "instance $instance_id passes read-only host verification" \
        /usr/bin/lara instance verify "$instance_id"
    check_command "instance $instance_id passes doctor" \
        /usr/bin/lara doctor --instance "$instance_id"
    if jq -e --arg id "$instance_id" '
        any(.instances[]?; .id == $id and
            (.features["lara.configuration.v1"].permissions | index("browse") != null))
    ' "$temporary_directory/manifest" >/dev/null 2>&1; then
        pass "manifest grants Developer configuration browse for $instance_id"
    else
        fail "manifest grants Developer configuration browse for $instance_id"
    fi
    status=$(request_status --config "$temporary_directory/auth.curl" \
        "$base_url/server-instances/$instance_id/configuration/tree") || status=000
    if [ "$status" = 200 ] && jq -e . "$temporary_directory/response" >/dev/null 2>&1; then
        pass "configuration tree is readable for $instance_id"
    else
        fail "configuration tree is readable for $instance_id (HTTP $status)"
    fi
}
check_instance "$first_id"
if [ -n "$second_id" ]; then check_instance "$second_id"; fi

printf '\nRelease C read-only smoke result: %s passed, %s failed.\n' \
    "$passed_count" "$failed_count"
if [ "$failed_count" -ne 0 ]; then exit 1; fi
