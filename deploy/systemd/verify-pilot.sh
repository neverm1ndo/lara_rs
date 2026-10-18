#!/bin/sh
set -eu

instance_id=${1:-}
case "$instance_id" in
    ''|*[!a-z0-9-]*|-*|*-)
        echo "usage: $0 <lowercase-instance-id>" >&2
        exit 2
        ;;
esac

unit="lara-game@${instance_id}.service"

if ! systemctl is-enabled --quiet "$unit"; then
    echo "$unit is not enabled" >&2
    exit 1
fi

if ! systemctl is-active --quiet "$unit"; then
    echo "$unit is not active" >&2
    systemctl --no-pager --full status "$unit" || true
    exit 1
fi

active_state=$(systemctl show "$unit" --property=ActiveState --value)
sub_state=$(systemctl show "$unit" --property=SubState --value)
main_pid=$(systemctl show "$unit" --property=MainPID --value)
invocation_id=$(systemctl show "$unit" --property=InvocationID --value)
control_group=$(systemctl show "$unit" --property=ControlGroup --value)

if [ "$active_state" != "active" ] || [ "$sub_state" != "running" ]; then
    echo "$unit has unexpected state: $active_state/$sub_state" >&2
    exit 1
fi

case "$main_pid" in
    ''|*[!0-9]*|0)
        echo "$unit has no valid MainPID" >&2
        exit 1
        ;;
esac

if [ -z "$invocation_id" ]; then
    echo "$unit has no InvocationID" >&2
    exit 1
fi

if [ -z "$control_group" ]; then
    echo "$unit has no ControlGroup" >&2
    exit 1
fi

if [ ! -r "/proc/$main_pid/cgroup" ] || \
   ! grep -F -- "$control_group" "/proc/$main_pid/cgroup" >/dev/null; then
    echo "MainPID $main_pid does not belong to $control_group" >&2
    exit 1
fi

echo "$unit passed the Release A pilot checks"
systemctl show "$unit" \
    --property=ActiveState \
    --property=SubState \
    --property=Result \
    --property=MainPID \
    --property=NRestarts \
    --property=InvocationID \
    --property=ExecMainCode \
    --property=ExecMainStatus \
    --property=ControlGroup \
    --property=FragmentPath
