#!/bin/sh
set -eu

image=${1:-aigw-samba-ad:test}
name=aigw-samba-secret-argv-test
scratch=$(mktemp -d)
test_secret='ArgvProbe-Only-7Qp2v9Mx4Za8'

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

mkdir -p "$scratch/secrets"
printf '%s\n' "$test_secret" >"$scratch/secrets/admin"
chmod 0600 "$scratch/secrets/admin"

docker run -d --name "$name" \
    --cap-add SYS_ADMIN \
    --entrypoint /usr/local/sbin/samba-ad-secret-tool \
    -v "$scratch/secrets:/run/secrets:ro" \
    "$image" \
    domain-provision /run/secrets/admin \
    ARGV.TEST.INTERNAL ARGVTEST argvdc >/dev/null

while [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ]; do
    process_args=$(docker top "$name" -eo args 2>/dev/null || true)
    case "$process_args" in
        *"$test_secret"*)
            printf '%s\n' 'FAIL: Samba secret appeared in container process arguments' >&2
            exit 1
            ;;
    esac
    sleep 0.05
done

exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$exit_code" -eq 0 ] || {
    docker logs "$name" >&2
    exit "$exit_code"
}

# Also prevent the former direct CLI patterns from being reintroduced.
if grep -Eq -- '--adminpass="\$|--newpassword="\$|samba-tool user create "\$[^ ]+" "\$' \
    services/samba-ad-lab/samba-ad-entrypoint; then
    printf '%s\n' 'FAIL: entrypoint passes a secret directly to samba-tool argv' >&2
    exit 1
fi

printf '%s\n' 'PASS: no Samba secret observed in process arguments'
