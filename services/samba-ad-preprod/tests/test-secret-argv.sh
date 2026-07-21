#!/bin/sh
set -eu

image=${1:-aigw-samba-ad:test}
scratch=$(mktemp -d)
token=$(basename "$scratch")
name="aigw-samba-secret-argv-$token"
owner_label=com.aigw.samba-test
test_secret='ArgvProbe-Only-7Qp2v9Mx4Za8'

unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH
context=$(docker context show)
endpoint=$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}')
case "$endpoint" in
    unix:///*) ;;
    *)
        printf '%s\n' 'Samba container tests require a local Unix-socket Docker context' >&2
        exit 1
        ;;
esac

docker_local() {
    docker --host "$endpoint" "$@"
}

remove_owned_container() {
    existing=$(docker_local ps -aq --filter "name=^/${name}$")
    [ -z "$existing" ] && return
    owner=$(docker_local inspect -f "{{index .Config.Labels \"$owner_label\"}}" "$existing")
    if [ "$owner" = "$token" ]; then
        docker_local rm -f "$existing" >/dev/null
    else
        printf '%s\n' "Refusing to remove unowned container $name" >&2
    fi
}

cleanup() {
    remove_owned_container || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT INT TERM

mkdir -p "$scratch/secrets"
printf '%s\n' "$test_secret" >"$scratch/secrets/admin"
chmod 0600 "$scratch/secrets/admin"

docker_local run -d --name "$name" --label "$owner_label=$token" \
    --cap-add SYS_ADMIN \
    --entrypoint /usr/local/sbin/samba-ad-secret-tool \
    -v "$scratch/secrets:/run/secrets:ro" \
    "$image" \
    domain-provision /run/secrets/admin \
    ARGV.TEST.INTERNAL ARGVTEST argvdc >/dev/null

while [ "$(docker_local inspect -f '{{.State.Running}}' "$name")" = true ]; do
    process_args=$(docker_local top "$name" -eo args 2>/dev/null || true)
    case "$process_args" in
        *"$test_secret"*)
            printf '%s\n' 'FAIL: Samba secret appeared in container process arguments' >&2
            exit 1
            ;;
    esac
    sleep 0.05
done

exit_code=$(docker_local inspect -f '{{.State.ExitCode}}' "$name")
[ "$exit_code" -eq 0 ] || {
    docker_local logs "$name" >&2
    exit "$exit_code"
}

# Also prevent the former direct CLI patterns from being reintroduced.
if grep -Eq -- '--adminpass="\$|--newpassword="\$|samba-tool user create "\$[^ ]+" "\$' \
    services/samba-ad-preprod/samba-ad-entrypoint; then
    printf '%s\n' 'FAIL: entrypoint passes a secret directly to samba-tool argv' >&2
    exit 1
fi

printf '%s\n' 'PASS: no Samba secret observed in process arguments'
