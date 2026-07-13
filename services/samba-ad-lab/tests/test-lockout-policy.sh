#!/bin/sh
set -eu

image=${1:-aigw-samba-ad:test}
name=aigw-samba-lockout-policy-test
prefix=aigw_samba_lockout_policy_test
scratch=$(mktemp -d)

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm \
        "${prefix}_config" "${prefix}_state" "${prefix}_public" \
        >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT INT TERM
cleanup
mkdir -p "$scratch/secrets"
printf '%s\n' 'LockAdm-7Qp2v9Mx4Za8' >"$scratch/secrets/admin"
printf '%s\n' 'LockBind-3Ks8w2Nv6Yt4' >"$scratch/secrets/bind"
chmod 0600 "$scratch/secrets/admin" "$scratch/secrets/bind"
for suffix in config state public; do
    docker volume create "${prefix}_${suffix}" >/dev/null
done

docker run -d --name "$name" --hostname samba-ad \
    --read-only --security-opt no-new-privileges:true --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add NET_BIND_SERVICE \
    --cap-add SETGID --cap-add SETUID --cap-add SYS_ADMIN \
    --dns 127.0.0.1 --pids-limit 2048 \
    --tmpfs /run --tmpfs /tmp --tmpfs /var/cache/samba --tmpfs /var/log/samba \
    -e SAMBA_REALM=LOCKOUT.AIGW.INTERNAL -e SAMBA_DOMAIN=LOCKOUT \
    -e SAMBA_HOSTNAME=samba-ad -e SAMBA_BIND_USER=svc-keycloak-ldap \
    -v "$scratch/secrets/admin:/run/secrets/samba_ad_admin_password:ro" \
    -v "$scratch/secrets/bind:/run/secrets/samba_ad_bind_password:ro" \
    -v "${prefix}_config:/etc/samba" \
    -v "${prefix}_state:/var/lib/samba" \
    -v "${prefix}_public:/var/lib/samba-public" \
    "$image" >/dev/null

wait_healthy() {
    attempts=0
    while [ "$attempts" -lt 60 ]; do
        state=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name")
        [ "$state" = healthy ] && return 0
        [ "$state" = unhealthy ] || [ "$state" = exited ] && break
        attempts=$((attempts + 1))
        sleep 2
    done
    docker logs "$name" >&2
    printf '%s\n' "Samba did not become healthy (state=$state)" >&2
    return 1
}

assert_policy() {
    settings=$(docker exec "$name" samba-tool domain passwordsettings show)
    printf '%s\n' "$settings" | grep -Eq '^Account lockout threshold \(attempts\):[[:space:]]+5$'
    printf '%s\n' "$settings" | grep -Eq '^Account lockout duration \(mins\):[[:space:]]+15$'
    printf '%s\n' "$settings" | grep -Eq '^Reset account lockout after \(mins\):[[:space:]]+15$'
}

wait_healthy
assert_policy

# Prove a restart repairs persisted drift instead of trusting bootstrap state.
docker exec "$name" samba-tool domain passwordsettings set \
    --account-lockout-threshold=0 --quiet >/dev/null
docker restart "$name" >/dev/null
wait_healthy
assert_policy

printf '%s\n' 'PASS: Samba lockout policy is bounded, healthy, and restart-persistent'
