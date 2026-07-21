#!/bin/sh
set -eu

image=${1:-aigw-samba-ad:test}
scratch=$(mktemp -d)
token=$(basename "$scratch")
name="aigw-samba-lockout-$token"
prefix="aigw_samba_lockout_$token"
owner_label=com.aigw.samba-test

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

remove_owned_volume() {
    volume=$1
    docker_local volume inspect "$volume" >/dev/null 2>&1 || return
    owner=$(docker_local volume inspect -f "{{index .Labels \"$owner_label\"}}" "$volume")
    if [ "$owner" = "$token" ]; then
        docker_local volume rm "$volume" >/dev/null
    else
        printf '%s\n' "Refusing to remove unowned volume $volume" >&2
    fi
}

cleanup() {
    remove_owned_container || true
    for suffix in config state; do
        remove_owned_volume "${prefix}_${suffix}" || true
    done
    rm -rf -- "$scratch"
}
trap cleanup EXIT INT TERM
mkdir -p "$scratch/secrets"
printf '%s\n' 'LockAdm-7Qp2v9Mx4Za8' >"$scratch/secrets/admin"
printf '%s\n' 'LockBind-3Ks8w2Nv6Yt4' >"$scratch/secrets/bind"
chmod 0600 "$scratch/secrets/admin" "$scratch/secrets/bind"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
    -subj /CN=AIGW-Samba-Test-Root \
    -keyout "$scratch/secrets/root.key" \
    -out "$scratch/secrets/root.pem" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -subj /CN=samba-ad.lockout.aigw.internal \
    -keyout "$scratch/secrets/tls.key" \
    -out "$scratch/secrets/tls.csr" >/dev/null 2>&1
printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:samba-ad.lockout.aigw.internal' \
    >"$scratch/secrets/tls.ext"
openssl x509 -req -sha256 -days 2 \
    -in "$scratch/secrets/tls.csr" \
    -CA "$scratch/secrets/root.pem" \
    -CAkey "$scratch/secrets/root.key" \
    -CAcreateserial \
    -extfile "$scratch/secrets/tls.ext" \
    -out "$scratch/secrets/tls.crt" >/dev/null 2>&1
chmod 0600 "$scratch/secrets/tls.key"
for suffix in config state; do
    docker_local volume create \
        --label "$owner_label=$token" "${prefix}_${suffix}" >/dev/null
done

docker_local run -d --name "$name" --label "$owner_label=$token" --hostname samba-ad \
    --read-only --security-opt no-new-privileges:true --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add NET_BIND_SERVICE \
    --cap-add SETGID --cap-add SETUID --cap-add SYS_ADMIN \
    --dns 127.0.0.1 --pids-limit 2048 \
    --tmpfs /run --tmpfs /tmp --tmpfs /var/cache/samba --tmpfs /var/log/samba \
    -e SAMBA_REALM=LOCKOUT.AIGW.INTERNAL -e SAMBA_DOMAIN=LOCKOUT \
    -e SAMBA_HOSTNAME=samba-ad -e SAMBA_BIND_USER=svc-keycloak-ldap \
    -e SAMBA_LDAPS_FQDN=samba-ad.lockout.aigw.internal \
    -v "$scratch/secrets/admin:/run/secrets/samba_ad_admin_password:ro" \
    -v "$scratch/secrets/bind:/run/secrets/samba_ad_bind_password:ro" \
    -v "$scratch/secrets/tls.crt:/run/secrets/samba_ad_tls_cert:ro" \
    -v "$scratch/secrets/tls.key:/run/secrets/samba_ad_tls_key:ro" \
    -v "$scratch/secrets/root.pem:/run/secrets/preprod_root_ca:ro" \
    -v "${prefix}_config:/etc/samba" \
    -v "${prefix}_state:/var/lib/samba" \
    "$image" >/dev/null

wait_healthy() {
    attempts=0
    while [ "$attempts" -lt 60 ]; do
        state=$(docker_local inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name")
        [ "$state" = healthy ] && return 0
        [ "$state" = unhealthy ] || [ "$state" = exited ] && break
        attempts=$((attempts + 1))
        sleep 2
    done
    docker_local logs "$name" >&2
    printf '%s\n' "Samba did not become healthy (state=$state)" >&2
    return 1
}

assert_policy() {
    settings=$(docker_local exec "$name" samba-tool domain passwordsettings show)
    printf '%s\n' "$settings" | grep -Eq '^Account lockout threshold \(attempts\):[[:space:]]+5$'
    printf '%s\n' "$settings" | grep -Eq '^Account lockout duration \(mins\):[[:space:]]+15$'
    printf '%s\n' "$settings" | grep -Eq '^Reset account lockout after \(mins\):[[:space:]]+15$'
}

wait_healthy
assert_policy

# Prove a restart repairs persisted drift instead of trusting bootstrap state.
docker_local exec "$name" samba-tool domain passwordsettings set \
    --account-lockout-threshold=0 --quiet >/dev/null
docker_local restart "$name" >/dev/null
wait_healthy
assert_policy

printf '%s\n' 'PASS: Samba lockout policy is bounded, healthy, and restart-persistent'
