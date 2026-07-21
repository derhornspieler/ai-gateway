#!/usr/bin/env bash
# Enable and verify Vault's HMAC-protected file audit device.
# Pipe the one-time Vault root token on stdin. The token never enters argv,
# the environment, a bind mount, or Docker logs.
set -euo pipefail
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
docker_cmd=(docker --host unix:///run/docker.sock)

if [[ -t 0 ]]; then
  echo "FATAL: pipe the Vault root token on stdin; interactive input is disabled" >&2
  exit 2
fi

"${docker_cmd[@]}" network inspect net-vault >/dev/null

exec "${docker_cmd[@]}" run --rm -i \
  --pull never \
  --network net-vault \
  --user 65532:65532 \
  --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=0700 \
  --pids-limit 64 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --log-driver none \
  --entrypoint /usr/bin/python3 \
  'dhi.io/python:3.14.6@sha256:c82da5a1a30a6214f45c42def5b6f5b85981c7dc7a1802015a6ebf264675436d' \
  -c '
import json
import re
import sys
import urllib.error
import urllib.request

class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Vault audit endpoint redirected")

raw = sys.stdin.buffer.read(8193)
if not raw or len(raw) > 8192:
    raise SystemExit("invalid Vault root-token input length")
try:
    token = raw.strip().decode("ascii")
except UnicodeDecodeError:
    raise SystemExit("Vault root-token input is not ASCII") from None
if re.fullmatch(r"[A-Za-z0-9._-]{16,8192}", token) is None:
    raise SystemExit("Vault root-token input has an invalid shape")

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    RejectRedirects(),
)

def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode("ascii")
    request = urllib.request.Request(
        "http://vault:8200" + path,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Token": token,
        },
        method=method,
    )
    try:
        with opener.open(request, timeout=10) as response:
            payload = response.read(1048577)
            if len(payload) > 1048576:
                raise RuntimeError("Vault audit response was too large")
            return response.status, json.loads(payload or b"{}")
    except urllib.error.HTTPError as error:
        error.read(1048577)
        return error.code, {}

desired = {
    "file_path": "/vault/logs/audit.log",
    "format": "json",
    "hmac_accessor": "true",
    "log_raw": "false",
    "mode": "0640",
}

status, devices = call("GET", "/v1/sys/audit")
if status != 200 or not isinstance(devices, dict):
    raise SystemExit("Vault audit-device inspection failed")
if "file/" not in devices:
    status, _ = call(
        "PUT",
        "/v1/sys/audit/file",
        {"type": "file", "options": desired},
    )
    if status not in (200, 204):
        raise SystemExit("Vault file audit-device setup failed")

status, devices = call("GET", "/v1/sys/audit")
device = devices.get("file/") if isinstance(devices, dict) else None
options = device.get("options") if isinstance(device, dict) else None
valid = (
    status == 200
    and isinstance(device, dict)
    and device.get("type") == "file"
    and isinstance(options, dict)
    and all(str(options.get(key, "")).lower() == value for key, value in desired.items())
)
if not valid:
    raise SystemExit("Vault file audit-device configuration did not verify")

print("Vault file audit device is enabled and verified.", file=sys.stderr)
'
