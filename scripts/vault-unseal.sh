#!/usr/bin/env bash
# Submit one Vault unseal share without placing it in argv, environment,
# container configuration, a bind mount, or Docker logs.
set -euo pipefail
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION
docker_cmd=(docker --host unix:///run/docker.sock)

if [[ -t 0 ]]; then
  echo "FATAL: pipe one unseal share on stdin; interactive input is disabled" >&2
  exit 2
fi

"${docker_cmd[@]}" network inspect net-vault >/dev/null

# Vault 2.x's CLI requires a TTY for hidden input and does not implement `-`
# as an stdin sentinel. This disposable client reads only stdin, has no proxy
# path or redirect support, and emits only fixed non-secret status text.
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
  'dhi.io/python:3.12.13@sha256:eb7705c04a8240fa06d1f3d6e8adb61f72e5f0b2b457411a2840297cb5f997f3' \
  -c '
import json
import sys
import urllib.request

class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Vault unseal endpoint redirected")

raw = sys.stdin.buffer.read(8193)
if not raw or len(raw) > 8192:
    raise SystemExit("invalid unseal input length")
try:
    key = raw.strip().decode("ascii")
except UnicodeDecodeError:
    raise SystemExit("unseal input is not ASCII") from None
request = urllib.request.Request(
    "http://vault:8200/v1/sys/unseal",
    data=json.dumps({"key": key}).encode("ascii"),
    headers={"Content-Type": "application/json"},
    method="PUT",
)
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    RejectRedirects(),
)
with opener.open(request, timeout=10) as response:
    result = json.load(response)
if result.get("sealed", True):
    print("Vault accepted an unseal share and remains sealed.", file=sys.stderr)
else:
    print("Vault is unsealed.", file=sys.stderr)
'
