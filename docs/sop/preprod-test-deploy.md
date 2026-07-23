# Test a release in local Docker preprod

Use this SOP to prove a release works before it goes anywhere near
production. The test loads the exact offline seed into your local Docker,
deploys the whole stack with Ansible, and runs the acceptance checks.

The same command works on macOS or Windows Docker Desktop and on a rootful
Linux Docker Engine. Docker Desktop reads your own release files directly.
Rootful Linux first makes a private root-owned staging copy. You do not need
to know the difference; the tool picks the right path.

## Before you start

You need:

- this repository, with commands run from its root;
- a running local Docker (Docker Desktop, or a rootful Linux Engine);
- `ansible-playbook` and `ansible-vault` on `PATH`, with the collections
  from `ansible-galaxy collection install -r ansible/requirements.yml`;
- sudo rights for the bounded hosts block (and loopback aliases on macOS);
- the release archive and manifest pair for your platform — or internet
  access with a `dhi.io` login if you still need to build one.

Your release files must be owned by you, and no other user may be able to
write them. Normal copied permissions (mode `0644`) are fine. If a check
rejects a file or folder, the error names the exact fix command.

## Option A — test an existing seed

Replace the sample paths with your absolute release paths:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/aigw-2026-07-22-linux-arm64.preprod.docker.tar.zst \
  --manifest /absolute/private/path/aigw-2026-07-22-linux-arm64.preprod.manifest.json \
  --load-archive \
  --ask-become-pass
```

Use the `.preprod` pair, not the production pair.

`--ask-become-pass` prompts once per Ansible play: twice on Docker Desktop
(clean room, then deploy), and four times on a rootful Linux Docker host
(root staging and its cleanup add two). This is normal. To avoid every
prompt, keep a private sudo password file and pass
`--become-password-file /absolute/private/path` instead. See
[Local preprod](../preprod.md) for how to create that file safely.

## Option B — build a new seed, then test it

When no seed files exist yet, one command builds all four release files and
then runs the same full test. This build half needs internet access and a
`dhi.io` login:

```bash
install -d -m 0700 /absolute/private/path/releases/2026-07-22-linux-arm64
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/arm64 \
  --archive /absolute/private/path/releases/2026-07-22-linux-arm64/aigw-2026-07-22-linux-arm64.docker.tar.zst \
  --manifest /absolute/private/path/releases/2026-07-22-linux-arm64/aigw-2026-07-22-linux-arm64.manifest.json \
  --test-preprod \
  --ask-become-pass
```

Use `linux/amd64` for an x86 target. The preprod pair is written next to the
production pair automatically.

## What success looks like

- The loader prints `LOADED <archive-sha256>`. A `SKIPPED` or `RELOADED`
  result is not release evidence.
- The run ends with `PREPROD_E2E_PASSED` and `SEEDED_PREPROD_E2E_PASSED`
  and exit status `0`.
- Every long-running container is healthy on the exact manifest image IDs.

You can then browse the stack at `aigw.internal` and re-check any time with
`python3 -I scripts/test-e2e-preprod.py`.

## Clean up

The test is a clean-room flow: it removes only resources owned by the
`aigw-preprod` project before it loads, and the final teardown play proves
removal again after testing. Follow
[finish with exact manifest teardown](../preprod.md#finish-with-exact-manifest-teardown).

## If it fails

- Read the first `ERROR:` line. File custody errors name the failing path
  and a safe repair command.
- Do not run `docker compose up` by hand and do not edit the manifest.
- A failed run is evidence. Fix the cause and run the whole SOP again;
  partial reruns are not release evidence.

Details: [Local preprod](../preprod.md),
[Offline image releases](../offline-image-seed.md), and the
[image update workflow](../image-update-workflow.md).
