# Bring up local preprod

This guide brings the whole AI Gateway up on your own computer's Docker so
you can click around and test it. Run every command from the top folder of
this repository.

## The easy way — one command

```bash
scripts/preprod-up.sh
```

That is it. The script checks each thing you need, and if something is
missing it stops and tells you the exact command to fix it. When everything
is ready it builds the images and starts the whole stack. It asks for your
computer password once, near the start.

You need three things first. The script checks all three for you:

1. **Docker Desktop**, installed and running.
2. **Ansible.** If it is missing, the script tells you to run
   `pip3 install ansible-core`.
3. **Ansible collections** (three add-ons). The script installs them for
   you. If your machine is blocked from `galaxy.ansible.com`, see
   [Locked-down site: bring the collections yourself](#locked-down-site-bring-the-collections-yourself).
4. **A `dhi.io` login** so Docker can download the images. If you are not
   logged in, run `docker login dhi.io` once, or use the offline seed way
   below (which needs no login).

The build takes a while the first time. When it finishes, open
`https://chat.aigw.internal` in a browser. Every test login is written to
one private file: `compose/secrets/preprod-test-logins.md`.

## Locked-down site: bring the collections yourself

Some work networks block `galaxy.ansible.com`, so the script cannot download
the Ansible collections. Do this once from a machine that has internet,
using a copy of this repository:

```bash
ansible-galaxy collection download -r ansible/requirements.yml -p aigw-collections
```

That makes a folder named `aigw-collections` with the three collections and
a `requirements.yml`. Copy the whole folder to the work machine. Then point
the bring-up script at it:

```bash
scripts/preprod-up.sh --collections-dir /path/to/aigw-collections
```

The script installs the collections from that folder instead of the
internet. If the collections are already installed, the script skips this
step on its own.

## The offline seed way — no `dhi.io` login needed

If your machine cannot download from `dhi.io`, use a release folder that
already holds the two preprod files (the `.preprod.docker.tar.zst` archive
and its `.preprod.manifest.json`). Point the script at that folder:

```bash
scripts/preprod-up.sh --seed /path/to/your/release-folder
```

You never type a SHA-256. The script finds the two files and reads their
hashes for you.

## Skip the password prompt

The script asks for your computer (sudo) password to set up local names. To
avoid the prompt, keep the password in a private file and pass it:

```bash
scripts/preprod-up.sh --become-password-file "$HOME/.ssh/become"
```

See [Local preprod](../preprod.md) for how to make that file safely.

## Build a fresh release seed to test

The steps above deploy the current code. To build a brand-new offline seed
from source and test it in one command (needs a `dhi.io` login):

```bash
install -d -m 0700 /absolute/private/path/releases/2026-07-23-linux-arm64
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/arm64 \
  --archive /absolute/private/path/releases/2026-07-23-linux-arm64/aigw-2026-07-23-linux-arm64.docker.tar.zst \
  --manifest /absolute/private/path/releases/2026-07-23-linux-arm64/aigw-2026-07-23-linux-arm64.manifest.json \
  --test-preprod \
  --ask-become-pass
```

Use `linux/amd64` for an x86 target. The preprod pair is written next to the
production pair. This is the release-engineer path; for a plain test, use the
one-command way above.

## What success looks like

- The loader prints `LOADED <archive-sha256>`. A `SKIPPED` or `RELOADED`
  result is not release evidence.
- The run ends with `PREPROD_E2E_PASSED` and `SEEDED_PREPROD_E2E_PASSED`
  and exit status `0`.
- Every long-running container is healthy on the exact manifest image IDs.

You can then browse the stack at `aigw.internal` and re-check any time with
`python3 -I scripts/test-e2e-preprod.py`.

For browser testing, every login you need is in one generated private file:
`compose/secrets/preprod-test-logins.md` — the three test users, the
break-glass logins, and all service names. Never commit or share it.

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
