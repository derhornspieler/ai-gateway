# Build an offline seed release

Use this SOP on a machine that **has internet** to build the release files
that a machine **without internet** needs. One command builds everything.

The result is four files: a production pair and a preprod pair. Sites that
cannot reach `dhi.io` install from these instead of pulling images.

This is the operator checklist for step 1 of the
[image update workflow](../image-update-workflow.md).

## Before you start

You need:

- this repository on the build machine, with commands run from its root;
- **Docker running locally.** The builder refuses a remote Docker engine
  over TCP or SSH; only a local Unix socket is allowed;
- **a `dhi.io` login.** Run `docker login dhi.io` once. This is the machine
  that does the downloading, so it is the machine that needs the account;
- **about 8 GB of free disk** for the four files, plus room inside Docker
  for the images themselves;
- a private folder to write into.

Decide one thing before you start: **which chip the target machine uses.**

| Target | Use |
| --- | --- |
| Intel or AMD server (most VMs) | `linux/amd64` |
| Apple Silicon, ARM server | `linux/arm64` |

The release only works on the chip you pick. An `arm64` release cannot
install on an x86 VM. If you need both, build twice into two folders.

**Build from a clean, committed checkout.** The manifest records a hash of
the source that produced each custom image, and the later upgrade command
refuses a checkout with uncommitted changes. Building from edited files
gives you a release you cannot cleanly upgrade from.

## 1. Make a private folder

Put the date and the chip in the name so two releases never mix:

```bash
install -d -m 0700 /srv/ai-gateway-releases/2026-07-22-linux-amd64
```

Use any path you like, as long as it is private and absolute.

## 2. Build both pairs

```bash
python3 -I scripts/update-images.py prepare \
  --provider anthropic \
  --platform linux/amd64 \
  --archive /srv/ai-gateway-releases/2026-07-22-linux-amd64/aigw-2026-07-22-linux-amd64.docker.tar.zst \
  --manifest /srv/ai-gateway-releases/2026-07-22-linux-amd64/aigw-2026-07-22-linux-amd64.manifest.json
```

Anthropic is the only approved provider today. The name must exist in the
reviewed catalog; there is no option for a custom host or CA file.

This takes a while. It downloads every pinned image and builds the custom
ones with no network access during the build.

## 3. Check you got four files

```bash
ls -l /srv/ai-gateway-releases/2026-07-22-linux-amd64/
```

You should see exactly these:

```text
aigw-2026-07-22-linux-amd64.docker.tar.zst          production pair
aigw-2026-07-22-linux-amd64.manifest.json
aigw-2026-07-22-linux-amd64.preprod.docker.tar.zst  preprod pair
aigw-2026-07-22-linux-amd64.preprod.manifest.json
```

One build makes both pairs. The production archive holds no test-only
images, so **never send the `.preprod` pair to a production VM.**

Each file is written mode `0600`. The manifest is generated proof of what
is inside the archive. **Do not edit it.** Editing it breaks the release.

## 4. Test it before you trust it

A release you have not tested is not a release. Load it into local preprod
and run the full checks:

```bash
scripts/preprod-up.sh --seed /srv/ai-gateway-releases/2026-07-22-linux-amd64
```

You never type a SHA-256; the script reads the hashes from the files. Full
steps: [preprod test deploy SOP](preprod-test-deploy.md).

To build and test in one command, add `--test-preprod` to step 2.

**Test on the same chip you built for.** You can build an `amd64` release
on an Apple Silicon Mac, but you cannot honestly test it there — it would
run under emulation, which is not what the target machine does. Build-only
is fine; just do not call an emulated run a passed test.

## 5. Record the release

Keep a written note with the files. Record:

- the source commit and the build date;
- the chip and the provider list;
- all four filenames and their SHA-256 values:

```bash
# macOS
shasum -a 256 /srv/ai-gateway-releases/2026-07-22-linux-amd64/*
# Linux
sha256sum /srv/ai-gateway-releases/2026-07-22-linux-amd64/*
```

This is for your records only. No later command asks you to type a hash.

After the preprod test passes, push the reviewed commit to `main` so the
**Repository and release container security** job scans the images. Do not
ship a release that has not been scanned.

## What success looks like

- The command exits `0` and all four files exist.
- The preprod test ends with `PREPROD_E2E_PASSED` and
  `SEEDED_PREPROD_E2E_PASSED`.
- Your written record holds the commit, chip, filenames, and hashes.

## If it fails

- **A pull is refused.** Run `docker login dhi.io` and try again.
- **Docker is remote.** The builder only accepts a local Unix socket. Run
  it on the machine where Docker actually runs.
- **Out of disk.** Free space and start over; a partial build is not a
  release.
- Do not edit a manifest and do not reuse a name. Fix the cause, use a new
  dated filename, and build again.

## Move the files to the offline site

Copy the whole folder. The two pairs travel together with their manifests.

| Where it is going | What to use |
| --- | --- |
| Local preprod test | [preprod test deploy SOP](preprod-test-deploy.md) |
| A brand-new production VM | [production new deploy SOP](production-new-deploy.md) |
| An existing production VM | [production image upgrade SOP](production-image-upgrade.md) |

Details: [offline image releases](../offline-image-seed.md) and the
[image update workflow](../image-update-workflow.md).
