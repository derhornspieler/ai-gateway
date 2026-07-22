# Add and manage a model

Use this SOP to add an Anthropic model without exposing it by mistake. This
workflow works only with an offline seed that includes the reviewed Anthropic
egress policy.

## Before you start

Make sure all of these are true:

- You are signed in to `https://admin.<domain>` as a current `aigw-admins`
  member.
- You signed in again within the last five minutes.
- The exact offline seed passed local PreProd.
- The provider is present in that seed's provider-policy receipt.
- You have a reviewed source reference for the model ID. Use a ticket or
  document ID. Do not enter a URL, hostname, CA file, route, or secret.

Today, `anthropic` is the only approved provider.

## Understand the states

| State | Can a key call it? | Is it in model discovery? |
| --- | --- | --- |
| Draft | No | No |
| Active and hidden | Yes, by exact name when allowed | No |
| Active and visible | Yes, when allowed | Yes |
| Retired | No | No |

Every state change is an append-only event. The service does not edit or
delete the old evidence.

## Add the model

1. Open the **Models** tab in the admin portal.
2. Enter a new gateway model name.
3. Select `anthropic`.
4. Enter the exact Anthropic model ID.
5. Enter the reviewed source reference and a short review note.
6. Select **Create hidden model**.

The result is a draft. No LiteLLM model is created yet.

## Activate and test it

1. Select **Activate**.
2. Wait for the success message.
3. Add the exact model name to one test project's allowed model list.
4. Mint or refresh a test key for that project.
5. Call the model by its exact name through `https://api.<domain>`.
6. Check that the request used Envoy and the approved provider path.
7. Check `/v1/models` with the test key. The hidden model must not be listed.

Activation records the event before it changes LiteLLM. If LiteLLM is down,
the portal reports that runtime reconciliation failed. The controller retries.
Its readiness check stays red until the runtime copy is exact.

## Set project limits for the model

Use this only when the project needs hard output limits:

1. Open **Identity & Access** in the admin portal.
2. Select the project group.
3. Check the model in **Allowed models**.
4. For that model, enter **Max output/request** and **Output/minute (UTC)**.
5. Make the request value no larger than the minute value.
6. Save the project policy. The portal updates the project's existing keys.

Both values must be positive whole numbers. Leave both blank when this model
does not need these two controls. A request above the first value is denied
before provider dispatch. Parallel requests share the fixed UTC-minute quota.
If Redis cannot make that shared reservation, the request fails closed with
HTTP 503 instead of using a local counter.

These controls limit output tokens. They do not create a rolling window,
monthly quota, per-user override, or money budget.

## Show or hide it

- Select **Show** to add an active model to filtered discovery.
- Select **Hide** to remove it from discovery.

Hiding a model does not remove an existing exact-name assignment. This lets an
API-only tool use a model that browser users should not see.

Public model discovery goes through the dev portal. It compares three sources:
the caller's LiteLLM list, the full LiteLLM deployment inventory, and the
controller's active-visible list. An ambiguous or malformed result returns an
error instead of a wider model list.

## Retire it

1. Remove the model from every Keycloak project policy.
2. Mint or refresh affected project keys.
3. Select **Retire** in the Models tab.
4. Confirm that exact-name calls fail.
5. Confirm that `/v1/models` does not list it.

Retirement is terminal. Create a new gateway model name if the provider model
must be replaced. The portal refuses retirement while any project still
assigns the model.

## Run the checks

From the repository root, run:

```bash
cd services/key-rotator
PYTHONPATH=. pytest -q
cd ../dev-portal
PYTHONPATH=. pytest -q
cd ../..
python3 -I -m unittest discover -v -s scripts/tests -p 'test_*.py'
bash scripts/validate-compose.sh
```

Release acceptance must clean, load, and deploy the exact PreProd seed through
Ansible. Replace both paths with the newly built `.preprod` pair:

```bash
python3 -I scripts/update-images.py test-preprod \
  --archive /absolute/private/path/aigw-YYYY-MM-DD.preprod.docker.tar.zst \
  --manifest /absolute/private/path/aigw-YYYY-MM-DD.preprod.manifest.json \
  --load-archive \
  --become-password-file "$HOME/.ssh/become"
```

That run calls the seed-only lifecycle test. While the same exact seed is
still running, you can repeat only that test with:

```bash
python3 -I scripts/test-preprod-model-lifecycle.py \
  --image-mode seed \
  --postgres-major 18
```

The full release pass must include all six `PREPROD_MODEL_*` lifecycle
markers listed in the [acceptance runbook](../test-runbook.md#step-2--clean-load-and-test-the-exact-preprod-pair).
Use only the private password-file path approved for your workstation. Never
commit that file. A source-mode Ansible run is useful during development, but
it is not offline-seed release evidence.

## If a check fails

- Do not use the native LiteLLM UI to repair a model. Its mutation routes are
  blocked at the admin edge.
- Do not add a database row by hand.
- Keep the model hidden or remove its project assignments.
- Fix the catalog or runtime problem, then let the controller reconcile.
- Roll back the whole offline release if the candidate cannot become healthy.

The previous release must restore its matching Envoy policy and runtime model
projection together. A rollback must never make a hidden or retired model
public.
