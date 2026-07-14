#!/usr/bin/env bash
# One authoritative Compose selector for every deployed operator script.
set -euo pipefail
# Keep DOCKER_CONFIG: root's reviewed registry-auth config may carry the DHI
# pull credential. Endpoint selection is pinned independently; only inherited
# context/host/TLS selectors are discarded.
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION COMPOSE_FILE COMPOSE_PROFILES
STACK_DIR="${STACK_DIR:-/opt/ai-gateway}"
PROJECT="${COMPOSE_PROJECT_NAME:-ai-gateway}"
[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || { echo "unsafe Compose project name" >&2; exit 2; }
[[ -f "$STACK_DIR/.env" && -f "$STACK_DIR/docker-compose.yml" && -f "$STACK_DIR/docker-compose.dns.yml" ]] || { echo "deployed Compose files are missing" >&2; exit 1; }
profile="$(grep -E '^DEPLOYMENT_PROFILE=' "$STACK_DIR/.env" | tail -n 1 | cut -d= -f2- || true)"
platform_dns="$(grep -E '^PLATFORM_AUTHORITATIVE_DNS_ENABLED=' "$STACK_DIR/.env" | tail -n 1 | cut -d= -f2- || true)"
vault_ui_selector_count="$(grep -Ec '^VAULT_UI_ENABLED=' "$STACK_DIR/.env" || true)"
[[ "$vault_ui_selector_count" == 1 ]] || { echo "expected exactly one VAULT_UI_ENABLED selector" >&2; exit 2; }
vault_ui="$(grep -E '^VAULT_UI_ENABLED=' "$STACK_DIR/.env" | cut -d= -f2-)"
identity_ldap_selector_count="$(grep -Ec '^IDENTITY_LDAP_ENABLED=' "$STACK_DIR/.env" || true)"
[[ "$identity_ldap_selector_count" == 1 ]] || { echo "expected exactly one IDENTITY_LDAP_ENABLED selector" >&2; exit 2; }
identity_ldap="$(grep -E '^IDENTITY_LDAP_ENABLED=' "$STACK_DIR/.env" | cut -d= -f2-)"
[[ "$platform_dns" == true || "$platform_dns" == false ]] || { echo "invalid platform DNS selector" >&2; exit 2; }
[[ "$vault_ui" == true || "$vault_ui" == false ]] || { echo "invalid Vault UI selector" >&2; exit 2; }
[[ "$identity_ldap" == true || "$identity_ldap" == false ]] || { echo "invalid external identity selector" >&2; exit 2; }
# Process environment has precedence over --env-file interpolation. Pin the
# selector to the single reviewed file value so a caller cannot split the
# service profile from Traefik's runtime router selector.
export VAULT_UI_ENABLED="$vault_ui"

if [[ "$vault_ui" == false ]]; then
  caller_args=("$@")
  for ((index = 0; index < ${#caller_args[@]}; index++)); do
    argument="${caller_args[index]}"
    if [[ "$argument" == --profile=vault-ui || "$argument" == '--profile=*' ]] ||
       { [[ "$argument" == --profile ]] &&
         (( index + 1 < ${#caller_args[@]} )) &&
         [[ "${caller_args[index + 1]}" == vault-ui ||
            "${caller_args[index + 1]}" == '*' ]]; }; then
      echo "Vault UI profile is disabled by the deployed selector" >&2
      exit 2
    fi
  done

  # Find the caller's Compose subcommand without treating values belonging to
  # supported global options as commands. Unrelated profiles remain allowed.
  subcommand=""
  subcommand_index=-1
  for ((index = 0; index < ${#caller_args[@]}; index++)); do
    argument="${caller_args[index]}"
    case "$argument" in
      -f|--file|--env-file|--ansi|--parallel|--profile|--progress|-p|--project-name|--project-directory)
        ((index += 1))
        ;;
      --*=*|-*)
        ;;
      *)
        subcommand="$argument"
        subcommand_index="$index"
        break
        ;;
    esac
  done

  is_disabled_service() {
    [[ "$1" == oauth2-proxy-vault || "$1" == vault-ui-proxy ]]
  }

  reject_disabled_service() {
    echo "Vault browser service '$1' is disabled by the deployed selector" >&2
    exit 2
  }

  case "$subcommand" in
    run)
      # Compose adds value-taking run options over time. Scan every caller
      # token after `run` so an unrecognized option cannot hide an explicitly
      # targeted disabled service and create a one-off container.
      for ((index = subcommand_index + 1; index < ${#caller_args[@]}; index++)); do
        argument="${caller_args[index]}"
        if is_disabled_service "$argument"; then
          reject_disabled_service "$argument"
        fi
      done
      ;;
    scale)
      for ((index = subcommand_index + 1; index < ${#caller_args[@]}; index++)); do
        argument="${caller_args[index]}"
        if is_disabled_service "${argument%%=*}"; then
          reject_disabled_service "${argument%%=*}"
        fi
      done
      ;;
    create|restart|start|unpause|up|watch)
      for ((index = subcommand_index + 1; index < ${#caller_args[@]}; index++)); do
        argument="${caller_args[index]}"
        if is_disabled_service "$argument"; then
          reject_disabled_service "$argument"
        fi
        if [[ "$argument" == --scale=* ]]; then
          scaled_service="${argument#--scale=}"
          scaled_service="${scaled_service%%=*}"
          if is_disabled_service "$scaled_service"; then
            reject_disabled_service "$scaled_service"
          fi
        elif [[ "$argument" == --scale ]] &&
             (( index + 1 < ${#caller_args[@]} )); then
          scaled_service="${caller_args[index + 1]%%=*}"
          if is_disabled_service "$scaled_service"; then
            reject_disabled_service "$scaled_service"
          fi
        fi
      done
      ;;
  esac
fi
compose=(docker --host unix:///run/docker.sock compose --project-name "$PROJECT" --env-file "$STACK_DIR/.env" -f "$STACK_DIR/docker-compose.yml" -f "$STACK_DIR/docker-compose.dns.yml")
if [[ "$platform_dns" == true ]]; then
  [[ -f "$STACK_DIR/docker-compose.platform-dns.yml" ]] || { echo "platform DNS overlay is missing" >&2; exit 1; }
  compose+=(-f "$STACK_DIR/docker-compose.platform-dns.yml")
fi
if [[ "$profile" == rocky9-lab ]]; then
  [[ -f "$STACK_DIR/docker-compose.lab.yml" ]] || { echo "lab identity overlay is missing" >&2; exit 1; }
  compose+=(-f "$STACK_DIR/docker-compose.lab.yml" --profile lab-ad)
fi
if [[ "$identity_ldap" == true ]]; then
  [[ "$profile" != rocky9-lab ]] || { echo "external identity overlay conflicts with the lab profile" >&2; exit 2; }
  [[ -f "$STACK_DIR/docker-compose.identity-ldap.yml" ]] || { echo "external identity overlay is missing" >&2; exit 1; }
  compose+=(-f "$STACK_DIR/docker-compose.identity-ldap.yml")
fi
if [[ "$vault_ui" == true ]]; then
  compose+=(--profile vault-ui)
fi
exec "${compose[@]}" "$@"
