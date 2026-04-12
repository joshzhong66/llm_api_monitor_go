#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LDAP_ENV_FILE="${LDAP_ENV_FILE:-${SCRIPT_DIR}/.ldap_env}"

load_env_file() {
  if [[ -f "${LDAP_ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${LDAP_ENV_FILE}"
    set +a
  fi
}

load_env_file

LDAP_URL="${LDAP_URL:-ldap://10.20.3.85:389}"
LDAP_BIND_DN="${LDAP_BIND_DN:-}"
LDAP_BIND_PASSWORD="${LDAP_BIND_PASSWORD:-}"
LDAP_BASE_DN="${LDAP_BASE_DN:-DC=xmfunny,DC=com}"

usage() {
  cat <<'EOF'
Usage:
  scripts/ldap_query.sh user <value>
  scripts/ldap_query.sh dn <distinguishedName>
  scripts/ldap_query.sh host <value>
  scripts/ldap_query.sh raw <ldap-filter>

Env:
  LDAP_ENV_FILE
  LDAP_URL
  LDAP_BIND_DN
  LDAP_BIND_PASSWORD
  LDAP_BASE_DN

Examples:
  cp scripts/ldap_env.example scripts/.ldap_env
  vi scripts/.ldap_env
  scripts/ldap_query.sh user 'it监控'
  scripts/ldap_query.sh dn 'CN=it监控,OU=Public,DC=xmfunny,DC=com'
  scripts/ldap_query.sh host 'pc-001'
EOF
}

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

prompt_password_if_needed() {
  if [[ -z "${LDAP_BIND_PASSWORD}" ]]; then
    read -r -s -p "LDAP password: " LDAP_BIND_PASSWORD
    echo
  fi
}

normalize_output() {
  perl -MMIME::Base64 -ne '
    if (/^([^:]+)::\s*(\S+)\s*$/) {
      my ($k, $v) = ($1, $2);
      print "$k: " . decode_base64($v) . "\n";
    } else {
      print;
    }
  '
}

run_search() {
  local filter="$1"
  shift
  ldapsearch -LLL -x -H "${LDAP_URL}" \
    -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PASSWORD}" \
    -b "${LDAP_BASE_DN}" \
    "${filter}" \
    "$@" | normalize_output
}

user_filter() {
  local value="$1"
  printf '(&(objectClass=user)(objectCategory=person)(|(sAMAccountName=%s)(userPrincipalName=%s)(cn=%s)(name=%s)(displayName=%s)))' \
    "$value" "$value" "$value" "$value" "$value"
}

dn_filter() {
  local value="$1"
  printf '(&(objectClass=*)(distinguishedName=%s))' "$value"
}

host_filter() {
  local value="$1"
  printf '(&(objectClass=computer)(|(cn=%s)(name=%s)(dNSHostName=%s)))' \
    "$value" "$value" "$value"
}

main() {
  require_bin ldapsearch
  require_bin perl

  if [[ $# -lt 2 ]]; then
    usage
    exit 1
  fi

  local mode="$1"
  shift
  local value="$*"

  if [[ -z "${LDAP_BIND_DN}" ]]; then
    echo "LDAP_BIND_DN is required" >&2
    exit 1
  fi

  prompt_password_if_needed

  case "${mode}" in
    user)
      run_search "$(user_filter "${value}")" \
        distinguishedName cn name displayName sAMAccountName userPrincipalName mail department company title telephoneNumber mobile description memberOf whenCreated whenChanged lastLogonTimestamp
      ;;
    dn)
      run_search "$(dn_filter "${value}")" '*'
      ;;
    host)
      run_search "$(host_filter "${value}")" \
        distinguishedName cn name dNSHostName operatingSystem operatingSystemVersion lastLogonTimestamp
      ;;
    raw)
      run_search "${value}" '*'
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
