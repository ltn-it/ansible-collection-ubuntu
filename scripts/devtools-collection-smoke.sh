#!/usr/bin/env bash
set -eo pipefail

COLLECTION_NAMESPACE="${COLLECTION_NAMESPACE:-lit}"

if [ -z "${COLLECTION_NAME:-}" ]; then
  if [ -f galaxy.yml ]; then
    COLLECTION_NAME="$(scripts/devtools-galaxy.sh value name galaxy.yml)"
  fi
  if [ -z "${COLLECTION_NAME:-}" ]; then
    echo "ERROR: COLLECTION_NAME not set and galaxy.yml missing 'name'." >&2
    exit 1
  fi
fi

EXAMPLE_PLAYBOOK="${EXAMPLE_PLAYBOOK:-playbooks/example.yml}"
EXAMPLE_PLAYBOOK_ARGS="${EXAMPLE_PLAYBOOK_ARGS:-}"
case "$EXAMPLE_PLAYBOOK_ARGS" in
  ""|--check) ;;
  *) echo "ERROR: unsupported example playbook arguments." >&2; exit 1 ;;
esac

echo "Running collection smoke test for ${COLLECTION_NAMESPACE}.${COLLECTION_NAME} using ${EXAMPLE_PLAYBOOK}"

COLLECTION_NAMESPACE="$COLLECTION_NAMESPACE" \
COLLECTION_NAME="$COLLECTION_NAME" \
EXAMPLE_PLAYBOOK="$EXAMPLE_PLAYBOOK" \
EXAMPLE_PLAYBOOK_ARGS="$EXAMPLE_PLAYBOOK_ARGS" \
WUNDER_DEVTOOLS_NETWORK=bridge \
WUNDER_DEVTOOLS_ROOTFS_MODE=rw \
WUNDER_DEVTOOLS_RUN_AS_ROOT=1 \
CONTAINER_HOME=/tmp/wunder \
bash scripts/wunder-devtools-ee.sh bash -c '
  set -euo pipefail

  ns="${COLLECTION_NAMESPACE}"
  name="${COLLECTION_NAME}"
  example="${EXAMPLE_PLAYBOOK:-playbooks/example.yml}"
  example_args="${EXAMPLE_PLAYBOOK_ARGS:-}"

  export HOME="$(mktemp -d /tmp/collection-smoke-home.XXXXXX)"
  mkdir -p "${HOME}"

  # Only this disposable package-install smoke opts into root + writable rootfs.
  # The released Devtools image deliberately makes package output directories
  # read-only. Restore owner-write on these two root-owned directories inside
  # the container; the mounted repository and host filesystem stay read-only.
  for package_directory in /usr/bin /usr/lib64; do
    [ ! -L "${package_directory}" ] && [ -d "${package_directory}" ] &&
      [ "$(stat -c %u "${package_directory}")" = 0 ] || exit 1
    chmod u+w "${package_directory}"
  done
  # /run is an isolated tmpfs. Disabled-role prechecks still require this
  # trusted standard Ubuntu lock parent, which is absent in the UBI image.
  install -d -m 0755 /run/lock
  # The hardened image starts with mode 000 on its disposable account databases.
  # Root with all capabilities dropped cannot read those files implicitly.
  # Enable only owner access inside this isolated smoke rootfs, never on the host.
  for account_database in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
    [ ! -L "${account_database}" ] && [ -f "${account_database}" ] &&
      [ "$(stat -c %u "${account_database}")" = 0 ] || exit 1
    chmod 0600 "${account_database}"
  done

  echo "Running collection smoke test for ${ns}.${name} with example playbook: ${example}"

  # -------------------------------------------------------------------
  # 1) Build + install this collection into a per-run collections dir
  # -------------------------------------------------------------------
  COLLECTIONS_DIR="$(bash /workspace/scripts/devtools-collection-prepare.sh | tail -n 1)"

  if [ -z "${COLLECTIONS_DIR:-}" ] || [ ! -d "${COLLECTIONS_DIR}" ]; then
    echo "ERROR: COLLECTIONS_DIR not found/invalid: ${COLLECTIONS_DIR:-<empty>}" >&2
    exit 1
  fi

  export ANSIBLE_COLLECTIONS_PATH="${COLLECTIONS_DIR}:/usr/share/ansible/collections"

  # -------------------------------------------------------------------
  # 2) Configure Ansible (optional)
  # -------------------------------------------------------------------
  if [ -f /workspace/ansible.cfg ]; then
    export ANSIBLE_CONFIG=/workspace/ansible.cfg
  fi

  # -------------------------------------------------------------------
  # 3) Run example playbook
  # -------------------------------------------------------------------
  if [ "${example_args}" = "--check" ]; then
    ansible-playbook -i localhost, "${example}" --check
  else
    ansible-playbook -i localhost, "${example}"
  fi
'
