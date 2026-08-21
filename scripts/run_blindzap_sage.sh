#!/usr/bin/env bash
set -Eeuo pipefail

readonly SAGE_IMAGE='docker.io/sagemath/sagemath@sha256:19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly MODEL='spec/blindzap/blindzap_reference.sage'
readonly SAGE_FIXTURE='test/blindzap/testdata/blindzap_sage_vectors.json'
readonly PYTHON_FIXTURE='test/blindzap/testdata/blindzap_vectors.json'

for required_file in "${MODEL}" "${SAGE_FIXTURE}" "${PYTHON_FIXTURE}"; do
  if [[ ! -f "${REPOSITORY_ROOT}/${required_file}" ]]; then
    printf 'missing required BlindZap reference file: %s\n' "${required_file}" >&2
    exit 2
  fi
done

readonly -a SAGE_ARGUMENTS=(
  "${MODEL}"
  --check "${SAGE_FIXTURE}"
  --cross-check "${PYTHON_FIXTURE}"
)

is_sage_10_6() {
  local sage_version
  sage_version="$("$1" --version 2>/dev/null)" || return 1
  [[ "${sage_version}" == 'SageMath version 10.6,'* ]]
}

if [[ -n "${BLINDZAP_SAGE_BIN:-}" ]]; then
  if [[ ! -x "${BLINDZAP_SAGE_BIN}" ]]; then
    printf 'BLINDZAP_SAGE_BIN is not executable: %s\n' "${BLINDZAP_SAGE_BIN}" >&2
    exit 2
  fi
  if ! is_sage_10_6 "${BLINDZAP_SAGE_BIN}"; then
    printf 'BLINDZAP_SAGE_BIN must be SageMath 10.6: %s\n' "${BLINDZAP_SAGE_BIN}" >&2
    exit 2
  fi
  cd -- "${REPOSITORY_ROOT}"
  exec "${BLINDZAP_SAGE_BIN}" -python "${SAGE_ARGUMENTS[@]}"
fi

if command -v sage >/dev/null 2>&1; then
  SAGE_PATH="$(command -v sage)"
  readonly SAGE_PATH
  if is_sage_10_6 "${SAGE_PATH}"; then
    cd -- "${REPOSITORY_ROOT}"
    exec "${SAGE_PATH}" -python "${SAGE_ARGUMENTS[@]}"
  fi
  printf 'ignoring local Sage other than 10.6: %s\n' "${SAGE_PATH}" >&2
fi

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Sage is unavailable; install Sage 10.6, set BLINDZAP_SAGE_BIN, or install Docker.' >&2
  exit 2
fi

exec docker run --rm \
  --platform linux/amd64 \
  --network none \
  --read-only \
  --env HOME=/tmp \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --volume "${REPOSITORY_ROOT}:/workspace:ro" \
  --workdir /workspace \
  "${SAGE_IMAGE}" \
  sage -python "${SAGE_ARGUMENTS[@]}"
