#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 SOURCES_DIR OUTPUT_DIR TARGET_KEY" >&2
  exit 2
fi

readonly SOURCES_DIR="$1"
readonly OUTPUT_DIR="$2"
readonly TARGET_KEY="$3"
readonly REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly BUILD_ROOT="/tmp/continuum-sqlcipher-build"
readonly OPENSSL_PREFIX="/tmp/continuum-sqlcipher-openssl-3.5.8"
readonly SOURCE_DATE_EPOCH="1788285600"
readonly DEVTOOLSET_ROOT="/opt/rh/gcc-toolset-14/root"
readonly BUILD_PATH="/opt/_internal/pipx/venvs/auditwheel/bin:${DEVTOOLSET_ROOT}/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly HARDENING_FLAGS="-O2 -g0 -fPIC -fvisibility=hidden -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
export SOURCE_DATE_EPOCH
export PATH="${BUILD_PATH}"
export LANG=C
export LC_ALL=C
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export ZERO_AR_DATE=1
export CC="${DEVTOOLSET_ROOT}/usr/bin/gcc"
export AR="${DEVTOOLSET_ROOT}/usr/bin/ar"
export RANLIB="${DEVTOOLSET_ROOT}/usr/bin/ranlib"
export LD="${DEVTOOLSET_ROOT}/usr/bin/ld"
unset PYTHONHOME PYTHONPATH PIP_CONFIG_FILE PIP_INDEX_URL PIP_EXTRA_INDEX_URL

case "${TARGET_KEY}" in
  linuxCp311)
    readonly PYTHON_ABI="cp311-cp311"
    readonly PYTHON_MINOR="3.11"
    readonly PYTHON_CACHE_TAG="cpython-311"
    ;;
  linuxCp312)
    readonly PYTHON_ABI="cp312-cp312"
    readonly PYTHON_MINOR="3.12"
    readonly PYTHON_CACHE_TAG="cpython-312"
    ;;
  linuxCp313)
    readonly PYTHON_ABI="cp313-cp313"
    readonly PYTHON_MINOR="3.13"
    readonly PYTHON_CACHE_TAG="cpython-313"
    ;;
  linuxCp314)
    readonly PYTHON_ABI="cp314-cp314"
    readonly PYTHON_MINOR="3.14"
    readonly PYTHON_CACHE_TAG="cpython-314"
    ;;
  *)
    echo "unknown patched-wheel target: ${TARGET_KEY}" >&2
    exit 2
    ;;
esac
readonly PYTHON_BIN="/opt/python/${PYTHON_ABI}/bin/python"
readonly BUILD_VENV="/tmp/continuum-sqlcipher-build-venv"
readonly BUILD_PYTHON="${BUILD_VENV}/bin/python"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "the reviewed supply-chain slice requires Linux x86-64" >&2
  exit 1
fi
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "the pinned builder does not contain ${PYTHON_ABI}" >&2
  exit 1
fi
"${PYTHON_BIN}" -I -c \
  'import sys; expected_minor, expected_tag = sys.argv[1:]; actual_minor = "%d.%d" % sys.version_info[:2]; assert actual_minor == expected_minor and sys.implementation.cache_tag == expected_tag, (actual_minor, sys.implementation.cache_tag)' \
  "${PYTHON_MINOR}" "${PYTHON_CACHE_TAG}"
if [[ -L "${SOURCES_DIR}" || ! -d "${SOURCES_DIR}" || -L "${OUTPUT_DIR}" || ! -d "${OUTPUT_DIR}" ]]; then
  echo "source and output mounts must be real directories" >&2
  exit 1
fi
if [[ -e "${BUILD_ROOT}" || -e "${OPENSSL_PREFIX}" || -e "${BUILD_VENV}" ]]; then
  echo "fixed build paths must start absent" >&2
  exit 1
fi

umask 022
mkdir -p "${BUILD_ROOT}"
"${PYTHON_BIN}" "${REPOSITORY_ROOT}/scripts/verify_patched_sqlcipher_inputs.py" \
  --sources "${SOURCES_DIR}"

/usr/bin/tar --no-same-owner --no-same-permissions -xzf \
  "${SOURCES_DIR}/openssl-3.5.8.tar.gz" -C "${BUILD_ROOT}"
unzip -q "${SOURCES_DIR}/sqlcipher-4.19.0.zip" -d "${BUILD_ROOT}"
/usr/bin/tar --no-same-owner --no-same-permissions -xzf \
  "${SOURCES_DIR}/sqlcipher3-0.6.2.tar.gz" -C "${BUILD_ROOT}"

readonly PREFIX_MAP="-ffile-prefix-map=${BUILD_ROOT}=/usr/src/continuum-sqlcipher"
export PERL5LIB="${REPOSITORY_ROOT}/packaging/sqlcipher/perl"
/usr/bin/perl -MIPC::Cmd -e 'exit(IPC::Cmd::can_run("gcc") && !IPC::Cmd::can_run("continuum-command-that-does-not-exist") ? 0 : 1)'
/usr/bin/perl -MTime::Piece -e 'my $date = Time::Piece->strptime("25 Aug 2026", "%d %b %Y"); exit($date->strftime("%Y-%m-%d") eq "2026-08-25" ? 0 : 1)'

pushd "${BUILD_ROOT}/openssl-3.5.8" >/dev/null
./Configure linux-x86_64 no-shared no-tests no-module no-dso no-zlib \
  no-autoload-config \
  --prefix="${OPENSSL_PREFIX}" \
  --openssldir="${OPENSSL_PREFIX}/ssl" \
  ${HARDENING_FLAGS} "${PREFIX_MAP}"
/usr/bin/make -j2 build_sw
/usr/bin/make install_sw
popd >/dev/null

readonly LIBCRYPTO="${OPENSSL_PREFIX}/lib64/libcrypto.a"
if [[ ! -f "${LIBCRYPTO}" ]]; then
  echo "static libcrypto was not produced" >&2
  exit 1
fi
"${OPENSSL_PREFIX}/bin/openssl" version -a

pushd "${BUILD_ROOT}/sqlcipher-4.19.0" >/dev/null
CFLAGS="${HARDENING_FLAGS} ${PREFIX_MAP}" \
CPPFLAGS="-I${OPENSSL_PREFIX}/include" \
LDFLAGS="${LIBCRYPTO} -ldl -pthread" \
  ./configure --with-tempstore=yes --enable-fts5
/usr/bin/make -j2 sqlite3.c
# SQLCipher intentionally differs from the SQLite Fossil manifest bundled in
# its source archive, so SQLite's verify-source target rejects the authentic
# SQLCipher release. Authenticity is established before extraction by the
# pinned archive hash, detached signature, release commit, and manifest UUID.
# This target instead validates the generated amalgamation's source structure.
/usr/bin/make sourcetest
popd >/dev/null

readonly BINDING_ROOT="${BUILD_ROOT}/sqlcipher3-0.6.2"
cp "${BUILD_ROOT}/sqlcipher-4.19.0/sqlite3.c" "${BINDING_ROOT}/vendor/sqlite3.c"
cp "${BUILD_ROOT}/sqlcipher-4.19.0/sqlite3.h" "${BINDING_ROOT}/vendor/sqlite3.h"
cp "${REPOSITORY_ROOT}/packaging/sqlcipher/setup_continuum.py" "${BINDING_ROOT}/setup.py"
cp "${REPOSITORY_ROOT}/packaging/sqlcipher/pyproject.toml" "${BINDING_ROOT}/pyproject.toml"
mkdir "${BINDING_ROOT}/THIRD_PARTY_LICENSES"
cp "${BUILD_ROOT}/sqlcipher-4.19.0/LICENSE.txt" \
  "${BINDING_ROOT}/THIRD_PARTY_LICENSES/SQLCipher-BSD-3-Clause.txt"
cp "${BUILD_ROOT}/sqlcipher-4.19.0/SQLITE_LICENSE.md" \
  "${BINDING_ROOT}/THIRD_PARTY_LICENSES/SQLite-Public-Domain.txt"
cp "${BUILD_ROOT}/openssl-3.5.8/LICENSE.txt" \
  "${BINDING_ROOT}/THIRD_PARTY_LICENSES/OpenSSL-Apache-2.0.txt"

"${PYTHON_BIN}" -I -m venv "${BUILD_VENV}"
"${BUILD_PYTHON}" -I -m pip --isolated install --no-index --no-deps --no-cache-dir \
  --disable-pip-version-check --force-reinstall \
  "${SOURCES_DIR}/setuptools-80.9.0-py3-none-any.whl" \
  "${SOURCES_DIR}/wheel-0.45.1-py3-none-any.whl"

mkdir "${BUILD_ROOT}/raw-wheel"
pushd "${BINDING_ROOT}" >/dev/null
PYTHONHASHSEED=0 \
CFLAGS="${HARDENING_FLAGS} ${PREFIX_MAP}" \
CONTINUUM_OPENSSL_INCLUDE="${OPENSSL_PREFIX}/include" \
CONTINUUM_LIBCRYPTO_A="${LIBCRYPTO}" \
  "${BUILD_PYTHON}" -I setup.py --quiet bdist_wheel --dist-dir "${BUILD_ROOT}/raw-wheel"
popd >/dev/null

mapfile -t raw_wheels < <(find "${BUILD_ROOT}/raw-wheel" -maxdepth 1 -type f -name '*.whl')
if [[ ${#raw_wheels[@]} -ne 1 ]]; then
  echo "expected exactly one raw wheel, found ${#raw_wheels[@]}" >&2
  exit 1
fi
/opt/_internal/pipx/venvs/auditwheel/bin/auditwheel show "${raw_wheels[0]}"
/opt/_internal/pipx/venvs/auditwheel/bin/auditwheel repair \
  --plat manylinux_2_28_x86_64 --wheel-dir "${OUTPUT_DIR}" "${raw_wheels[0]}"

mapfile -t repaired_wheels < <(find "${OUTPUT_DIR}" -maxdepth 1 -type f -name '*.whl')
if [[ ${#repaired_wheels[@]} -ne 1 ]]; then
  echo "expected exactly one repaired wheel, found ${#repaired_wheels[@]}" >&2
  exit 1
fi
sha256sum "${repaired_wheels[0]}"
