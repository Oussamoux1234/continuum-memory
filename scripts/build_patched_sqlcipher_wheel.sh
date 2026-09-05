#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 SOURCES_DIR OUTPUT_DIR" >&2
  exit 2
fi

readonly SOURCES_DIR="$1"
readonly OUTPUT_DIR="$2"
readonly REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly PYTHON_BIN="/opt/python/cp314-cp314/bin/python"
readonly BUILD_ROOT="/tmp/continuum-sqlcipher-build"
readonly OPENSSL_PREFIX="/opt/continuum/openssl-3.5.8"
readonly SOURCE_DATE_EPOCH="1788285600"
export SOURCE_DATE_EPOCH

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "the first supply-chain slice requires Linux x86-64" >&2
  exit 1
fi
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "the pinned builder does not contain CPython 3.14" >&2
  exit 1
fi
if [[ -e "${BUILD_ROOT}" || -e "${OPENSSL_PREFIX}" ]]; then
  echo "fixed build paths must start absent" >&2
  exit 1
fi

mkdir -p "${BUILD_ROOT}" "${OUTPUT_DIR}"
"${PYTHON_BIN}" "${REPOSITORY_ROOT}/scripts/verify_patched_sqlcipher_inputs.py" \
  --sources "${SOURCES_DIR}"

tar -xzf "${SOURCES_DIR}/openssl-3.5.8.tar.gz" -C "${BUILD_ROOT}"
unzip -q "${SOURCES_DIR}/sqlcipher-4.18.0.zip" -d "${BUILD_ROOT}"
tar -xzf "${SOURCES_DIR}/sqlcipher3-0.6.2.tar.gz" -C "${BUILD_ROOT}"

readonly PREFIX_MAP="-ffile-prefix-map=${BUILD_ROOT}=/usr/src/continuum-sqlcipher"
export PERL5LIB="${REPOSITORY_ROOT}/packaging/sqlcipher/perl"
perl -MIPC::Cmd -e 'exit(IPC::Cmd::can_run("gcc") && !IPC::Cmd::can_run("continuum-command-that-does-not-exist") ? 0 : 1)'
perl -MTime::Piece -e 'my $date = Time::Piece->strptime("25 Aug 2026", "%d %b %Y"); exit($date->strftime("%Y-%m-%d") eq "2026-08-25" ? 0 : 1)'

pushd "${BUILD_ROOT}/openssl-3.5.8" >/dev/null
./Configure linux-x86_64 no-shared no-tests no-module no-dso no-zlib \
  --prefix="${OPENSSL_PREFIX}" \
  --openssldir="${OPENSSL_PREFIX}/ssl" \
  -O2 -g0 -fPIC -fvisibility=hidden "${PREFIX_MAP}"
make -j2 build_sw
make install_sw
popd >/dev/null

readonly LIBCRYPTO="${OPENSSL_PREFIX}/lib64/libcrypto.a"
if [[ ! -f "${LIBCRYPTO}" ]]; then
  echo "static libcrypto was not produced" >&2
  exit 1
fi
"${OPENSSL_PREFIX}/bin/openssl" version -a

pushd "${BUILD_ROOT}/sqlcipher-4.18.0" >/dev/null
CFLAGS="-O2 -g0 -fPIC ${PREFIX_MAP}" \
CPPFLAGS="-I${OPENSSL_PREFIX}/include" \
LDFLAGS="${LIBCRYPTO} -ldl -pthread" \
  ./configure --with-tempstore=yes --enable-fts5
make -j2 sqlite3.c
# SQLCipher intentionally differs from the SQLite Fossil manifest bundled in
# its source archive, so SQLite's verify-source target rejects the authentic
# SQLCipher release. Authenticity is established before extraction by the
# pinned archive hash, detached signature, release commit, and manifest UUID.
# This target instead validates the generated amalgamation's source structure.
make sourcetest
popd >/dev/null

readonly BINDING_ROOT="${BUILD_ROOT}/sqlcipher3-0.6.2"
cp "${BUILD_ROOT}/sqlcipher-4.18.0/sqlite3.c" "${BINDING_ROOT}/vendor/sqlite3.c"
cp "${BUILD_ROOT}/sqlcipher-4.18.0/sqlite3.h" "${BINDING_ROOT}/vendor/sqlite3.h"
cp "${REPOSITORY_ROOT}/packaging/sqlcipher/setup_continuum.py" "${BINDING_ROOT}/setup.py"
cp "${REPOSITORY_ROOT}/packaging/sqlcipher/pyproject.toml" "${BINDING_ROOT}/pyproject.toml"
mkdir "${BINDING_ROOT}/THIRD_PARTY_LICENSES"
cp "${BUILD_ROOT}/sqlcipher-4.18.0/LICENSE.txt" \
  "${BINDING_ROOT}/THIRD_PARTY_LICENSES/SQLCipher-BSD-3-Clause.txt"
cp "${BUILD_ROOT}/sqlcipher-4.18.0/SQLITE_LICENSE.md" \
  "${BINDING_ROOT}/THIRD_PARTY_LICENSES/SQLite-Public-Domain.txt"
cp "${BUILD_ROOT}/openssl-3.5.8/LICENSE.txt" \
  "${BINDING_ROOT}/THIRD_PARTY_LICENSES/OpenSSL-Apache-2.0.txt"

"${PYTHON_BIN}" -m pip install --no-index --no-deps --force-reinstall \
  "${SOURCES_DIR}/setuptools-80.9.0-py3-none-any.whl" \
  "${SOURCES_DIR}/wheel-0.45.1-py3-none-any.whl"

mkdir "${BUILD_ROOT}/raw-wheel"
pushd "${BINDING_ROOT}" >/dev/null
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
PYTHONHASHSEED=0 \
CFLAGS="-O2 -g0 -fPIC -fvisibility=hidden ${PREFIX_MAP}" \
CONTINUUM_OPENSSL_INCLUDE="${OPENSSL_PREFIX}/include" \
CONTINUUM_LIBCRYPTO_A="${LIBCRYPTO}" \
  "${PYTHON_BIN}" setup.py --quiet bdist_wheel --dist-dir "${BUILD_ROOT}/raw-wheel"
popd >/dev/null

mapfile -t raw_wheels < <(find "${BUILD_ROOT}/raw-wheel" -maxdepth 1 -type f -name '*.whl')
if [[ ${#raw_wheels[@]} -ne 1 ]]; then
  echo "expected exactly one raw wheel, found ${#raw_wheels[@]}" >&2
  exit 1
fi
auditwheel show "${raw_wheels[0]}"
auditwheel repair --plat manylinux_2_28_x86_64 --wheel-dir "${OUTPUT_DIR}" "${raw_wheels[0]}"

mapfile -t repaired_wheels < <(find "${OUTPUT_DIR}" -maxdepth 1 -type f -name '*.whl')
if [[ ${#repaired_wheels[@]} -ne 1 ]]; then
  echo "expected exactly one repaired wheel, found ${#repaired_wheels[@]}" >&2
  exit 1
fi
sha256sum "${repaired_wheels[0]}"
