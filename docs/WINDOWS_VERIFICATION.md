# Native Windows prototype verification

The full-gate candidate targets standard public `windows-2025` x64 runners with
Python 3.11, 3.12, 3.13 and 3.14. A configured workflow is not evidence that its
current revision passes: inspect all four native results before accepting the
runtime. The older filesystem and named-pipe workflows alone are not full-product
acceptance. Windows 10/11 desktop behavior still needs separately recorded evidence.

This is plaintext prototype verification using disposable synthetic vaults. It
does not establish encryption, a native human-presence broker, protected signing
keys, trusted application identity, or protection against same-user malware.
Normal Windows administrative approval remains unavailable and fails closed.
Only explicitly marked ephemeral test daemons inject prototype approval.

## Run the full gate in PowerShell

Use a fresh checkout and a Python 3.11–3.14 environment. The tool preparation step
downloads hash-pinned build/verification wheels; the verifier and fresh package
installation steps run with package indexes disabled. These are development tools,
not application runtime dependencies. No system approval installation is performed.

```powershell
python -m venv .venv
$python = Join-Path $PWD '.venv\Scripts\python.exe'
& $python -m pip download --only-binary=:all: --require-hashes -r packaging/build-requirements.txt --dest work/build-wheels
if ($LASTEXITCODE -ne 0) { throw 'Tool download failed' }
& $python -m pip install --no-index --find-links work/build-wheels --require-hashes -r packaging/build-requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Tool installation failed' }
& $python -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Tool dependencies are incomplete' }
& $python scripts/verify.py
if ($LASTEXITCODE -ne 0) { throw 'Full verification failed' }
```

The gate runs all applicable tests, real MCP subprocess fixtures and lifecycle
demo, two fresh deterministic source/wheel builds, fresh offline installations of
both artifacts, all four installed entrypoint help/version checks, and independent
SPDX validation. Checking the Linux-only helper's `--help` does not enable it on
Windows: its operational commands remain refused. POSIX root-helper/file-lock and
Unix-socket tests stay in their native gates; common contracts and Windows-native
boundary tests must run, not be replaced by mocks or broad skips.

The migration writer-contention test uses real child processes on Windows too.
Its bounded pipe barrier uses native `PeekNamedPipe` rather than POSIX `select`.
This demonstrates process-crash recovery, not host power-loss durability.

The new Windows workflow uploads no packages, source archives, SBOMs, or vault
files. Generated package checks remain on the disposable runner; ordinary job
logs report the environment and pass/fail evidence. Local verification uses
temporary output unless `CONTINUUM_RELEASE_OUTPUT` selects an empty destination.

## Dependency and source checks

The Windows-only Colorama dependency required by `build==1.3.0` is pinned to
`0.4.6`; PyYAML `6.0.3` has exact CPython 3.11–3.14 `win_amd64` wheel hashes.
Their metadata and downloaded bytes were checked against the respective
[PyPI Colorama release](https://pypi.org/project/colorama/0.4.6/) and
[PyPI PyYAML release](https://pypi.org/project/PyYAML/6.0.3/).
The payload SBOM inventories application archives, not these unbundled build tools.

Source checkout uses LF line endings. Archive paths reject drive-qualified names,
alternate streams, device names, trailing-dot/space aliases and case-colliding
members before extraction. Reproducibility compares two clean builds on the same
recorded environment; it is not a claim of identical artifacts across every OS.
