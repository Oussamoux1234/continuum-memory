"""Test-only daemon with the prototype approval seam explicitly injected."""

import argparse
import tempfile
from pathlib import Path

from continuum_memory.daemon import serve
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import absolute_path, ensure_private_regular


def prototype_kernel(store):
    data_dir = store.data_dir.resolve()
    temporary_root = Path(tempfile.gettempdir()).resolve()
    marker = data_dir / ".continuum-test-vault"
    if temporary_root not in data_dir.parents:
        raise MemoryError("unsafe_test_fixture", "Prototype approval is limited to temporary test vaults.")
    ensure_private_regular(marker, "The prototype test-vault marker")
    return Kernel(store, allow_prototype_approval=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Continuum Memory prototype test daemon")
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    serve(absolute_path(args.data_dir), kernel_factory=prototype_kernel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
