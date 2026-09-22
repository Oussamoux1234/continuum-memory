"""Short-deadline transport probes, restricted to marked disposable vaults."""

import argparse
from pathlib import Path

from continuum_memory import daemon
from continuum_memory.security import absolute_path
from fixtures.prototype_daemon import prototype_kernel


class TransportKernel:
    def __init__(self, store):
        self.delegate = prototype_kernel(store)  # Enforces the temporary-vault guard.

    def dispatch(self, capability, method, params):
        if method == "fixture_large":
            return {"payload": "x" * 60000}
        if method == "fixture_oversized":
            return {"payload": "x" * 70000}
        return self.delegate.dispatch(capability, method, params)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    daemon.READ_TIMEOUT = 0.6
    daemon.WRITE_TIMEOUT = 0.6
    daemon.MAX_CONNECTIONS = 4
    daemon.serve(absolute_path(args.data_dir), kernel_factory=TransportKernel)


if __name__ == "__main__":
    main()
