"""Run every example demo and assert each exits 0.

Run:  python examples/run_all_demos.py
Exits non-zero if any demo fails, so it can gate CI.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

DEMOS = [
    "run_demo.py",
    "demo_structuring.py",
    "demo_layering_trace.py",
    "demo_network_brokers.py",
    "demo_temporal.py",
    "demo_entity_resolution.py",
    "demo_typology_zoo.py",
    "demo_casefile.py",
    "demo_exports.py",
    "demo_investigation.py",
]


def main() -> int:
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    failures = []
    for name in DEMOS:
        path = os.path.join(HERE, name)
        print(f"\n{'=' * 72}\n>>> {name}\n{'=' * 72}")
        r = subprocess.run([sys.executable, path], env=env)
        if r.returncode != 0:
            failures.append((name, r.returncode))
    print(f"\n{'=' * 72}")
    print(f"Ran {len(DEMOS)} demos; {len(DEMOS) - len(failures)} passed, "
          f"{len(failures)} failed.")
    if failures:
        for name, rc in failures:
            print(f"  FAIL {name} (exit {rc})")
        return 1
    print("All demos exited 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
