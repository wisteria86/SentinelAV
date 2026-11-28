# Purpose: Explicit runtime job entry point. Refuses the host; never resets a guest itself.
# Works with: lab.runtime_job, updates.artifacts
# Used by: the Python module loader or CLI entry point

"""Explicit runtime job entry point. Refuses the host; never resets a guest itself."""

import argparse
import json
from sentinelav.updates.artifacts import bounded_json
from sentinelav.lab.runtime_job import run_job


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('job')
    args = parser.parse_args()
    print(json.dumps(run_job(bounded_json(args.job, 16384)), indent=2))


if __name__ == '__main__':
    main()
