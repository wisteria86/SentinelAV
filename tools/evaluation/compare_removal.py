# Purpose: Compare frozen paired cleanup cases against independently recorded ground truth.
# Works with: lab/removal_benchmark.py; updates/artifacts.py; workspace.py
# Used by: the Python module loader or CLI entry point

import argparse
import json
from pathlib import Path
from sentinelav.lab.removal_benchmark import compare
from sentinelav.updates.artifacts import bounded_json
from sentinelav.workspace import Workspace


def main():
    parser = argparse.ArgumentParser(
        description='Audit matched Defender/SentinelAV cleanup metadata; never executes specimens'
    )
    parser.add_argument('manifest', type=Path)
    parser.add_argument('trials', type=Path)
    args = parser.parse_args()
    report = compare(bounded_json(args.manifest), bounded_json(args.trials)['trials'])
    print(Workspace().immutable_report(report, 'removal-comparison'))


if __name__ == '__main__':
    main()
