# Purpose: Command line for selecting, downloading and sealing a MalwareBazaar corpus by first-seen window.
# Works with: lab.qualification.bazaar_corpus
# Used by: evaluation runs (bazaar-dev and bazaar-holdout profiles)

"""Select, download and seal a MalwareBazaar corpus by first-seen window. Resumable."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from sentinelav.lab.qualification.bazaar_corpus import build  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name', choices=['dev', 'holdout'])
    parser.add_argument('export', type=Path, help='MalwareBazaar full export (full.csv.zip)')
    parser.add_argument(
        '--start',
        required=True,
        help='First-seen lower bound, inclusive, e.g. "2026-10-11 00:00:00"',
    )
    parser.add_argument('--end', required=True, help='First-seen upper bound, exclusive')
    parser.add_argument('--count', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=20261111)
    args = parser.parse_args()
    manifest = build(
        args.name,
        args.export,
        args.start,
        args.end,
        args.count,
        args.seed,
        progress=lambda line: print(line, flush=True),
    )
    print(f"{len(manifest['entries'])} sealed, {len(manifest['skipped'])} skipped")


if __name__ == '__main__':
    main()
