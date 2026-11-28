# Purpose: Fit a plain-JSON supervised model; never activates it or runs sample files.
# Works with: detection.classifier, updates.artifacts
# Used by: the Python module loader or CLI entry point

"""Fit a plain-JSON supervised model; never activates it or runs sample files."""

import argparse
import hashlib
import json
from pathlib import Path
from sentinelav.detection.classifier import train
from sentinelav.updates.artifacts import bounded_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--epochs', type=int, default=300)
    parser.add_argument('--target-fpr', type=float, default=0.01)
    args = parser.parse_args()
    dataset = bounded_json(args.dataset)
    model = train(dataset['rows'], epochs=args.epochs, target_fpr=args.target_fpr)
    model['dataset_sha256'] = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(model, stream, indent=2, allow_nan=False)
    print(
        'Unvalidated model written; independent evaluation and explicit signed activation are still required.'
    )


if __name__ == '__main__':
    main()
