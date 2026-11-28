# Purpose: Deterministic temporal sampling of public feature JSON; no archive extraction.
# Works with: workspace, tools.evaluation.acquire_features
# Used by: the Python module loader or CLI entry point

"""Deterministic temporal sampling of public feature JSON; no archive extraction."""

import argparse
import hashlib
import heapq
import json
import zipfile
from sentinelav.workspace import Workspace
from tools.evaluation.acquire_features import FILES, REVISION


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=('Dot_Net', 'Win32', 'Win64'), default='Dot_Net')
    parser.add_argument('--published-model', action='store_true')
    parser.add_argument('--per-class', type=int, default=500)
    args = parser.parse_args()
    if not 10 <= args.per_class <= 1000:
        parser.error('Use 10..1000 rows per class per week')
    from thrember.features import PEFeatureExtractor

    keys = [f.name for f in PEFeatureExtractor().features]
    work = Workspace()
    folder = work.area('datasets') / 'ember2024'
    output = work.run('datasets', 'prepared-' + args.format)
    target = output / 'rows.jsonl'
    seen = set()
    groups = {}
    counts = {s: 0 for s in ('train', 'calibration', 'test')}
    families = {s: set() for s in counts}
    selected = ['test'] if args.published_model else ['train', 'test']
    with target.open('x', encoding='utf-8') as stream:
        for source in selected:
            name = args.format + '_' + source + '.zip'
            path = folder / name
            expected_size, expected_hash = FILES[name]
            digest = hashlib.sha256()
            with path.open('rb') as archive:
                while raw := archive.read(4 * 1024 * 1024):
                    digest.update(raw)
            if path.stat().st_size != expected_size or digest.hexdigest() != expected_hash:
                raise ValueError('Unverified feature archive')
            with zipfile.ZipFile(path) as archive:
                entries = sorted(
                    [i for i in archive.infolist() if i.filename.endswith('.jsonl')],
                    key=lambda i: i.filename,
                )
                for index, entry in enumerate(entries):
                    if args.published_model:
                        split = 'calibration' if index < 4 else 'test'
                    elif source == 'train' and index < 44:
                        split = 'train'
                    elif source == 'train':
                        split = 'calibration'
                    else:
                        split = 'test'
                    limit = min(args.per_class, 100) if split == 'train' else args.per_class
                    heaps = {0: [], 1: []}
                    with archive.open(entry) as rows:
                        while raw := rows.readline(2 * 1024 * 1024 + 1):
                            if len(raw) > 2 * 1024 * 1024:
                                raise ValueError('Feature row budget')
                            row = json.loads(raw)
                            label = row.get('label')
                            sha = row.get('sha256')
                            if label not in (0, 1) or not isinstance(sha, str) or len(sha) != 64:
                                continue
                            # Keep the smallest hashes for a stable per-week/class sample.
                            rank = -int(sha, 16)
                            heap = heaps[label]
                            if len(heap) < limit:
                                heapq.heappush(heap, (rank, raw))
                            elif rank > heap[0][0]:
                                heapq.heapreplace(heap, (rank, raw))
                    for heap in heaps.values():
                        for rank, raw in sorted(heap, reverse=True):
                            row = json.loads(raw)
                            sha = row['sha256']
                            group = row.get('tlsh') or sha
                            if sha in seen or group in groups and groups[group] != split:
                                continue
                            seen.add(sha)
                            groups[group] = split
                            features = {key: row[key] for key in keys}
                            result = dict(
                                sha256=sha,
                                label=row['label'],
                                split=split,
                                group=group,
                                file_type=args.format,
                                features=features,
                                provenance='EMBER2024 '
                                + REVISION
                                + ' '
                                + name
                                + ' '
                                + expected_hash,
                                family=row.get('family'),
                                first_submission_date=row.get('first_submission_date'),
                            )
                            stream.write(json.dumps(result, separators=(',', ':')) + '\n')
                            counts[split] += 1
                            if row.get('family'):
                                families[split].add(row['family'])
                    print(
                        json.dumps(dict(week=entry.filename, split=split, counts=counts)),
                        flush=True,
                    )
                    work.check()
    manifest = dict(
        schema=1,
        format=args.format,
        published_model=args.published_model,
        counts=counts,
        family_counts={key: len(value) for key, value in families.items()},
        family_disjoint=False,
        related_group_method='Exact TLSH equality; additional near-build/family evaluation remains required',
        source_revision=REVISION,
        rows=str(target),
        raw_specimens=False,
    )
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
