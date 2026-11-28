# Purpose: Bounded diagnostics for the guest-only emulator evaluation report.
# Works with: sibling modules in lab
# Used by: lab.static_corpus, tests.unit.test_emulation_evaluation

"""Bounded diagnostics for the guest-only emulator evaluation report."""

STATUSES = ('Not run', 'Not applicable', 'Unavailable', 'Partial', 'Complete')


def metrics(row):
    """Summarise the emulation part of one evaluation row: status, bounded counters, whether emulation
    found anything, and why it stopped.
    """
    scan = row.get('scan', {})
    coverage = scan.get('advanced_analysis', {}).get('coverage', {}).get('emulation')
    if not coverage:
        status = (
            'Not applicable'
            if scan.get('file_format', {}).get('format') not in (None, 'PE')
            else 'Not run'
        )
        coverage = {}
    else:
        status = coverage.get('status', 'Not run')
    if status not in STATUSES:
        status = 'Not run'
    omissions = scan.get('advanced_analysis', {}).get('omissions', [])
    text = ' '.join(str(value) for value in omissions).casefold()
    categories = dict(
        api_model_stopped='api model stopped' in text,
        cpu_stopped='cpu stopped' in text,
        budget_or_path_incomplete=any(
            value in text for value in ('budget', 'instruction/time', 'cumulative emulation')
        ),
        environment_subset='win32 subset' in text,
        unavailable=status == 'Unavailable',
        not_applicable=status == 'Not applicable',
        analysis_missing=status == 'Not run',
    )

    def bounded(key, maximum):
        """Read one integer counter, clamped between 0 and `maximum`."""
        value = coverage.get(key)
        return min(maximum, max(0, value)) if type(value) is int else 0

    findings = any(
        e.get('source') == 'emulation' and e.get('confirmed')
        for e in scan.get('advanced_analysis', {}).get('evidence', [])
    )
    return dict(
        status=status,
        instructions=bounded('instructions_observed', 200000),
        api_calls=bounded('api_calls', 65535),
        changed_pages=bounded('changed_pages', 256),
        emulation_signature_finding=findings,
        omission_categories=categories,
    )
