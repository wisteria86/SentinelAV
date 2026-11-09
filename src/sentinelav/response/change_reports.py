# Purpose: Export summaries without recorded contents, command lines or credentials.
# Works with: sibling modules in response
# Used by: ui.app_changes_ui, tests.unit.test_app_changes

"""Export summaries without recorded contents, command lines or credentials."""


def summary(changes,receipts):
    observations=[]
    for row in changes:
        target=row['resource']
        observations.append(dict(id=row['id'],observed_at=row['observed_at'],
            resource_kind=target['kind'],resource_id=target['id'],
            attribution=row['attribution'],preexisting=row['preexisting'],
            baseline_available=row['baseline_available'],before_hash=row['before_hash'],after_hash=row['after_hash']))
    operations=[]
    for row in receipts:
        if row.get('kind')!='RemediationReceipt':continue
        operations.append(dict(id=row['id'],outcome=row['state'],mode=row['mode'],
            actions=[dict(change_id=result['change_id'],state=result['state'],
                resource_kind=result['resource']['kind'],
                detail='Review the local receipt for details' if result.get('reason') else None)
                for result in row.get('results',[])]))
    return dict(schema=1,kind='AppChangeSummary',observations=observations,operations=operations,
        redactions='Before/after payloads, paths, commands, error text and process arguments omitted')
