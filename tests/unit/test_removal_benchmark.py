# Purpose: Verify test removal benchmark behavior using controlled fixtures.
# Works with: lab.removal_benchmark
# Used by: unittest discovery

import copy
import unittest
from sentinelav.lab.removal_benchmark import compare


class RemovalBenchmarkTests(unittest.TestCase):
    def fixture(self):
        manifest = dict(
            schema=1,
            cases=[
                dict(
                    id='case',
                    family='example',
                    initial_state_sha256='a' * 64,
                    malicious_artifacts=['payload', 'startup'],
                    benign_artifacts=['control'],
                )
            ],
        )
        common = dict(
            case_id='case',
            defender_active=True,
            os_build='fixture',
            reset_evidence_sha256='b' * 64,
            engine_version='fixture',
            intelligence_version='fixture',
            configuration_sha256='c' * 64,
            initial_state_sha256='a' * 64,
            observations_complete=True,
            full_scan_completed=True,
            reboot_checks=[dict(remaining_artifacts=[]), dict(remaining_artifacts=[])],
            remaining_artifacts=[],
            changed_artifacts=[],
        )
        return manifest, [
            dict(common, product='Defender', guest_id='one'),
            dict(common, product='SentinelAV', guest_id='two'),
        ]

    def test_inactive_defender_never_counts_as_a_win(self):
        manifest, rows = self.fixture()
        rows[0]['defender_active'] = False
        result = compare(manifest, rows)
        self.assertEqual(result['eligible_pairs'], 0)
        self.assertFalse(result['superiority_gate_passed'])

    def test_missing_observation_metadata_is_ineligible(self):
        manifest, rows = self.fixture()
        del rows[0]['engine_version']
        self.assertEqual(compare(manifest, rows)['eligible_pairs'], 0)

    def test_recurrence_and_collateral_prevent_complete_cleanup(self):
        manifest, rows = self.fixture()
        rows = copy.deepcopy(rows)
        rows[1]['reboot_checks'][1]['remaining_artifacts'] = ['startup']
        rows[1]['changed_artifacts'] = ['control']
        result = compare(manifest, rows)
        outcome = result['cases'][0]['SentinelAV']
        self.assertFalse(outcome['complete'])
        self.assertEqual(outcome['collateral'], ['control'])
        self.assertEqual(outcome['malicious_remnants'], ['startup'])
