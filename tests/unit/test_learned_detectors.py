# Purpose: Verify test learned detectors behavior using controlled fixtures.
# Works with: detection.engine, detection.inspection, detection.neural_bytes, detection.pe_ensemble,
#   lab.advanced_check
# Used by: unittest discovery

import copy
import importlib.util
import os
from pathlib import Path
import unittest
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.detection.pe_ensemble import combine, validate


class LogitPoolingTests(unittest.TestCase):
    def test_disagreement_is_not_independent_confirmation(self):
        self.assertAlmostEqual(combine([0.9, 0.1]), 0.5)
        self.assertAlmostEqual(combine([0.9, 0.9]), 0.9)
        with self.assertRaises(ValueError):
            combine([float('nan')])


@unittest.skipUnless(
    (RESOURCE_ROOT / 'analysis-data/active.json').exists(), 'Published weights not installed'
)
class PublishedModelTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows worker memory regression')
    def test_learned_models_leave_room_for_emulation_across_reused_worker(self):
        from sentinelav.detection.inspection import IsolatedScanner

        scanner = IsolatedScanner(
            RESOURCE_ROOT / 'signatures.json',
            RESOURCE_ROOT / 'rules',
            persistent=True,
            options=dict(
                signature_free=True,
                model=True,
                neural=True,
                emulation=True,
                emulation_profile='lab',
            ),
        )
        try:
            for name in ('whoami.exe', 'cmd.exe', 'whoami.exe'):
                result = scanner.scan(
                    [Path(os.environ['WINDIR']) / 'System32' / name],
                    lambda: False,
                    lambda *args: None,
                )
                coverage = result.get('advanced_analysis', {}).get('coverage', {})
                self.assertEqual(
                    coverage.get('model', {}).get('status'), 'Complete', result.get('errors')
                )
                self.assertEqual(
                    coverage.get('neural', {}).get('status'), 'Complete', result.get('errors')
                )
                emulation = coverage.get('emulation', {})
                self.assertGreater(emulation.get('api_attempts', 0), 0, result.get('errors'))
                self.assertNotEqual(
                    emulation.get('termination_reason'), 'backend_error', result.get('errors')
                )
                self.assertTrue(result['signature_policy']['signature_free'])
        finally:
            scanner.close()

    def test_extracted_pe_runs_learned_analysis_without_response_authority(self):
        import hashlib
        import tempfile
        from pathlib import Path
        import zipfile
        from sentinelav.lab.advanced_check import exit_fixture
        from sentinelav.detection.engine import Scanner

        raw = exit_fixture()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'inert.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('inert.exe', raw)
            scanner = Scanner(
                RESOURCE_ROOT / 'signatures.json',
                RESOURCE_ROOT / 'rules',
                options=dict(signature_free=True, model=True, neural=True),
            )
            result = scanner.scan([path], lambda: False, lambda *a: None)
            rows = result.get('embedded_model_analysis', [])
            self.assertTrue(rows, result['errors'])
            self.assertEqual(rows[0]['member_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(rows[0]['coverage']['model']['status'], 'Complete')
            self.assertFalse(rows[0]['automatic_response_eligible'])

    def test_installed_model_is_signed_and_tampering_rejected(self):
        from sentinelav.updates.artifacts import active

        model, _ = active(
            RESOURCE_ROOT / 'analysis-data', RESOURCE_ROOT / 'trusted-update-keys.json', 'model'
        )
        if model.get('algorithm') != 'lightgbm-pe-ensemble-v1':
            self.skipTest('Different model active')
        validate(model)
        self.assertEqual(set(model['members']), {'PE', 'Win32', 'Win64', 'Dot_Net'})
        altered = copy.deepcopy(model)
        altered['members']['PE']['model_text'] += 'tampering'
        with self.assertRaises(ValueError):
            validate(altered)


@unittest.skipUnless(
    (RESOURCE_ROOT / 'analysis-data/malconv2-state.npz').exists(), 'Neural weights not installed'
)
class NeuralModelTests(unittest.TestCase):
    def test_chunking_does_not_change_logits(self):
        import numpy as np
        from sentinelav.detection.neural_bytes import logits, weights, predict

        data = bytes(range(256)) * 13
        state = weights()
        np.testing.assert_allclose(
            logits(data, state, 3), logits(data, state, 4096), atol=1e-4, rtol=1e-4
        )
        output = predict(data)
        self.assertEqual(output['bytes_examined'], len(data))
        self.assertFalse(output['automatic_response_eligible'])

    @unittest.skipUnless(
        importlib.util.find_spec('torch'), 'Optional reference runtime not installed'
    )
    def test_numpy_matches_pytorch_network(self):
        import numpy as np
        import torch
        import torch.nn.functional as f
        from sentinelav.detection.neural_bytes import weights, logits

        data = bytes(range(256)) * 13
        state = weights()
        s = {k: torch.from_numpy(v) for k, v in state.items()}
        torch.set_num_threads(2)
        tokens = torch.from_numpy(
            np.frombuffer(data, dtype=np.uint8).astype(np.int64) + 1
        ).unsqueeze(0)
        with torch.inference_mode():

            def feature(prefix, share):
                x = f.embedding(tokens, s[prefix + 'embd.weight']).transpose(1, 2)
                x = f.glu(
                    f.conv1d(
                        x, s[prefix + 'convs.0.weight'], s[prefix + 'convs.0.bias'], stride=64
                    ),
                    dim=1,
                )
                return f.leaky_relu(f.conv1d(x, s[share + 'weight'], s[share + 'bias']))

            context = feature('context_net.', 'context_net.convs_1.0.').amax(dim=2)
            x = feature('', 'convs_share.0.')
            gate = torch.tanh(
                f.linear(context, s['linear_atn.0.weight'], s['linear_atn.0.bias'])
            ).unsqueeze(2)
            x = (x * torch.sigmoid(f.conv1d(x, gate))).amax(dim=2)
            output = f.linear(
                f.leaky_relu(f.linear(x, s['fc_1.weight'], s['fc_1.bias'])),
                s['fc_2.weight'],
                s['fc_2.bias'],
            )
        np.testing.assert_allclose(logits(data, state), output.numpy()[0], atol=1e-4, rtol=1e-4)
