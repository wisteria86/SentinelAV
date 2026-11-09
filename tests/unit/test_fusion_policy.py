# Purpose: Verify test fusion policy behavior using controlled fixtures.
# Works with: detection.decisions, detection.fusion
# Used by: unittest discovery

import unittest
from sentinelav.detection.decisions import Evidence,decide
from sentinelav.detection.fusion import gates


class FusionPolicyTests(unittest.TestCase):
    def policy(self):
        return dict(schema=1,algorithm='fusion-v1',model_sha256='a'*64,threshold=.999,
            evaluation=dict(benign=30000,false_actions=0,malware=1000,true_positives=950,
                raw_samples=200,raw_detected=180,families=20,manifest_sha256='b'*64))
    def model(self):return Evidence('model','statistical_classification','Model',details=dict(model_id='a'*64,calibrated_probability=True,model_score=.9999))
    def test_correlated_static_signals_do_not_confirm_model(self):
        result=decide([self.model(),Evidence('static','packing','High entropy'),Evidence('static','imports','API capabilities')],policy=self.policy())
        self.assertEqual(result['verdict'],'Review');self.assertFalse(result['automatic_response_eligible'])
    def test_independent_behavior_and_validated_gate_can_confirm(self):
        evidence=Evidence('behavior','observed_sequence','Verified process sequence',details=dict(verified_process_identity=True,independent_indicators=2))
        result=decide([self.model(),evidence],policy=self.policy())
        self.assertEqual(result['verdict'],'Detected');self.assertTrue(result['automatic_response_eligible'])
    def test_insufficient_benign_validation_does_not_authorize(self):
        policy=self.policy();policy['evaluation']['benign']=200
        result=decide([self.model(),Evidence('emulation','modeled_behavior_sequence','Modeled sequence')],policy=policy)
        self.assertFalse(result['automatic_response_eligible']);self.assertEqual(result['verdict'],'Review')
    def test_false_action_prevents_automatic_gate(self):
        policy=self.policy();policy['evaluation']['false_actions']=1
        self.assertFalse(gates(policy)['automatic'])
