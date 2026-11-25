# Purpose: Verify test analysis artifacts behavior using controlled fixtures.
# Works with: detection.advanced_pipeline, detection.anomaly_model, detection.classifier,
#   updates.analysis_trust, updates.artifacts
# Used by: tests.ui.verify_analysis_ui

import base64
import copy
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from sentinelav.detection.anomaly_model import FEATURES
from sentinelav.detection.classifier import train,predict
from sentinelav.detection.advanced_pipeline import AdvancedPipeline
from sentinelav.updates.artifacts import canonical,verify,activate,active
from sentinelav.updates.analysis_trust import update_pin
from tests.unit.test_anomaly_model import row


def signed(payload,kind,key,revision=1):
    now=int(time.time())
    manifest=dict(kind=kind,key_id='fixture',revision=revision,issued=now-10,expires=now+3600,
        payload_sha256=hashlib.sha256(canonical(payload)).hexdigest())
    return dict(schema=1,manifest=manifest,payload=payload,
        signature=base64.b64encode(key.sign(canonical(manifest))).decode())


def public_hex(key): return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()


def minimal_model():
    return dict(schema=1,algorithm='logistic-static-v1',features=list(FEATURES),bias=0,
        weights=[0]*len(FEATURES),center=[0]*len(FEATURES),scale=[1]*len(FEATURES),review_threshold=.6)


class ArtifactTests(unittest.TestCase):
    def test_signature_payload_expiry_and_unpinned_key_fail_closed(self):
        key=Ed25519PrivateKey.generate(); envelope=signed(minimal_model(),'model',key)
        trust=dict(keys={'fixture':public_hex(key)})
        self.assertEqual(verify(envelope,trust,'model'),minimal_model())
        tampered=copy.deepcopy(envelope); tampered['payload']['bias']=10
        with self.assertRaises(ValueError): verify(tampered,trust,'model')
        with self.assertRaises(ValueError): verify(envelope,{'keys':{}},'model')
        with self.assertRaises(ValueError): verify(envelope,trust,'model',now=envelope['manifest']['expires'])
        tampered=copy.deepcopy(envelope); tampered['manifest']['revision']=2
        with self.assertRaises(InvalidSignature): verify(tampered,trust,'model')

    def test_models_may_be_permanent_but_feeds_may_not(self):
        key=Ed25519PrivateKey.generate(); trust=dict(keys={'fixture':public_hex(key)})
        def permanent(payload,kind):
            manifest=dict(kind=kind,key_id='fixture',revision=1,issued=int(time.time())-10,expires=None,payload_sha256=hashlib.sha256(canonical(payload)).hexdigest())
            return dict(schema=1,manifest=manifest,payload=payload,signature=base64.b64encode(key.sign(canonical(manifest))).decode())
        envelope=permanent(minimal_model(),'model')
        self.assertEqual(verify(envelope,trust,'model',now=time.time()+50*365*86400),minimal_model())
        with self.assertRaises(ValueError): verify(permanent(dict(schema=1,entries=[]),'reputation'),trust,'reputation')

    def test_signed_invalid_model_does_not_replace_active_revision(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); key=Ed25519PrivateKey.generate()
            trust=root/'trust.json'; trust.write_text(json.dumps({'schema':1,'keys':{'fixture':public_hex(key)}}))
            candidate=root/'candidate.json'; candidate.write_text(json.dumps(signed(minimal_model(),'model',key)))
            activate(candidate,root/'store',trust,'model')
            previous=(root/'store/active.json').read_bytes()
            with self.assertRaises(ValueError): activate(candidate,root/'store',trust,'model')
            bad=minimal_model(); bad['scale'][0]=0
            candidate.write_text(json.dumps(signed(bad,'model',key,2)))
            with self.assertRaises(ValueError): activate(candidate,root/'store',trust,'model')
            self.assertEqual((root/'store/active.json').read_bytes(),previous)
            self.assertEqual(active(root/'store',trust,'model')[1]['revision'],1)

    def test_removing_pin_invalidates_cached_reputation_on_next_inspection(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); key=Ed25519PrivateKey.generate(); trust=root/'trust.json'
            update_pin(trust,'fixture',public_hex(key))
            data=b'Harmless reputation fixture'; sha=hashlib.sha256(data).hexdigest()
            payload=dict(schema=1,entries=[dict(kind='sha256',value=sha,verdict='malicious',source='Synthetic fixture',expires=int(time.time())+300)])
            candidate=root/'reputation.json'; candidate.write_text(json.dumps(signed(payload,'reputation',key)))
            activate(candidate,root/'store',trust,'reputation')
            pipeline=AdvancedPipeline(root/'store',dict(reputation=True,analysis_trust=str(trust),content=False,documents=False))
            def inspect(): return pipeline.inspect(data,root/'ordinary.txt',sha,{'signals':[]},{'format':'Other'},lambda *args:([],[],[]),lambda:False)
            self.assertEqual(inspect()['verdict'],'Review')
            update_pin(trust,'fixture',None)
            result=inspect()
            self.assertEqual(result['verdict'],'Indeterminate')
            self.assertFalse(result['evidence'])

    def test_classifier_learns_and_test_rows_do_not_change_fit(self):
        rows=[row(1,'train',0),row(2,'train',1),row(3,'train',4,'malware'),row(4,'train',5,'malware'),
              row(5,'calibration',0),row(6,'calibration',1),row(7,'test',2)]
        model=train(rows,epochs=100)
        self.assertLess(predict(model,rows[0]['features'])['model_score'],predict(model,rows[3]['features'])['model_score'])
        rows[-1]['features']={key:10000 for key in FEATURES}
        self.assertEqual(train(rows,epochs=100),model)
        self.assertFalse(predict(model,rows[3]['features'])['automatic_response_eligible'])
