import json, os, unittest
from unittest.mock import patch
from urllib.error import HTTPError
from backend.core import ROOT, analyze
try:
    from apig_sdk import signer
except ImportError:
    signer=None

class IAMTransportTests(unittest.TestCase):
    @unittest.skipIf(signer is None, "Install the official Huawei API signing SDK for IAM signature tests")
    def test_wire_signature_matches_query_and_body(self):
        env={'AGENTARTS_AUTH_MODE':'iam','AGENTARTS_APP_MODE':'lowcode',
             'AGENTARTS_REGION':'cn-southwest-2','HUAWEICLOUD_SDK_AK':'TEST_AK',
             'HUAWEICLOUD_SDK_SK':'TEST_SK',
             'AGENTARTS_INVOKE_URL':'https://test.cn-southwest-2.huaweicloud-agentarts.com/runtimes/agent-test/invocations?endpoint=Latest'}
        data=json.loads((ROOT/'samples/demo.json').read_text(encoding='utf-8'))
        captured=[]
        def intercept(req, timeout):
            captured.append(req)
            headers=dict(req.header_items())
            auth=next(v for k,v in headers.items() if k.lower()=='authorization')
            headers={k:v for k,v in headers.items() if k.lower()!='authorization'}
            sig=signer.Signer(algorithm='V11-HMAC-SHA256',region_id='cn-southwest-2')
            sig.Key='TEST_AK'; sig.Secret='TEST_SK'
            wire=signer.HttpRequest('POST',req.full_url,headers,req.data.decode('utf-8'))
            self.assertTrue(sig.Verify(wire,auth))
            self.assertIn('endpoint=Latest',req.full_url)
            prompt=json.loads(json.loads(req.data)['query'])
            self.assertEqual(len(prompt['findings']),3)
            self.assertTrue(all(f['evidence'] is not None for f in prompt['findings']))
            raise HTTPError(req.full_url,403,'synthetic denial',{},None)
        with patch.dict(os.environ,env,clear=True), patch('backend.core.build_opener') as opener:
            opener.return_value.open.side_effect=intercept
            with self.assertRaisesRegex(ValueError,'HTTP 403'):
                analyze(data,cloud=True,consent=True)
        self.assertEqual(len(captured),1)

    def test_missing_iam_credentials_stops_before_transport(self):
        with patch.dict(os.environ,{'AGENTARTS_AUTH_MODE':'iam','AGENTARTS_INVOKE_URL':'https://test.huaweicloud.com'},clear=True), patch('backend.core.build_opener') as opener:
            with self.assertRaisesRegex(ValueError,'缺少'):
                analyze(json.loads((ROOT/'samples/demo.json').read_text(encoding='utf-8')),True,True)
            opener.assert_not_called()
