import unittest,json,os,threading
from unittest.mock import patch
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from backend.core import ROOT,analyze,parse_report,clean_path,validate_cloud_output,markdown_report
from backend.server import Handler,TOKEN

class CoreTests(unittest.TestCase):
    def setUp(self): self.data=json.loads((ROOT/'samples/demo.json').read_text(encoding='utf-8'))
    def test_dedup_and_sources(self):
        r=analyze(self.data);self.assertEqual(r['stats'],{'raw':5,'unique':4,'removed_duplicates':1,'evidence_valid':3});self.assertEqual(len(r['findings'][0]['sources']),2)
    def test_missing_evidence_refused(self): self.assertEqual(analyze(self.data)['findings'][-1]['provider'],'evidence_refusal')
    def test_source_line_mapping(self): self.assertIn('SELECT',analyze(self.data)['findings'][0]['evidence'])
    def test_normal_empty_report(self): self.assertEqual(analyze({'findings':[]})['stats']['unique'],0)
    def test_local_is_template(self): self.assertEqual(analyze(self.data)['findings'][0]['provider'],'offline_template')
    def test_path_traversal(self):
        for p in ['../demo.py','/demo.py','C:/secret','a/../../secret']:
            with self.assertRaises(ValueError): clean_path(p)
    def test_invalid_line(self):
        self.data['findings'][0]['line']=False
        with self.assertRaises(ValueError): analyze(self.data)
    def test_upload_limit_count(self):
        with self.assertRaises(ValueError): parse_report({'findings':[{}]*501})
    def test_sarif(self):
        r={'version':'2.1.0','runs':[{'tool':{'driver':{'name':'TestSARIF','rules':[{'id':'sql','properties':{'tags':['external/cwe/CWE-89']}}]}},'results':[{'ruleId':'sql','level':'error','message':{'text':'test'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'demo.py'},'region':{'startLine':3}}}]}]}]}
        x=analyze(r)['findings'][0];self.assertEqual(x['category'],'CWE-89');self.assertEqual(x['severity'],'high')
    def test_cloud_requires_consent(self):
        with self.assertRaisesRegex(ValueError,'显式'): analyze(self.data,True,False)
    def test_cloud_missing_config_fails(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(ValueError,'缺少'): analyze(self.data,True,True)
    def test_cloud_evidence_mutation_rejected(self):
        fs=analyze(self.data)['findings'];xs=[{**f,'explanation':'test','fix':'test','verification':'test'} for f in fs if f['evidence'] is not None];xs[0]['line']=99
        with self.assertRaisesRegex(ValueError,'修改'):validate_cloud_output({'explanations':xs},fs)
    def test_cloud_missing_item_rejected(self):
        with self.assertRaisesRegex(ValueError,'缺少'):validate_cloud_output({'explanations':[]},analyze(self.data)['findings'])
    def test_export_reflects_review(self):
        r=analyze(self.data);r['findings'][0]['review']='false_positive';self.assertIn('false_positive',markdown_report(r))

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s=ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.t=threading.Thread(target=cls.s.serve_forever,daemon=True);cls.t.start();cls.url=f'http://127.0.0.1:{cls.s.server_port}'
    @classmethod
    def tearDownClass(cls): cls.s.shutdown();cls.s.server_close()
    def request(self,path,body=None,token=TOKEN):
        req=Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-SecPilot-Token':token})
        with urlopen(req) as r:return json.loads(r.read())
    def test_health_and_ui(self):
        self.assertEqual(self.request('/api/health')['status'],'ok')
        with urlopen(self.url) as r:self.assertIn('SecPilot',r.read().decode())
    def test_end_to_end_review_export(self):
        r=self.request('/api/analyze',{'report':self.request('/api/sample')});fid=r['findings'][0]['id']
        r=self.request('/api/review',{'run_id':r['run_id'],'id':fid,'status':'confirmed'})
        e=self.request('/api/export?run_id='+r['run_id']);self.assertEqual(e['findings'][0]['review'],'confirmed');self.assertEqual(len(e['findings'][0]['history']),1)
    def test_invalid_token(self):
        with self.assertRaises(HTTPError) as c:self.request('/api/analyze',{},token='wrong')
        self.assertEqual(c.exception.code,403)
    def test_malformed_report(self):
        with self.assertRaises(HTTPError) as c:self.request('/api/analyze',{'report':[]})
        self.assertEqual(c.exception.code,400)

if __name__=='__main__':unittest.main()
