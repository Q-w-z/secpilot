import sys,json,time,platform,unittest,io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.core import ROOT,analyze,markdown_report
stream=io.StringIO()
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
(ROOT/'evidence/tests.log').write_text(stream.getvalue(),encoding='utf-8')
data=json.loads((ROOT/'samples/demo.json').read_text(encoding='utf-8'))
start=time.perf_counter();run=analyze(data);elapsed=(time.perf_counter()-start)*1000
metrics={'dataset':'SYNTHETIC','raw_findings':5,'unique_findings':run['stats']['unique'],'dedup_removed':run['stats']['removed_duplicates'],'valid_evidence':run['stats']['evidence_valid'],'missing_evidence_refused':sum(f['provider']=='evidence_refusal' for f in run['findings']),
 'tests_run':result.testsRun,'tests_passed':result.testsRun-len(result.failures)-len(result.errors),'tests_failed':len(result.failures)+len(result.errors),
 'elapsed_ms_single_local_run':round(elapsed,3),'platform':platform.platform(),'python':sys.version.split()[0],
 'timestamp_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
 'limits':'仅5条人工构造告警和1个正常代码样本；正常样本为人工空报告；无真实扫描、无模型准确率、无云耗时或成本结论'}
(ROOT/'evidence/metrics.json').write_text(json.dumps(metrics,ensure_ascii=False,indent=2),encoding='utf-8')
(ROOT/'evidence/demo_report.json').write_text(json.dumps(run,ensure_ascii=False,indent=2),encoding='utf-8')
(ROOT/'evidence/demo_report.md').write_text(markdown_report(run),encoding='utf-8')
print(json.dumps(metrics,ensure_ascii=False,indent=2));sys.exit(bool(result.failures or result.errors))
