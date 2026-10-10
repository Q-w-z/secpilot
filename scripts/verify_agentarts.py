"""Requires a real configured high-code runtime. Never uses a fake endpoint."""
import sys,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.core import ROOT,analyze
try:
    run=analyze(json.loads((ROOT/'samples/demo.json').read_text(encoding='utf-8')),cloud=True,consent=True)
    (ROOT/'evidence/agentarts_latest_report.json').write_text(json.dumps(run,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(run['cloud_receipt'],ensure_ascii=False))
except Exception as e:
    (ROOT/'evidence/agentarts_status.json').write_text(json.dumps({'status':'NOT_CONNECTED','reason':str(e),'cloud_call_succeeded':False},ensure_ascii=False,indent=2),encoding='utf-8')
    print('NOT_CONNECTED: '+str(e));sys.exit(2)
