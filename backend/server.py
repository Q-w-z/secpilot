import json, sqlite3, time, threading, secrets
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from .core import ROOT, analyze, markdown_report

TOKEN=secrets.token_urlsafe(24)
LOCK=threading.Lock()
def db():
    c=sqlite3.connect(ROOT/'evidence'/'runs.db')
    c.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
    return c
def save(run):
    with LOCK,db() as c: c.execute('INSERT OR REPLACE INTO runs VALUES (?,?)',(run['run_id'],json.dumps(run,ensure_ascii=False)))
def load(rid):
    with db() as c: row=c.execute('SELECT body FROM runs WHERE id=?',(rid,)).fetchone()
    if not row: raise ValueError('运行记录不存在')
    return json.loads(row[0])

class Handler(BaseHTTPRequestHandler):
    def send(self,status,data,ctype='application/json; charset=utf-8'):
        if not isinstance(data,(str,bytes)): data=json.dumps(data,ensure_ascii=False)
        if isinstance(data,str): data=data.encode('utf-8')
        self.send_response(status); self.send_header('Content-Type',ctype)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'")
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        p=urlparse(self.path)
        try:
            if p.path=='/api/health': return self.send(200,{'status':'ok','mode':'LOCAL_DEMO','cloud_configured':bool(__import__('os').environ.get('AGENTARTS_INVOKE_URL') and __import__('os').environ.get('AGENTARTS_API_KEY'))})
            if p.path=='/api/session': return self.send(200,{'token':TOKEN})
            if p.path=='/api/sample': return self.send(200,(ROOT/'samples'/'demo.json').read_bytes())
            if p.path=='/api/export':
                q=parse_qs(p.query); run=load(q.get('run_id',[''])[0])
                if q.get('format',['json'])[0]=='md': return self.send(200,markdown_report(run),'text/markdown; charset=utf-8')
                return self.send(200,run)
            files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
            if p.path in files:
                ct={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}
                return self.send(200,(ROOT/'frontend'/files[p.path]).read_bytes(),ct[p.path])
            self.send(404,{'error':'页面不存在'})
        except ValueError as e: self.send(400,{'error':str(e)})
    def do_POST(self):
        if self.headers.get('X-SecPilot-Token')!=TOKEN: return self.send(403,{'error':'无效本地会话令牌'})
        if not self.headers.get('Content-Type','').startswith('application/json'): return self.send(415,{'error':'只接受 JSON'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=2*1024*1024: return self.send(413,{'error':'请求不能为空或超过2MB'})
            body=json.loads(self.rfile.read(n))
            if self.path=='/api/analyze':
                if not isinstance(body,dict) or type(body.get('cloud',False)) is not bool or type(body.get('consent',False)) is not bool: raise ValueError('请求字段类型错误')
                run=analyze(body.get('report'),body.get('cloud',False),body.get('consent',False)); save(run); return self.send(200,run)
            if self.path=='/api/review':
                run=load(body['run_id'])
                if body.get('status') not in ['pending','confirmed','false_positive']: raise ValueError('审核状态无效')
                f=next((f for f in run['findings'] if f['id']==body.get('id')),None)
                if f is None: raise ValueError('告警不存在')
                f['history'].append({'from':f['review'],'to':body['status'],'at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
                f['review']=body['status']; save(run); return self.send(200,run)
            self.send(404,{'error':'接口不存在'})
        except (ValueError,KeyError,TypeError,AttributeError,IndexError) as e: self.send(400,{'error':str(e)[:200]})
        except Exception: self.send(500,{'error':'内部错误，未切换为本地成功'})
    def log_message(self,*args): pass

if __name__=='__main__':
    import argparse
    a=argparse.ArgumentParser(); a.add_argument('--port',type=int,default=8765); args=a.parse_args()
    print(f'SecPilot http://127.0.0.1:{args.port}',flush=True)
    ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
