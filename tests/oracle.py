"""Differential archive reader oracle: Python zipfile/hashlib versus installed C++."""
from pathlib import Path
import hashlib,importlib.util,io,json,random,subprocess,sys,tempfile
sys.dont_write_bytecode=True
binary=Path(sys.argv[1]).resolve();source=Path(sys.argv[2]).resolve();checks=0
def expect(value,message):
    global checks
    checks+=1
    if not value:raise AssertionError(message)
def run(path,code=0):
    r=subprocess.run([binary,'inspect',path,'--format','json'],capture_output=True,encoding='utf-8',timeout=30)
    expect(r.returncode==code,str(r.returncode)+' '+r.stderr+r.stdout[-200:]);return json.loads(r.stdout)
spec=importlib.util.spec_from_file_location('synthetic',source/'examples/make_archives.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
with tempfile.TemporaryDirectory(prefix='zipscope oracle ') as tmp:
    root=Path(tmp);expected=fixture.create(root/'fixtures')
    for name,oracle in expected.items():
        path=root/'fixtures'/(name+'.zip');report=run(path,2 if not oracle['complete'] else 1 if oracle['codes'] else 0)
        expect(report['complete']==oracle['complete'] and report['stopCode']==oracle['stopCode'],'completion oracle '+name)
        expect(report['sourceSha256']==oracle['sha256'],'file digest '+name)
        expect(sorted({f['code'] for f in report['findings']})==oracle['codes'],'policy oracle '+name+' '+str(report['findings']))
        for entry,wanted in zip(report['entries'],oracle.get('entries',[])):
            expect(entry['decodedBytes']==wanted['size'] and entry['decodedSha256']==wanted['sha256'] and entry['verified'],'payload oracle '+name)
            expect(entry['localOffset']==wanted['local'],'independent byte position')
    randomizer=random.Random(44291)
    for trial in range(384):
        rows=[]
        for i in range(randomizer.randrange(1,7)):
            size=randomizer.randrange(0,4097);data=bytes(randomizer.randrange(256) for _ in range(size)) if i%2 else bytes([trial%256])*size
            rows.append((str(trial)+'/'+str(i)+'.bin',data,0o100644,b''))
        method=8 if trial%2 else 0
        data=fixture.archive(rows,method,streamed=trial%5==0,zip64=trial%7==0 and trial%5!=0)
        path=root/'random.zip';path.write_bytes(data);report=run(path)
        expect(report['complete'] and len(report['entries'])==len(rows),'generated count')
        expect(report['sourceSha256']==hashlib.sha256(data).hexdigest(),'generated source hash')
        for entry,(name,body,mode,_) in zip(report['entries'],rows):
            expect(entry['centralName']['sha256']==hashlib.sha256(name.encode()).hexdigest(),'name bytes identity')
            expect(entry['decodedSha256']==hashlib.sha256(body).hexdigest() and entry['decodedBytes']==len(body),'independent decoded body')
            expect(entry['attributes']==mode<<16,'exact metadata')
            expect(entry['method']==method and entry['verified'],'method and integrity')
print('Independent binary-oracle checks passed:',checks,'; generated archives:',384)
