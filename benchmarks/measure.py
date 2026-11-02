"""Measure the installed command on a reproducible bounded synthetic workload."""
from pathlib import Path
import importlib.util,json,platform,statistics,subprocess,sys,tempfile,time
sys.dont_write_bytecode=True
binary=Path(sys.argv[1]).resolve();source=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture',source/'examples/make_archives.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
with tempfile.TemporaryDirectory(prefix='zipscope benchmark ') as tmp:
    root=Path(tmp);samples=[]
    for label,rows,method in [('stored',[(str(i)+'.bin',bytes([i])*16384,0o100644,b'') for i in range(64)],0),('deflated',[(str(i)+'.bin',bytes([i])*16384,0o100644,b'') for i in range(64)],8)]:
        path=root/(label+'.zip');data=fixture.archive(rows,method);path.write_bytes(data);elapsed=[];identity=None
        for trial in range(8):
            start=time.perf_counter();r=subprocess.run([binary,'inspect',path,'--format','json'],capture_output=True,encoding='utf-8',timeout=30);duration=time.perf_counter()-start
            assert r.returncode==0 and json.loads(r.stdout)['complete'];report=json.loads(r.stdout)
            if identity is None:identity=report
            else:assert report==identity,'nondeterministic semantic report'
            if trial>=3:elapsed.append(duration*1000)
        samples.append(dict(case=label,entries=len(rows),archiveBytes=len(data),decodedBytes=sum(len(row[1]) for row in rows),medianMilliseconds=statistics.median(elapsed),minMilliseconds=min(elapsed),measurements=len(elapsed),includesProcessStartup=True))
print(json.dumps(dict(schema='zipscope.benchmark.v1',platform=platform.platform(),toolVersion=subprocess.check_output([binary,'--version'],text=True).strip(),samples=samples),indent=2))
