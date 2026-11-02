"""Installed command contracts, report privacy, comparison gates and source preservation."""
from pathlib import Path
import importlib.util,json,os,subprocess,sys,tempfile
sys.dont_write_bytecode=True
binary=Path(sys.argv[1]).resolve();source=Path(sys.argv[2]).resolve();checks=0
def expect(value,why):
    global checks
    checks+=1
    if not value:raise AssertionError(why)
def run(*args,code=0):
    r=subprocess.run([binary,*map(str,args)],capture_output=True,encoding='utf-8',timeout=30)
    expect(r.returncode==code,str(r.returncode)+' '+r.stderr+r.stdout[-200:]);return r.stdout
spec=importlib.util.spec_from_file_location('fixture',source/'examples/make_archives.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
with tempfile.TemporaryDirectory(prefix='ZipScope installed space ') as tmp:
    root=Path(tmp);fixture.create(root/'fixtures');f=root/'fixtures';good=f/'stored.zip';before=good.read_bytes()
    expect(run('--version').strip()=='zipscope 0.1.0-preview','version');expect('No extraction' in run('--help'),'help')
    for format in ['text','json','html','sarif']:
        text=run('inspect',good,'--format',format);expect('safe.txt' not in text and 'invented payload' not in text,'private default '+format)
    expect('safe.txt' in run('inspect',good,'--format','json','--show-names'),'explicit names')
    r=json.loads(run('compare',good,f/'deflated.zip'));expect(r['comparable'] and r['manifestEqual'] is True and not r['differences'],'recompression manifest equality')
    r=json.loads(run('compare',good,f/'changed.zip',code=1));expect(r['comparable'] and r['manifestEqual'] is False and r['differences'][0]['change']=='modified','changed payload')
    r=json.loads(run('compare',good,f/'added.zip',code=1));expect(len(r['differences'])==1 and r['differences'][0]['change']=='added','added member')
    for bad in ['truncated.zip','crc-mismatch.zip','local-disagreement.zip','collision.zip']:
        r=json.loads(run('compare',good,f/bad,'--fail-on','none',code=2));expect(not r['comparable'] and r['manifestEqual'] is None,'unsafe/incomplete comparison unavailable')
    for flag,value in [('--max-total-mib','0'),('--max-entry-mib','0'),('--max-entries','1')]:
        r=json.loads(run('inspect',good,flag,value,'--format','json',code=2));expect(not r['complete'],'budget never clear')
    run('inspect',f/'traversal.zip','--fail-on','none');run('inspect',f/'trailing.zip','--fail-on','error')
    report=root/'r\u00e9sum\u00e9 space.json';expect(run('inspect',good,'--format','json','--output',report)=='','file output');saved=report.read_bytes();expect(json.loads(saved)['complete'],'Unicode destination')
    run('inspect',good,'--output',report,code=2);expect(report.read_bytes()==saved,'never replace report')
    run('inspect',good,'--output',good,code=2);expect(good.read_bytes()==before,'never replace source')
    copy=root/'archive \u00e9.zip';copy.write_bytes(before);expect(json.loads(run('inspect',copy,'--format','json'))['complete'],'Unicode input')
    if os.name!='nt':expect(report.stat().st_mode&0o077==0,'private POSIX output')
    html=run('inspect',f/'markup-name.zip','--show-names','--format','html',code=1);expect('&lt;img&gt;.txt' in html and '<script' not in html and 'Content-Security-Policy' in html,'encoded HTML names')
    sarif=json.loads(run('inspect',f/'traversal.zip','--format','sarif',code=1));expect(sarif['version']=='2.1.0' and sarif['runs'][0]['results'],'SARIF findings')
    sarif=json.loads(run('inspect',f/'truncated.zip','--format','sarif',code=2));expect(not sarif['runs'][0]['invocations'][0]['executionSuccessful'],'SARIF incomplete')
    for args in [('--unknown',),('--format','bogus'),('--format','json','--format','text'),('--output',),('--max-entries','0'),('--max-input-mib','1025'),('--max-entry-mib','-1'),('--max-total-mib','2049'),('--fail-on','changed')]:run('inspect',good,*args,code=2)
    run('compare',good,good,'--format','html',code=2);run('compare',good,good,'--fail-on','error',code=2);run('inspect',root/'missing.zip',code=2)
    expect(set(p.name for p in root.iterdir())=={'fixtures',report.name,copy.name},'no archive extraction or side files')
print('Independent installed-command checks passed:',checks)
