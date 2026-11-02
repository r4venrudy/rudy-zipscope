"""Verify an installed layout and build a controlled native release archive."""
from pathlib import Path
import argparse,importlib.util,json,os,subprocess,sys,tarfile,zipfile
sys.dont_write_bytecode=True
p=argparse.ArgumentParser(description=__doc__);p.add_argument('stage',type=Path);p.add_argument('target',choices=['linux-x64','windows-x64','macos-arm64']);p.add_argument('--version',required=True);args=p.parse_args()
assert args.version=='0.1.0-preview','Tag version must match the source preview'
source=Path(__file__).resolve().parents[1];stage=args.stage.resolve();binary=stage/'bin'/('zipscope.exe' if os.name=='nt' else 'zipscope')
def run(*arguments,code=0):
    r=subprocess.run([binary,*map(str,arguments)],capture_output=True,encoding='utf-8',timeout=40)
    assert r.returncode==code,r.stdout+r.stderr
    return r.stdout
assert run('--version').strip()=='zipscope '+args.version
spec=importlib.util.spec_from_file_location('fixtures',source/'examples/make_archives.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
capture=stage/'examples/synthetic';fixture.create(capture)
report=json.loads(run('inspect',capture/'stored.zip','--format','json'));comparison=json.loads(run('compare',capture/'stored.zip',capture/'deflated.zip'))
assert report['complete'] and comparison['comparable'] and comparison['manifestEqual']
(capture/'inspection.json').write_bytes((json.dumps(report,indent=2)+'\n').encode());(capture/'comparison.json').write_bytes((json.dumps(comparison,indent=2)+'\n').encode())
run('inspect',capture/'local-disagreement.zip','--format','html','--output',capture/'investigation.html',code=1)
run('inspect',capture/'traversal.zip','--format','sarif','--output',capture/'policy.sarif',code=1)
dest=source/'dist';dest.mkdir(exist_ok=True);archive=dest/('zipscope-'+args.version+'-'+args.target+('.zip' if args.target=='windows-x64' else '.tar.gz'));files=sorted(stage.rglob('*'))
assert all(not file.is_symlink() for file in files)
if archive.suffix=='.zip':
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as output:
        for file in files:output.write(file,file.relative_to(stage).as_posix())
else:
    with tarfile.open(archive,'x:gz') as output:
        for file in files:output.add(file,arcname=file.relative_to(stage).as_posix(),recursive=False)
print('Installed evidence and manifest witnesses passed:',archive.name)
