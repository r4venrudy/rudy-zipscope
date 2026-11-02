"""Build invented ZIP evidence; never extract or execute archive members."""
from pathlib import Path
import hashlib,io,json,stat,struct,warnings,zipfile,zlib

def archive(entries,method=0,streamed=False,zip64=False):
    class Stream(io.BytesIO):
        def seekable(self):return False
        def seek(self,*args):raise io.UnsupportedOperation('streaming fixture')
    output=Stream() if streamed else io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',UserWarning)
        with zipfile.ZipFile(output,'w',compression=method) as z:
            for name,content,mode,extra in entries:
                info=zipfile.ZipInfo(name,(2026,1,2,3,4,6));info.create_system=3;info.external_attr=mode<<16;info.compress_type=method;info.extra=extra
                if zip64:
                    with z.open(info,'w',force_zip64=True) as f:f.write(content)
                else:z.writestr(info,content)
    return output.getvalue()

def create(destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    base=[('safe.txt',b'invented payload',0o100644,b''),('folder/readme.txt',b'hello from RUDY\n',0o100644,b'')]
    samples={};expect={}
    def add(name,data,codes=(),stop=None):samples[name]=data;expect[name]=dict(codes=sorted(codes),complete=stop is None,stopCode=stop)
    stored=archive(base);add('stored',stored);add('deflated',archive(base,8));add('streamed',archive(base,8,streamed=True));add('local-zip64',archive(base,8,zip64=True))
    add('changed',archive([('safe.txt',b'changed payload',0o100644,b''),base[1]],8))
    add('added',archive(base+[('new.txt',b'new',0o100644,b'')],8));add('empty',archive([]))
    for name,path,code in [('traversal','../escape','PARENT_TRAVERSAL'),('absolute','/escape','ABSOLUTE_PATH'),('drive','C:/drive','DRIVE_OR_STREAM_PATH'),('device','AUX.txt','WINDOWS_DEVICE'),('trailing','trailing.','WINDOWS_TRAILING_CHARACTER')]:add(name,archive([(path,b'harmless fixture',0o100644,b'')]),[code])
    add('collision',archive([('One.txt',b'a',0o100644,b''),('one.txt',b'b',0o100644,b'')]),['PATH_COLLISION'])
    add('duplicate',archive([('same.txt',b'a',0o100644,b''),('same.txt',b'b',0o100644,b'')]),['PATH_COLLISION'])
    add('file-directory',archive([('file',b'a',0o100644,b''),('file/child',b'b',0o100644,b'')]),['FILE_DIRECTORY_CONFLICT'])
    add('link-escape',archive([('link',b'../escape',0o120777,b'')]),['LINK_TARGET_ESCAPE','SYMLINK_ENTRY'])
    add('link-cycle',archive([('a',b'b',0o120777,b''),('b',b'a',0o120777,b'')]),['LINK_CYCLE','SYMLINK_ENTRY'])
    add('unicode',archive([('caf\u00e9.txt',b'value',0o100644,b'')]),['UNICODE_PORTABILITY_UNMODELED'])
    alternative=b'../override';extra=struct.pack('<HHBI',0x7075,5+len(alternative),1,zlib.crc32(b'safe.txt'))+alternative
    add('unicode-override',archive([('safe.txt',b'value',0o100644,extra)]),['PARENT_TRAVERSAL','UNICODE_NAME_DISAGREEMENT'])
    raw=bytearray(stored);raw[30]=ord('X');add('local-disagreement',bytes(raw),['NAME_DISAGREEMENT'])
    raw=bytearray(stored);raw[38]^=1;add('crc-mismatch',bytes(raw),stop='CRC_MISMATCH')
    cd=stored.index(b'PK\x01\x02');raw=bytearray(stored);struct.pack_into('<H',raw,6,0x1);struct.pack_into('<H',raw,cd+8,0x1);add('encrypted-flag',bytes(raw),stop='UNSUPPORTED_FLAGS')
    raw=bytearray(stored);struct.pack_into('<H',raw,8,99);struct.pack_into('<H',raw,cd+10,99);add('unknown-method',bytes(raw),stop='UNSUPPORTED_METHOD')
    add('truncated',stored[:-8],stop='EOCD_MISSING')
    raw=bytearray(stored);struct.pack_into('<H',raw,len(raw)-2,22);raw+=struct.pack('<IHHHHIIH',0x06054b50,0,0,0,0,0,0,0);add('ambiguous-footer',bytes(raw),stop='EOCD_AMBIGUOUS')
    raw=bytearray(stored);footer=raw[-22:];raw=raw[:-22];z=len(raw);count,size,start=struct.unpack_from('<HII',footer,10)
    raw+=struct.pack('<IQHHIIQQQQ',0x06064b50,44,45,45,0,0,count,count,size,start)+struct.pack('<IIQI',0x07064b50,0,z,1)
    struct.pack_into('<HHII',footer,8,0xffff,0xffff,0xffffffff,0xffffffff);raw+=footer;add('zip64-footer',bytes(raw))
    add('high-ratio',archive([('repeat.txt',b'a'*(2*1024*1024),0o100644,b'')],8),['HIGH_EXPANSION_RATIO'])
    add('markup-name',archive([('<img>.txt',b'private body canary',0o100644,b'')]),['WINDOWS_INVALID_CHARACTER'])
    for name,data in samples.items():
        (destination/(name+'.zip')).write_bytes(data);expect[name]['sha256']=hashlib.sha256(data).hexdigest()
        if not expect[name]['codes'] and expect[name]['complete']:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                expect[name]['entries']=[dict(name=m.filename,size=m.file_size,sha256=hashlib.sha256(z.read(m)).hexdigest(),local=m.header_offset) for m in z.infolist()]
    (destination/'expected.json').write_bytes((json.dumps(expect,indent=2)+'\n').encode())
    return expect
if __name__=='__main__':
    import sys
    if len(sys.argv)!=2:raise SystemExit('usage: make_archives.py NEW_DIRECTORY')
    create(sys.argv[1])
