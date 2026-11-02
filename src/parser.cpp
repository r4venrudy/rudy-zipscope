#include "zipscope/parser.hpp"
#include "zipscope/bytes.hpp"
#include "zipscope/extra.hpp"
#include "zipscope/hash.hpp"
#include <algorithm>
namespace zs {
Directory directory(Bytes b){
 if(b.size()<22)throw Error("EOCD_MISSING",b.size());
 const auto lower=b.size()>65557?b.size()-65557:0;std::uint64_t found=0;unsigned matches=0;
 for(std::size_t p=b.size()-22;;--p){if(u32(b,p)==0x06054b50 && p+22+u16(b,p+20)==b.size()){found=p;matches++;}if(p==lower)break;}
 if(matches!=1)throw Error(matches?"EOCD_AMBIGUOUS":"EOCD_MISSING",b.size());
 if(u16(b,found+4)||u16(b,found+6)||u16(b,found+8)!=u16(b,found+10))throw Error("MULTI_DISK",found);
 Directory d;d.eocd=found;d.end=found;d.count=u16(b,found+10);d.size=u32(b,found+12);d.start=u32(b,found+16);
 if(d.count==0xffff||d.size==0xffffffff||d.start==0xffffffff){
  if(found<20||u32(b,found-20)!=0x07064b50)throw Error("ZIP64_LOCATOR",found);
  auto locator=found-20;if(u32(b,locator+4)||u32(b,locator+16)!=1)throw Error("MULTI_DISK",locator);
  auto z=u64(b,locator+8);slice(b,z,56);if(u32(b,z)!=0x06064b50)throw Error("ZIP64_END",z);
  auto size=u64(b,z+4);if(size<44||size>1048576||z>locator||size+12!=locator-z)throw Error("ZIP64_END_RANGE",z);
  if(u32(b,z+16)||u32(b,z+20)||u64(b,z+24)!=u64(b,z+32))throw Error("MULTI_DISK",z);
  auto count=u64(b,z+32),length=u64(b,z+40),start=u64(b,z+48);
  if((d.count!=0xffff&&d.count!=count)||(d.size!=0xffffffff&&d.size!=length)||(d.start!=0xffffffff&&d.start!=start))throw Error("ZIP64_END_DISAGREEMENT",found);
  d.count=count;d.size=length;d.start=start;d.zip64=true;d.end=z;
 }
 if(d.start>d.end||d.size>d.end-d.start)throw Error("DIRECTORY_RANGE",d.start);
 return d;
}
std::vector<Entry> central(Bytes b,const Directory&d,const Limits&limits){
 if(d.count>limits.entries)throw Error("ENTRY_LIMIT",d.start);
 auto end=d.start+d.size,p=d.start;std::vector<Entry> out;
 for(std::uint64_t i=0;i<d.count;i++){
  slice(b,p,46);if(p>end||46>end-p||u32(b,p)!=0x02014b50)throw Error("CENTRAL_HEADER",p);
  Entry e;e.made_by=u16(b,p+4);e.needed=u16(b,p+6);e.flags=u16(b,p+8);e.method=u16(b,p+10);e.crc=u32(b,p+16);e.compressed=u32(b,p+20);e.size=u32(b,p+24);e.attrs=u32(b,p+38);e.local=u32(b,p+42);
  auto n=u16(b,p+28),x=u16(b,p+30),c=u16(b,p+32);auto tail=static_cast<std::uint64_t>(n)+x+c;
  if(n==0||n>4096||tail>end-p-46)throw Error("CENTRAL_FIELDS",p);
  if(u16(b,p+34))throw Error("MULTI_DISK",p);
  e.name=raw(slice(b,p+46,n));auto extra=slice(b,p+46+n,x);e.extra.assign(extra.begin(),extra.end());
  zip64_values(e);out.push_back(std::move(e));p+=46+tail;
 }
 if(p!=end)throw Error("CENTRAL_SIZE_DISAGREEMENT",p);
 return out;
}
void local(Bytes b,Entry&e){
 auto p=e.local;slice(b,p,30);if(u32(b,p)!=0x04034b50)throw Error("LOCAL_HEADER",p);
 if(u16(b,p+4)!=e.needed||u16(b,p+6)!=e.flags||u16(b,p+8)!=e.method)throw Error("HEADER_DISAGREEMENT",p);
 auto n=u16(b,p+26),x=u16(b,p+28);if(n==0||n>4096)throw Error("LOCAL_NAME_LIMIT",p);
 e.local_name=raw(slice(b,p+30,n));auto extra=slice(b,p+30+n,x);e.local_extra.assign(extra.begin(),extra.end());extras(e.local_extra);
 e.data=p+30+n+x;slice(b,e.data,e.compressed);e.end=e.data+e.compressed;
 auto compressed=static_cast<std::uint64_t>(u32(b,p+18)),size=static_cast<std::uint64_t>(u32(b,p+22));
 if(size==0xffffffff||compressed==0xffffffff){auto fields=extras(e.local_extra);if(!fields.contains(1))throw Error("LOCAL_ZIP64_MISSING",p);auto z=fields.at(1);std::uint64_t q=0;if(size==0xffffffff){size=u64(z,q);q+=8;}if(compressed==0xffffffff)compressed=u64(z,q);}
 if(!(e.flags&8)&&(u32(b,p+14)!=e.crc||compressed!=e.compressed||size!=e.size))throw Error("LOCAL_SIZE_OR_CRC",p);
 if((e.flags&8)&&((u32(b,p+14)!=0&&u32(b,p+14)!=e.crc)||(compressed!=0&&compressed!=e.compressed)||(size!=0&&size!=e.size)))throw Error("DESCRIPTOR_PLACEHOLDER",p);
}
void descriptor(Bytes b,Entry&e){
 if(!(e.flags&8))return;
 // Some producers use 64-bit descriptors with small ZIP64 entries. Try all
 // bounded layouts, require exactly one complete match and preserve ambiguity.
 std::vector<std::uint64_t> matches;
 for(bool signature:{false,true})for(bool wide:{false,true}){
  auto p=e.end;auto length=static_cast<std::uint64_t>((signature?4:0)+(wide?20:12));
  if(p>b.size()||length>b.size()-p)continue;
  if(signature){if(u32(b,p)!=0x08074b50)continue;p+=4;}
  if(u32(b,p)!=e.crc)continue;p+=4;
  auto compressed=wide?u64(b,p):u32(b,p);p+=wide?8:4;auto size=wide?u64(b,p):u32(b,p);
  if(compressed==e.compressed&&size==e.size)matches.push_back(e.end+length);
 }
 if(matches.size()!=1)throw Error(matches.empty()?"DESCRIPTOR_MISMATCH":"DESCRIPTOR_AMBIGUOUS",e.end);
 e.end=matches[0];
}
Report analyze(Bytes b,const Limits&limits){
 Report r;r.sha256=sha256(b);
 try{
  if(b.size()>limits.input)throw Error("INPUT_LIMIT",0);
  r.directory=directory(b);r.entries=central(b,r.directory,limits);
  for(std::size_t i=0;i<r.entries.size();i++){auto&e=r.entries[i];local(b,e);descriptor(b,e);if(e.name!=e.local_name)r.findings.push_back({"NAME_DISAGREEMENT",i+1,"error"});}
  std::vector<const Entry*> order;for(const auto&e:r.entries)order.push_back(&e);
  std::sort(order.begin(),order.end(),[](auto a,auto c){return a->local<c->local;});std::uint64_t cursor=0;
  for(auto e:order){if(e->local<cursor||e->end>r.directory.start)throw Error("RECORD_OVERLAP",e->local);if(e->local>cursor)r.gaps.push_back({cursor,e->local,sha256(slice(b,cursor,e->local-cursor))});cursor=e->end;}
  if(cursor<r.directory.start)r.gaps.push_back({cursor,r.directory.start,sha256(slice(b,cursor,r.directory.start-cursor))});
  auto central_end=r.directory.start+r.directory.size;if(central_end<r.directory.end)r.gaps.push_back({central_end,r.directory.end,sha256(slice(b,central_end,r.directory.end-central_end))});
  if(!r.gaps.empty())r.findings.push_back({"UNREFERENCED_BYTES",0,"warning"});
  r.complete=true;
 }catch(const Error&e){r.stop_code=e.code;r.stop_offset=e.offset;}
 return r;
}
}
