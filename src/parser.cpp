#include "zipscope/parser.hpp"
#include "zipscope/bytes.hpp"
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
}
