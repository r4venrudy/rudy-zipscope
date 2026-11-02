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
 if(d.count==0xffff||d.size==0xffffffff||d.start==0xffffffff)throw Error("ZIP64_REQUIRED",found);
 if(d.start>found||d.size>found-d.start)throw Error("DIRECTORY_RANGE",d.start);
 return d;
}
}
