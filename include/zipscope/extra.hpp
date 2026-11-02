#pragma once
#include "bytes.hpp"
#include <map>
namespace zs {
inline std::map<std::uint16_t,Bytes> extras(Bytes b){std::map<std::uint16_t,Bytes> out;std::uint64_t p=0;while(p<b.size()){auto id=u16(b,p),n=u16(b,p+2);auto value=slice(b,p+4,n);if(!out.emplace(id,value).second)throw Error("DUPLICATE_EXTRA",p);p+=4+n;}return out;}
inline void zip64_values(Entry&e){auto fields=extras(e.extra);bool needed=e.size==0xffffffff||e.compressed==0xffffffff||e.local==0xffffffff;if(!needed)return;if(!fields.contains(1))throw Error("ZIP64_EXTRA_MISSING",e.local);auto b=fields.at(1);std::uint64_t p=0;if(e.size==0xffffffff){e.size=u64(b,p);p+=8;}if(e.compressed==0xffffffff){e.compressed=u64(b,p);p+=8;}if(e.local==0xffffffff)e.local=u64(b,p);}
}
