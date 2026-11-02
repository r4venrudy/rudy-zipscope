#include "zipscope/content.hpp"
#include "zipscope/bytes.hpp"
#include "zipscope/hash.hpp"
#include "zlib/zlib.h"
#include <array>
#include <algorithm>
namespace zs {
void payload(Bytes b,Entry&e,const Limits&limits,std::uint64_t& total){
 if(e.size>limits.entry||total>limits.total||e.size>limits.total-total)throw Error("EXPANSION_LIMIT",e.data);
 auto input=slice(b,e.data,e.compressed);Sha256 hash;std::uint64_t produced=0;uLong crc=crc32(0,nullptr,0);
 auto host=e.made_by>>8;bool link=(host==3||host==19)&&((e.attrs>>16)&0170000U)==0120000U;
 auto accept=[&](Bytes bytes){if(produced>e.size||bytes.size()>e.size-produced)throw Error("SIZE_MISMATCH",e.data);produced+=bytes.size();hash.update(bytes);crc=crc32(crc,bytes.data(),static_cast<uInt>(bytes.size()));if(link&&e.prefix.size()<4096){auto count=std::min(bytes.size(),4096-e.prefix.size());e.prefix+=raw(bytes.first(count));}};
 if(e.method==0){if(e.compressed!=e.size)throw Error("STORED_SIZE",e.data);accept(input);}
 else if(e.method==8){
  z_stream stream{};if(inflateInit2(&stream,-15)!=Z_OK)throw Error("INFLATE_INIT",e.data);
  struct End {z_stream* stream;~End(){inflateEnd(stream);}} end{&stream};
  stream.next_in=const_cast<Bytef*>(input.data());stream.avail_in=static_cast<uInt>(input.size());std::array<std::uint8_t,32768> output{};
  for(;;){stream.next_out=output.data();stream.avail_out=static_cast<uInt>(output.size());auto before=stream.avail_in;auto code=inflate(&stream,Z_NO_FLUSH);auto count=output.size()-stream.avail_out;accept(Bytes(output.data(),count));
   if(code==Z_STREAM_END){if(stream.avail_in!=0)throw Error("DEFLATE_TRAILING_BYTES",e.data);break;}
   if(code!=Z_OK||(before==stream.avail_in&&count==0))throw Error("DEFLATE_INVALID",e.data);
  }
 }else throw Error("UNSUPPORTED_METHOD",e.local);
 if(produced!=e.size)throw Error("SIZE_MISMATCH",e.data);
 e.sha256=hash.finish();
 if(static_cast<std::uint32_t>(crc)!=e.crc)throw Error("CRC_MISMATCH",e.data);
 e.verified=true;total+=produced;
}
}
