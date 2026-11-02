#include "zipscope/names.hpp"
namespace zs {
bool utf8(const std::string&s){
 std::size_t p=0;while(p<s.size()){
  auto c=static_cast<unsigned char>(s[p++]);if(c<0x80){if(c<32||c==127)return false;continue;}
  unsigned n=0;std::uint32_t value=0,minimum=0;
  if(c>=0xc2&&c<=0xdf){n=1;value=c&31;minimum=0x80;}else if(c>=0xe0&&c<=0xef){n=2;value=c&15;minimum=0x800;}else if(c>=0xf0&&c<=0xf4){n=3;value=c&7;minimum=0x10000;}else return false;
  if(n>s.size()-p)return false;while(n--){auto d=static_cast<unsigned char>(s[p++]);if((d&0xc0)!=0x80)return false;value=(value<<6)|(d&63);}
  if(value<minimum||value>0x10ffff||(value>=0xd800&&value<=0xdfff)||(value>=0x80&&value<=0x9f))return false;
 }
 return true;
}
void names(Report&r){for(std::size_t i=0;i<r.entries.size();i++){const auto&e=r.entries[i];for(const auto* name:{&e.name,&e.local_name}){if(!utf8(*name))throw Error("INVALID_NAME_ENCODING",e.local);if(!(e.flags&0x800))for(char c:*name)if(static_cast<unsigned char>(c)>=128)throw Error("LEGACY_NAME_ENCODING",e.local);}}}
}
