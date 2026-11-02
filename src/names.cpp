#include "zipscope/names.hpp"
#include <algorithm>
#include <sstream>
#include <set>
#include <tuple>
#include <map>
#include "zipscope/extra.hpp"
#include "zlib/zlib.h"
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
void names(Report&r){for(std::size_t i=0;i<r.entries.size();i++){auto&e=r.entries[i];for(bool local:{false,true}){auto fields=extras(local?Bytes(e.local_extra):Bytes(e.extra));if(fields.contains(8))throw Error("EXTENDED_LANGUAGE_ENCODING",e.local);if(!fields.contains(0x7075))continue;auto field=fields.at(0x7075);const auto&original=local?e.local_name:e.name;if(field.size()<5||field[0]!=1||u32(field,1)!=static_cast<std::uint32_t>(crc32(0,reinterpret_cast<const Bytef*>(original.data()),static_cast<uInt>(original.size())))){r.findings.push_back({"UNICODE_EXTRA_INVALID",i+1,"warning"});continue;}auto alias=raw(field.subspan(5));if(!utf8(alias)||alias.empty())throw Error("UNICODE_EXTRA_ENCODING",e.local);if(alias!=original)r.findings.push_back({"UNICODE_NAME_DISAGREEMENT",i+1,"error"});e.aliases.push_back(std::move(alias));}
 std::vector<const std::string*> views{&e.name,&e.local_name};for(const auto&alias:e.aliases)views.push_back(&alias);for(const auto* name:views){
 if(!utf8(*name))throw Error("INVALID_NAME_ENCODING",e.local);if(!(e.flags&0x800))for(char c:*name)if(static_cast<unsigned char>(c)>=128)throw Error("LEGACY_NAME_ENCODING",e.local);
 auto path=*name;std::replace(path.begin(),path.end(),'\\','/');
 if(path.starts_with('/'))r.findings.push_back({"ABSOLUTE_PATH",i+1,"error"});
 std::istringstream parts(path);std::string part;while(std::getline(parts,part,'/'))if(part=="..")r.findings.push_back({"PARENT_TRAVERSAL",i+1,"error"});
 if(path.find(':')!=std::string::npos)r.findings.push_back({"DRIVE_OR_STREAM_PATH",i+1,"error"});
 if(normalized(path).empty())r.findings.push_back({"EMPTY_PATH",i+1,"error"});
 const std::set<std::string> devices{"con","prn","aux","nul","conin$","conout$","com1","com2","com3","com4","com5","com6","com7","com8","com9","lpt1","lpt2","lpt3","lpt4","lpt5","lpt6","lpt7","lpt8","lpt9"};
 std::istringstream windows(path);while(std::getline(windows,part,'/')){if(part.empty()||part=="."||part=="..")continue;auto stem=part.substr(0,part.find('.'));for(auto&c:stem)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');if(devices.contains(stem))r.findings.push_back({"WINDOWS_DEVICE",i+1,"error"});if(part.back()=='.'||part.back()==' ')r.findings.push_back({"WINDOWS_TRAILING_CHARACTER",i+1,"warning"});if(part.find_first_of("<>\"|?*")!=std::string::npos)r.findings.push_back({"WINDOWS_INVALID_CHARACTER",i+1,"warning"});}
 if(std::any_of(name->begin(),name->end(),[](char c){return static_cast<unsigned char>(c)>=128;}))r.findings.push_back({"UNICODE_PORTABILITY_UNMODELED",i+1,"warning"});
}}
 std::map<std::string,std::size_t> projected;
 for(std::size_t i=0;i<r.entries.size();i++){std::vector<const std::string*> views{&r.entries[i].name,&r.entries[i].local_name};for(const auto&alias:r.entries[i].aliases)views.push_back(&alias);for(const auto* name:views){auto key=normalized(*name);for(auto&c:key)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');auto [at,inserted]=projected.emplace(key,i);if(!inserted&&at->second!=i){r.findings.push_back({"PATH_COLLISION",i+1,"error"});r.findings.push_back({"PATH_COLLISION",at->second+1,"error"});}}}
 for(std::size_t i=0;i<r.entries.size();i++){auto&e=r.entries[i];auto host=e.made_by>>8;auto mode=(host==3||host==19)?(e.attrs>>16)&0170000U:0U;e.directory=e.name.ends_with('/')||mode==0040000U||(e.attrs&0x10);e.symlink=mode==0120000U;if(mode!=0&&mode!=0040000U&&mode!=0100000U&&mode!=0120000U)r.findings.push_back({"SPECIAL_FILE",i+1,"error"});if((e.name.ends_with('/')&&mode==0100000U)||(e.directory&&e.size!=0))r.findings.push_back({"TYPE_DISAGREEMENT",i+1,"error"});}
 for(const auto&[path,index]:projected){for(auto pos=path.find('/');pos!=std::string::npos;pos=path.find('/',pos+1)){auto it=projected.find(path.substr(0,pos));if(it!=projected.end()&&!r.entries[it->second].directory)r.findings.push_back({"FILE_DIRECTORY_CONFLICT",index+1,"error"});}}
 std::map<std::string,std::string> links;
 for(std::size_t i=0;i<r.entries.size();i++){const auto&e=r.entries[i];if(!e.symlink)continue;r.findings.push_back({"SYMLINK_ENTRY",i+1,"warning"});if(e.size>4096)throw Error("LINK_TARGET_LIMIT",e.data);auto target=e.prefix;std::replace(target.begin(),target.end(),'\\','/');if(!utf8(target))throw Error("LINK_TARGET_ENCODING",e.data);if(target.empty()||target.starts_with('/')||target.find(':')!=std::string::npos||normalized(target).starts_with("..")||target.find("/../")!=std::string::npos||target.ends_with("/.."))r.findings.push_back({"LINK_TARGET_ESCAPE",i+1,"error"});auto name=normalized(e.name);auto pos=name.rfind('/');auto parent=pos==std::string::npos?"":name.substr(0,pos+1);links[name]=normalized(parent+target);}
 std::map<std::string,bool> reaches_cycle;
 for(const auto&[start,target]:links){(void)target;if(reaches_cycle.contains(start))continue;std::vector<std::string> chain;std::set<std::string> seen;auto current=start;bool cycle=false;while(links.contains(current)){if(reaches_cycle.contains(current)){cycle=reaches_cycle.at(current);break;}if(!seen.insert(current).second){cycle=true;break;}chain.push_back(current);current=links.at(current);}for(const auto&node:chain)reaches_cycle[node]=cycle;}
 for(std::size_t i=0;i<r.entries.size();i++)if(r.entries[i].symlink&&reaches_cycle[normalized(r.entries[i].name)])r.findings.push_back({"LINK_CYCLE",i+1,"error"});
 std::sort(r.findings.begin(),r.findings.end(),[](const auto&a,const auto&b){return std::tie(a.entry,a.code,a.severity)<std::tie(b.entry,b.code,b.severity);});r.findings.erase(std::unique(r.findings.begin(),r.findings.end(),[](const auto&a,const auto&b){return a.entry==b.entry&&a.code==b.code&&a.severity==b.severity;}),r.findings.end());
}
std::string normalized(std::string name){std::replace(name.begin(),name.end(),'\\','/');std::istringstream stream(name);std::string part,out;while(std::getline(stream,part,'/')){if(part.empty()||part==".")continue;if(!out.empty())out+='/';out+=part;}return out;}
}
