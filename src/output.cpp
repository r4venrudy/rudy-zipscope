#include "zipscope/output.hpp"
#include "zipscope/hash.hpp"
#include "zipscope/names.hpp"
#include "nlohmann/json.hpp"
#include <sstream>
namespace zs {
using J=nlohmann::ordered_json;
static std::string identity(const std::string&s){return sha256(Bytes(reinterpret_cast<const std::uint8_t*>(s.data()),s.size()));}
static J name_evidence(const std::string&s,bool show){J out{{"sha256",identity(s)}};if(show){if(utf8(s))out["value"]=s;else{std::string hex;constexpr char digits[]="0123456789abcdef";for(char raw:s){auto c=static_cast<unsigned char>(raw);hex+=digits[c>>4];hex+=digits[c&15];}out["rawHex"]=hex;}}return out;}
std::string json(const Report&r,bool show){
 J entries=J::array(),findings=J::array(),gaps=J::array();
 for(std::size_t i=0;i<r.entries.size();i++){const auto&e=r.entries[i];J aliases=J::array();for(const auto&name:e.aliases)aliases.push_back(name_evidence(name,show));entries.push_back(J{{"number",i+1},{"centralName",name_evidence(e.name,show)},{"localName",name_evidence(e.local_name,show)},{"unicodeNames",aliases},{"method",e.method},{"flags",e.flags},{"attributes",e.attrs},{"localOffset",e.local},{"dataOffset",e.data},{"recordEnd",e.end},{"compressedBytes",e.compressed},{"decodedBytes",e.size},{"crc32",e.crc},{"verified",e.verified},{"decodedSha256",e.sha256.empty()?J(nullptr):J(e.sha256)},{"directory",e.directory},{"symlink",e.symlink}});}
 for(const auto&f:r.findings)findings.push_back(J{{"code",f.code},{"entry",f.entry},{"severity",f.severity}});
 for(const auto&g:r.gaps)gaps.push_back(J{{"begin",g.begin},{"end",g.end},{"sha256",g.sha256}});
 J out{{"schema","zipscope.report.v1"},{"version",version()},{"sourceSha256",r.sha256},{"complete",r.complete},{"stopCode",r.stop_code.empty()?J(nullptr):J(r.stop_code)},{"stopOffset",r.stop_code.empty()?J(nullptr):J(r.stop_offset)},{"directory",J{{"offset",r.directory.start},{"bytes",r.directory.size},{"entries",r.directory.count},{"zip64",r.directory.zip64},{"eocdOffset",r.directory.eocd}}},{"entries",entries},{"findings",findings},{"unreferencedRanges",gaps}};
 return out.dump(2,' ',false,J::error_handler_t::replace)+"\n";
}
std::string text(const Report&r,bool show){std::ostringstream out;out.imbue(std::locale::classic());out<<"RUDY ZIPSCOPE / "<<(r.complete?"COMPLETE PROFILE":"INCOMPLETE")<<"\nSource SHA-256: "<<r.sha256<<"\nEntries: "<<r.entries.size()<<" | Findings: "<<r.findings.size()<<"\n";if(!r.stop_code.empty())out<<"Stopped: "<<r.stop_code<<" at byte "<<r.stop_offset<<"\n";for(std::size_t i=0;i<r.entries.size();i++){const auto&e=r.entries[i];out<<'#'<<i+1<<" ["<<e.local<<','<<e.end<<") method="<<e.method<<" bytes="<<e.size<<" verified="<<(e.verified?"yes":"no")<<" name-sha256="<<identity(e.name);if(show&&utf8(e.name))out<<" name="<<e.name;out<<'\n';}for(const auto&f:r.findings)out<<f.severity<<" / #"<<f.entry<<" / "<<f.code<<'\n';return out.str();}
}
