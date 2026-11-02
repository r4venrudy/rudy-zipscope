#include "zipscope/compare.hpp"
#include "zipscope/hash.hpp"
#include <map>
#include <algorithm>
namespace zs {
Comparison compare(const Report&a,const Report&b){
 Comparison out;out.before=a.sha256;out.after=b.sha256;
 auto ready=[](const Report&r){return r.complete&&std::all_of(r.entries.begin(),r.entries.end(),[](const auto&e){return e.verified;})&&std::none_of(r.findings.begin(),r.findings.end(),[](const auto&f){return f.severity=="error";});};
 if(!ready(a)||!ready(b))return out;
 auto manifest=[](const Report&r){std::map<std::string,std::string> m;for(const auto&e:r.entries)m.emplace(e.name,e.sha256+":"+std::to_string(e.attrs)+":"+std::to_string(e.made_by>>8)+":"+std::to_string(e.size));return m;};
 auto old=manifest(a),now=manifest(b);if(old.size()!=a.entries.size()||now.size()!=b.entries.size())return out;
 out.comparable=true;
 for(const auto&[name,value]:old){auto it=now.find(name);if(it==now.end())out.differences.push_back({name,"removed",value,""});else if(it->second!=value)out.differences.push_back({name,"modified",value,it->second});}
 for(const auto&[name,value]:now)if(!old.contains(name))out.differences.push_back({name,"added","",value});
 std::sort(out.differences.begin(),out.differences.end(),[](const auto&x,const auto&y){return x.name<y.name;});out.equal=out.differences.empty();return out;
}
}
