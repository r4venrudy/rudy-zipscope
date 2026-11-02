#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include "zipscope/parser.hpp"
#include "zipscope/output.hpp"
#include "zipscope/compare.hpp"
#include "zipscope/io.hpp"
#include <iostream>
#include <map>
#include <charconv>
#include <algorithm>
static std::uint64_t number(const std::string&s,std::uint64_t max){std::uint64_t n=0;auto r=std::from_chars(s.data(),s.data()+s.size(),n);if(r.ec!=std::errc{}||r.ptr!=s.data()+s.size()||n>max)throw zs::Error("OPTION_NUMBER",0);return n;}
static std::filesystem::path path(const char*s){std::string bytes(s);return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(bytes.data()),bytes.size()));}
static int run(int argc,char**argv){try{
 if(argc==2&&std::string(argv[1])=="--version"){std::cout<<"zipscope "<<zs::version()<<'\n';return 0;}
 if(argc==2&&(std::string(argv[1])=="--help"||std::string(argv[1])=="-h")){std::cout<<"zipscope inspect ARCHIVE [--format text|json|html|sarif] [--show-names] [--fail-on warning|error|none]\nzipscope compare BEFORE AFTER [--format json|text] [--show-names] [--fail-on changed|none]\nLimits: --max-input-mib 1..1024 --max-total-mib 0..2048 --max-entry-mib 0..1024 --max-entries 1..100000\nExit: 0=gate clear, 1=gate hit, 2=incomplete/input/usage/I/O error. No extraction or network access.\n";return 0;}
 if(argc<3)throw zs::Error("USAGE",0);std::string command=argv[1];bool diff=command=="compare";if(command!="inspect"&&!diff)throw zs::Error("USAGE",0);int first=diff?4:3;if(argc<first)throw zs::Error("USAGE",0);
 std::map<std::string,std::string> options;for(int i=first;i<argc;i++){std::string key=argv[i];if(key!="--output"&&key!="--show-names"&&key!="--format"&&key!="--fail-on"&&key!="--max-input-mib"&&key!="--max-total-mib"&&key!="--max-entry-mib"&&key!="--max-entries")throw zs::Error("UNKNOWN_OPTION",0);std::string value="true";if(key!="--show-names"){if(++i==argc)throw zs::Error("OPTION_VALUE",0);value=argv[i];}if(!options.emplace(key,value).second)throw zs::Error("DUPLICATE_OPTION",0);}
 auto get=[&](const std::string&key,const std::string&fallback){auto i=options.find(key);return i==options.end()?fallback:i->second;};zs::Limits limits;
 limits.input=number(get("--max-input-mib","256"),1024)*1024*1024;limits.total=number(get("--max-total-mib","512"),2048)*1024*1024;limits.entry=number(get("--max-entry-mib","64"),1024)*1024*1024;limits.entries=static_cast<std::size_t>(number(get("--max-entries","10000"),100000));if(!limits.input||!limits.entries)throw zs::Error("INVALID_LIMITS",0);
 auto format=get("--format",diff?"json":"text"),gate=get("--fail-on",diff?"changed":"warning");bool show=options.contains("--show-names");
 zs::Snapshot before(path(argv[2]),limits.input);auto a=zs::analyze(before.bytes(),limits);std::string output;int code=0;
 if(diff){if(format!="json"&&format!="text")throw zs::Error("COMPARE_FORMAT",0);if(gate!="changed"&&gate!="none")throw zs::Error("COMPARE_GATE",0);zs::Snapshot after(path(argv[3]),limits.input);auto b=zs::analyze(after.bytes(),limits);auto result=zs::compare(a,b);before.recheck();after.recheck();output=zs::json(result,show);if(format=="text")output="RUDY ZIPSCOPE / MANIFEST COMPARISON\n"+output;code=!result.comparable?2:(!result.equal&&gate=="changed"?1:0);}
 else{if(gate!="warning"&&gate!="error"&&gate!="none")throw zs::Error("INSPECT_GATE",0);if(format=="json")output=zs::json(a,show);else if(format=="text")output=zs::text(a,show);else if(format=="html")output=zs::html(a,show);else if(format=="sarif")output=zs::sarif(a,show);else throw zs::Error("INSPECT_FORMAT",0);before.recheck();code=!a.complete?2:std::any_of(a.findings.begin(),a.findings.end(),[&](const auto&f){return gate=="warning"||(gate=="error"&&f.severity=="error");})?1:0;}
 if(output.size()>16*1024*1024)throw zs::Error("REPORT_LIMIT",0);if(options.contains("--output"))zs::write_new(output,path(options.at("--output").c_str()));else{std::cout<<output;if(!std::cout)throw zs::Error("OUTPUT_IO",0);}return code;
 }catch(const zs::Error&e){std::cerr<<"ZipScope: "<<e.code<<" at byte "<<e.offset<<'\n';return 2;}catch(const std::exception&){std::cerr<<"ZipScope: local operation could not be completed.\n";return 2;}}
#ifdef _WIN32
int wmain(int argc,wchar_t**argv){std::vector<std::string> values;std::vector<char*> pointers;for(int i=0;i<argc;i++){int count=lstrlenW(argv[i]);int length=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[i],count,nullptr,0,nullptr,nullptr);if(length==0&&count>0)return 2;values.emplace_back(static_cast<std::size_t>(length),'\0');if(length)WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[i],count,values.back().data(),length,nullptr,nullptr);}for(auto&v:values)pointers.push_back(v.data());return run(argc,pointers.data());}
#else
int main(int argc,char**argv){return run(argc,argv);}
#endif
