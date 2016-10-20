#ifndef _SHIBBOLETHMANAGER_H
#define _SHIBBOLETHMANAGER_H
#include <string>
#include <array>
#include <memory>
#include <stdint.h>
#include <vector>
#include  <boost/xpressive/xpressive_dynamic.hpp>
namespace re = boost::xpressive;
typedef std::array<char, 8192> BufferT;
class ShibbolethManager
{
public:
    static ShibbolethManager& Instance();

    void Load(const std::string& confPath);

    bool GetShibboleth(const char* msg, int32_t len, std::shared_ptr<BufferT> outBuffer);
    bool IsShibboleth(const char* msg, int32_t len) const; 

private:
    ShibbolethManager(){}
    ShibbolethManager(const ShibbolethManager&);
    
    struct Shibboleth
    {
	std::string type;
	re::cregex request;
	std::string format;
    };
    
    std::shared_ptr<Shibboleth> Find(const char* msg, int32_t len) const;
    std::vector<std::shared_ptr<Shibboleth>> mShibboleths;
};
#endif

