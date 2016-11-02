#include <fstream>
#include <time.h>
#include "ShibbolethManager.h"
#include <boost/algorithm/string.hpp>
ShibbolethManager& ShibbolethManager::Instance()
{
    static ShibbolethManager instance;
    return instance;
}

void ShibbolethManager::Load(const std::string& confPath)
{
    std::ifstream confFile(confPath.c_str(), std::ios_base::binary | std::ios_base::in);
    if(confFile)
    {
	std::string line;
	while(std::getline(confFile, line))
	{
	    if(0 != line.length())
	    {
		auto typeEndPos = line.find(':');
		auto requestEndPos = line.find(':', typeEndPos + 1);

		std::shared_ptr<Shibboleth> pShibboleth = std::make_shared<Shibboleth>();
		pShibboleth->type = line.substr(0, typeEndPos);

		std::string requestPattern = line.substr(typeEndPos + 1, requestEndPos - typeEndPos - 1);
                boost::replace_all(requestPattern, "|", "\\|");
		pShibboleth->request = re::cregex::compile(requestPattern );
		pShibboleth->format = line.substr(requestEndPos + 1);
		mShibboleths.push_back(pShibboleth);
	    }
	}
    //mExcludeShibboleths.emplace_back("ahbs");
    }
}

std::shared_ptr<ShibbolethManager::Shibboleth> ShibbolethManager::Find(const char* msg, int32_t len) const
{
    for(auto pShibboleth : mShibboleths)
    {
	if(0 == memcmp(msg, pShibboleth->type.c_str(), pShibboleth->type.length()))
	{
	    return pShibboleth;
	}
    }

    return nullptr;
}

bool ShibbolethManager::GetShibboleth(const char* msg, int32_t len, std::shared_ptr<BufferT> outBuffer)
{
    auto pShibboleth = Find(msg, len);
    if(nullptr == pShibboleth || pShibboleth->format.empty())
    {
	return false;
    }

    char* outBeg = outBuffer->begin() + 4;
    auto endIt = re::regex_replace(outBeg, (char*)msg, msg + len, pShibboleth->request, pShibboleth->format);
    *((int32_t*)outBuffer->data()) = endIt - outBeg;
    *endIt = '\0';
    std::cout << "req:" << currentTime() << ":" << msg << std::endl;
    std::cout << "rsp:" << currentTime() << ":" << outBeg << std::endl;
    return true;
}

bool ShibbolethManager::IsShibboleth(const char* msg, int32_t len) const
{
    return nullptr != Find(msg, len);
}

bool ShibbolethManager::IsExclude(const char* msg, int32_t len) const
{
    for(auto& exclude : mExcludeShibboleths)
    {
        if(0 == memcmp(msg, exclude.c_str(), exclude.length()))
        {
            return true;
        }
    }
    return false;
}


std::string ShibbolethManager::currentTime( void )
{
    std::time_t t = std::time(nullptr);
	std::tm *now = std::localtime(&t);

    char szTime[64];
    snprintf(szTime, 16, "%04d%02d%02d.%02d%02d%02d", (1900 + now->tm_year), (1 + now->tm_mon), now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
    return std::string(szTime, 16);
}
