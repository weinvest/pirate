#ifndef _SNIFFER_H
#define _SNIFFER_H
#include "pcap.h"
#include <string>
#include <thread>
#include <memory>
#include <fstream>
#include <array>
#include <map>

class Server;
class Sniffer
{
public:
    typedef std::array<char, 8192> BufferT;
    Sniffer(Server& server, bool isResearchMode = false);

    bool Run(const std::string& dev, const std::string& filter);
private:
    static void GotPachage(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
    int32_t Send(std::shared_ptr<BufferT> pBuffer);
    void ReassembleTCP(uint32_t seq, const char* payload, int32_t size_payload);

    Server& mServer;
    std::shared_ptr<std::thread> mThread;
    bool mIsResearchMode;
    std::shared_ptr<std::ofstream> mResearchFile;

    uint32_t mNextSequence;
    std::map<int32_t, std::shared_ptr<BufferT>> mBufferedData;
};
#endif
