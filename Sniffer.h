#ifndef _SNIFFER_H
#define _SNIFFER_H
#include "pcap.h"
#include <string>
#include <thread>
#include <memory>
#include <fstream>

class Server;
class Sniffer
{
public:
    Sniffer(Server& server, bool isResearchMode = false);

    bool Run(const std::string& dev, const std::string& filter);
private:
    static void GotPachage(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    Server& mServer;
    std::shared_ptr<std::thread> mThread;
    bool mIsResearchMode;
    std::shared_ptr<std::ofstream> mResearchFile;
};
#endif
