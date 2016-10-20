#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include "Server.h"
#include "Sniffer.h"
#include "ShibbolethManager.h"

int main(int argc, char** argv)
{
    using namespace boost::program_options;
    options_description opts("dispatch options");
    opts.add_options()
            ("help,h","print this help information.")
	    ("conf,c", value<std::string>(), "configure file")
            ("listenIP,i", value<std::string>()->default_value("127.0.0.1"), "listen ip")
            ("listen,l", value<uint16_t>(), "listen port")
            ("host,H", value<std::string>(), "sniffle package from this ip")
            ("port,P", value<uint16_t>(), "sniffle package from this port")
            ("device,d", value<std::string>(), "on which device to sniffle")
            ("research,r", "research mode");

    variables_map vm;
    store(parse_command_line(argc,argv,opts),vm);

    if(vm.count("help"))
    {
        std::cout<<opts<<std::endl;
        return 0;
    }

    if(0 == vm.count("listen"))
    {
        std::cout << "no listen port specified" << std::endl;
        std::cout << opts << std::endl;
        return -1;
    }

    if(0 == vm.count("host"))
    {
        std::cout << opts << std::endl;
        std::cout << "no host ip specified" << std::endl;
        return -1;
    }

    if(0 == vm.count("port"))
    {
        std::cout << opts << std::endl;
        std::cout << "no port ip specified" << std::endl;
        return -1;
    }

    bool isResearchMode = false;
    if(0 != vm.count("research"))
    {
        isResearchMode = true;
    }

    std::string configurePath;
    if(0 != vm.count("conf"))
    {
	configurePath = vm["conf"].as<std::string>();
	if(!boost::filesystem::is_regular_file(configurePath))
	{
	    std::cout<< "configure file " << configurePath << " doesn't exists" << std::endl;
	    return -1;
	}
    }

    try
    {
        std::string listenIP = vm["listenIP"].as<std::string>();
        uint16_t listenPort = vm["listen"].as<uint16_t>();
        std::string hostIP = vm["host"].as<std::string>();
        uint16_t hostPort = vm["port"].as<uint16_t>();

        std::string dev = vm["device"].as<std::string>();
        Server server(listenIP, boost::lexical_cast<std::string>(listenPort));
        Sniffer sniffer(server, isResearchMode);

        char filter[64];
	if(isResearchMode)
	{
            snprintf(filter, sizeof(filter), "host %s and port %d", hostIP.c_str(), hostPort);
	}
	else
	{
            snprintf(filter, sizeof(filter), "src %s and port %d", hostIP.c_str(), hostPort);
	}
	ShibbolethManager::Instance().Load(configurePath);
        sniffer.Run(dev, std::string(filter));
        server.run();
    }
    catch (const std::exception& ex)
    {
        std::cerr << "exception: " << ex.what() << std::endl;
    }

    return 0;
}
