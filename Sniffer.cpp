#include "ProtocolStruct.h"
#include "Sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "Server.h"
#include "Connection.h"
#include "ShibbolethManager.h"

Sniffer::Sniffer(Server& server, bool isResearchMode)
    :mServer(server)
    ,mIsResearchMode(isResearchMode)
{
    if(mIsResearchMode)
    {
	std::time_t t = std::time(nullptr);
	std::tm *now = std::localtime(&t);
	char fileName[64];
	memset(fileName, 0 ,sizeof(fileName));
	snprintf(fileName, sizeof(fileName), "%04d%02d%02d.%02d%02d%02d.research", (1900 + now->tm_year)
		,(1 + now->tm_mon) , now->tm_mday , now->tm_hour , now->tm_min , now->tm_sec);

	mResearchFile = std::make_shared<std::ofstream>(fileName, std::ios_base::binary | std::ios_base::out);
    }
}

void Sniffer::GotPachage(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20)
    {
	printf("   * Invalid IP header length: %u bytes\n", size_ip);
	return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* determine protocol */
    switch(ip->ip_p)
    {
	case IPPROTO_TCP:
	    printf("   Protocol: TCP\n");
	    break;
	case IPPROTO_UDP:
	    printf("   Protocol: UDP\n");
	    return;
	case IPPROTO_ICMP:
	    printf("   Protocol: ICMP\n");
	    return;
	case IPPROTO_IP:
	    printf("   Protocol: IP\n");
	    return;
	default:
	    printf("   Protocol: unknown\n");
	    return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20)
    {
	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    payload = (const char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if(0 != size_payload)
    {
	Sniffer* pThis = reinterpret_cast<Sniffer*>(args);
	if(nullptr != pThis->mResearchFile)
	{
	    (*(pThis->mResearchFile)) << ntohs(tcp->th_sport) << "->" << ntohs(tcp->th_dport)
		<< ":" << size_payload<<":";
	    pThis->mResearchFile->write(payload, size_payload);
	    (*(pThis->mResearchFile)) << "\n";
	}

        if(!ShibbolethManager::Instance().IsShibboleth(payload, size_payload))
	{
	    for(auto& c : pThis->mServer.get_connections())
	    {
	        c->send(payload, size_payload);
	    }
	}
    }
}

bool Sniffer::Run(const std::string& sDev, const std::string& filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */

    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = -1;			/* number of packets to capture */
    const char* filter_exp = filter.c_str();
    const char* dev = sDev.c_str();
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
	fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		dev, errbuf);
	net = 0;
	mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter.c_str());

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 0, 0, errbuf);
    if (handle == NULL)
    {
	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	return false;
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
	fprintf(stderr, "%s is not an Ethernet\n", dev);
	return false;
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
	fprintf(stderr, "Couldn't parse filter %s: %s\n",
		filter_exp, pcap_geterr(handle));
	return false;
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
    {
	fprintf(stderr, "Couldn't install filter %s: %s\n",
		filter_exp, pcap_geterr(handle));
	return false;
    }

    mThread = std::make_shared<std::thread>([this, handle, num_packets, &fp]()
	    {
	    /* now we can set our callback function */
	    pcap_loop(handle, num_packets, &Sniffer::GotPachage, (u_char*)this);

	    /* cleanup */
	    pcap_freecode(&fp);
	    pcap_close(handle);
	    });
    return true;
}
