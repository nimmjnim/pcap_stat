#include "stat.hpp"

void usage() {
    printf("syntax: pcap_stat <pcap file name>\n");
}

int main(int argc, char* argv[]) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    uint64_t length;
    struct libnet_ethernet_hdr *Ether;
    struct libnet_ipv4_hdr *IP;
    uint32_t IPData[2];
    MAC MacData[2];

    map<uint32_t, V> IPEndpoint;
    map<MAC, V> MacEndpoint;
    map<Conservation<uint32_t>, V> IPConservation;
    map<Conservation<MAC>, V> MacConservation;

    if (argc != 2) {
        usage();
        return -1;
    }


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_offline(argv[1],errbuf);
    if(pcap_handle == nullptr){
        fprintf(stderr, "Failed Open...%s\n", errbuf);
        return -1;
    }

    while (true) {
        res = pcap_next_ex(pcap_handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        length = header->len;
        Ether = (struct libnet_ethernet_hdr *)packet;
        IP = (struct libnet_ipv4_hdr *)(packet+14);

        MacData[0].Change2Mac(packet+6);
        MacData[1].Change2Mac(packet);
        FindAndUpdateEP(length, MacEndpoint, MacData);
        FindAndUpdateCV(length, MacConservation, MacData, SwapWhenReverse(MacData));

        if(Ether->ether_type == 0x0008){
            IPData[0] = ntohl((uint32_t)IP->ip_src.s_addr);
            IPData[1] = ntohl((uint32_t)IP->ip_dst.s_addr);
            FindAndUpdateEP(length, IPEndpoint, IPData);
            FindAndUpdateCV(length, IPConservation, IPData, SwapWhenReverse(IPData));
        }

    }

    PrintStatEP(MacEndpoint);

    PrintStatCV(MacConservation);
    PrintStatEP(IPEndpoint);
    PrintStatCV(IPConservation);

    pcap_close(pcap_handle);
    return 0;
}

