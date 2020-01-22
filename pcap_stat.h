#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <netinet/in.h>

#ifndef PCAP_STAT_H
#define PCAP_STAT_H

class ConservationsStat{
private:
    const u_char *PacketP;
    uint32_t Packet;
    uint64_t Bytes;
    uint32_t AtoBPacket;
    uint64_t AtoBBytes;
    uint32_t BtoAPacket;
    uint64_t BtoABytes;
public:
    void UpdateStat()
};

class EndpointStat{
private:
    u_char *PacketP;
    uint32_t Packet;
    uint64_t Bytes;
    uint32_t TXPacket;
    uint64_t TXBytes;
    uint32_t RXPacket;
    uint64_t RXBytes;
public:
    void UpdateStat();
};


#endif // PCAP_STAT_H
