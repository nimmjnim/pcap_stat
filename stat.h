#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <iomanip>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cstdlib>
#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <map>
#include <netinet/in.h>

using namespace std;

#ifndef STAT_H
#define STAT_H

class MAC{
public:
    uint8_t *num;
    MAC();
    void Change2Mac(const u_char *p);
    bool operator<(const MAC &r) const{
        return (memcmp(num, r.num, 6) < 0);
    }
};

template <typename Data>
class Conservation{
public:
    Data data[2];
    Conservation(MAC *data);
    Conservation(uint32_t *data);
    bool operator<(const Conservation &r) const{
        if(r.data[0] < data[0]) return false;
        if(data[0] < r.data[0]) return true;
        return (data[1] < r.data[1]);
    }
};

class V{
private:
    uint32_t Packet;
    uint32_t Bytes;
    uint32_t OutOne;
    uint32_t OutBytes;
    uint32_t InOne;
    uint32_t InBytes;

public:
    V();
    void UpdateStat(int flag, uint64_t length);
    void PrintStat();
};

#endif // STAT_H
