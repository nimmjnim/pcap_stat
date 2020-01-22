#include "stat.h"


template<typename Data>
void PrintEP(Data data){
    printf("%3u.%3u.%3u.%3u", (data & 0xff000000) >> 24, (data & 0xff0000) >> 16, (data & 0xff00) >> 8, (data & 0xff));
};

template<>
void PrintEP(MAC data){
    for(int i=0;i < 6; i++) {
        printf("%02x", data.num[i]);
        if(i != 5) printf(":");
    }
};

template <typename Data>
void PrintCV(const Data *data){
    for(int i=0; i<2; i++){
        printf("%3u.%3u.%3u.%3u", (data[i] & 0xff000000) >> 24, (data[i] & 0xff0000) >> 16, (data[i] & 0xff00) >> 8, (data[i] & 0xff));
        if(!i) printf("  ");
    }

};

template <>
void PrintCV(const MAC *data){
    for(int j=0; j<2; j++){
        for(int i=0;i < 6; i++) {
            printf("%02x", data[j].num[i]);
            if(i != 5) printf(":");
        }
        if(!j) printf("  ");
    }
};

template <typename Data>
bool SwapWhenReverse(Data *data){
    Data tmp;
    if(data[1] < data[0]){
        tmp = data[0];
        data[0] = data[1];
        data[1] = tmp;
        return true;
    }
    return false;
}

template <typename Data>
Conservation<Data>::Conservation(MAC *data){
    memcpy(this->data[0].num, data[0].num, 8);
    memcpy(this->data[1].num, data[1].num, 8);
}

template <typename Data>
Conservation<Data>::Conservation(uint32_t *data){
    memcpy(this->data, data, 8);
}

MAC::MAC(){
    num = new uint8_t[6];
}

void MAC::Change2Mac(const u_char *p){
    for(int i=0; i<6; i++) num[i] = p[i];
}

V::V(){
    Packet = Bytes = OutOne = OutBytes = InOne = InBytes = 0;
}

void V::PrintStat()
{
    cout << setw(15) << Packet << setw(15) << Bytes;
    cout << setw(15) << OutOne << setw(15) << OutBytes << setw(15) << InOne << setw(15) << InBytes << '\n';
}

void V::UpdateStat(int flag, uint64_t length)
{
    if(!flag){
        OutOne++;
        OutBytes += length;
    }
    else{
        InOne++;
        InBytes += length;
    }
    Packet++;
    Bytes += length;

}

template<typename Data>
void FindAndUpdateEP(uint64_t length, map<Data, V> &r, Data *data){
    for(int i=0; i<2; i++){
        auto it = r.find(data[i]);
        if(it == r.end()){
            V tmp;
            tmp.UpdateStat(i, length);
            r.insert(make_pair(data[i], tmp));
        }
        else it->second.UpdateStat(i, length);
    }
}

template<>
void FindAndUpdateEP(uint64_t length, map<MAC, V> &r, MAC *data){
    MAC *p = new MAC[2];
    memcpy(p[0].num, data[0].num, 8);
    memcpy(p[1].num, data[1].num, 8);

    for(int i=0; i<2; i++){
        auto it = r.find(p[i]);
        if(it == r.end()){
            V tmp;
            tmp.UpdateStat(i, length);
            r.insert(make_pair(p[i], tmp));
        }
        else it->second.UpdateStat(i, length);
    }
}

template<typename Data>
void FindAndUpdateCV(uint64_t length, map<Conservation<Data>, V> &r, Data *data, int flag){
    Conservation<Data> p(data);

    auto it = r.find(p);
    if(it == r.end()){
        V tmp;
        tmp.UpdateStat(flag, length);
        r.insert(make_pair(p, tmp));
    }
    else it->second.UpdateStat(flag, length);
}



template<typename Data>
void PrintStatEP(map<Data, V>& r){

    int n;
    cout.setf(ios::right);
    if(sizeof(Data) == sizeof(uint32_t)) {
        cout << "IP Endpoint\n";
        n = 15;
    }
    else {
        cout << "MAC Endpoint\n";
        n = 17;
    }

    cout << setw(n) <<"Address" << setw(15) << "Packets" << setw(15) << "Bytes";
    cout << setw(15) << "TX Packets" << setw(15) << "TX Bytes" << setw(15) << "RX Packets" << setw(15) << "RX Bytes" << '\n';

    for(auto i=r.begin(); i!=r.end(); ++i) {
        PrintEP<Data>(i->first);
        i->second.PrintStat();
    }
    printf("\n");
}

template<typename Data>
void PrintStatCV(map<Conservation<Data>, V>& r){

    int n;
    cout.setf(ios::right);
    if(sizeof(Data) == sizeof(uint32_t)) {
        cout << "IP Conservation\n";
        n = 15;
    }
    else {
        cout << "MAC Conservation\n";
        n = 17;
    }

    cout << setw(n) << "AddressA" << setw(n+2) << "AddressB" << setw(15) << "Packets" << setw(15) << "Bytes";
    cout << setw(15) << "Packets AB" << setw(15) << "Bytes AB" << setw(15) << "Packets BA" << setw(15) << "Bytes BA" << '\n';

    for(auto i=r.begin(); i!=r.end(); ++i) {
        PrintCV<Data>(i->first.data);
        i->second.PrintStat();
    }
    printf("\n");
}
