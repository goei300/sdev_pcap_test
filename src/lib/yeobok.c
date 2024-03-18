#include "lib/yeobok_global.h"
#include "lib/yeobok.h"
// validate protocol(condition)
bool isIP(const u_char *packet) {

    uint16_t etherType = ntohs(*(const uint16_t*)(packet + 12));
    return etherType == 0x0800; // Ethertype = 8   => IP
}
bool isTCP(const u_char *packet){
    // ※packet's addr : L3 ADDR

    const u_char *ipHeader = getIPAddr(packet); 
    uint8_t protocol = *(ipHeader + 9);
    return protocol == 6; // protocol -6 => TCP
}
bool isPayload(const u_char *packet){
    
    // ip addr
    const u_char *ipHeader = getIPAddr(packet);

    // extract total_length field
    uint16_t totalLength = (ipHeader[2] << 8) | ipHeader[3];

    // extract IHL field
    unsigned int ipHeaderLength = (ipHeader[0] & 0x0F) * 4;

    // tcp addr
    const u_char *tcpHeader = getTCPAddr(packet);

    // calculate tcp header length from 'offset' field
    unsigned int tcpHeaderLength = ((tcpHeader[12] >> 4) & 0x0F) * 4;

    // calculate payload length
    int payloadLength = totalLength - ipHeaderLength - tcpHeaderLength;

    return payloadLength >= 10;
}

// read header's addr
const u_char* getIPAddr(const u_char *packet) {
    return packet + 14; // ethernet frame's size is 14 bytes
}

const u_char* getTCPAddr(const u_char *packet) {
    const uint8_t *ipHeader = getIPAddr(packet);
    // calculate IHL 
    unsigned int ipHeaderLength = (*ipHeader & 0x0F) * 4;
    return ipHeader + ipHeaderLength;
}

const u_char* getPayloadAddr(const u_char *packet) {
    const uint8_t *tcpHeader = getTCPAddr(packet);
    // calculate THL from 'Offset' field
    unsigned int tcpHeaderLength = ((tcpHeader[12] >> 4) & 0x0F) * 4;
    return tcpHeader + tcpHeaderLength;
}


// extract value from header

const u_char* getMACsrc(const u_char *ETHERF) {
    return ETHERF + 6;
}
const u_char* getMACDest(const u_char *ETHERF) {
    return ETHERF; 
}
uint32_t getIPSrc(const u_char *IPH) {
    return *((uint32_t *)(IPH + 12));
}
uint32_t getIPDest(const u_char *IPH) {
    return *((uint32_t *)(IPH + 16));
}
uint16_t getPortSrc(const u_char *TCPH) {
    return *((uint16_t *)TCPH);
}
uint16_t getPortDest(const u_char *TCPH) {
    return *((uint16_t *)(TCPH + 2));
}

//  # active func

void PrintMacAddr(const u_char *packet) {
    const u_char *smac = getMACsrc(packet);
    const u_char *dmac = getMACDest(packet);

    printf("Source MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
           smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
    printf("Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
           dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
    printf("\n");
}

void PrintIPAddr(const u_char *IPH) {
    uint32_t sip = ntohl(getIPSrc(IPH)); 
    uint32_t dip = ntohl(getIPDest(IPH)); 

    printf("Source IP : %d.%d.%d.%d\n",
           (sip >> 24) & 0xFF, (sip >> 16) & 0xFF, (sip >> 8) & 0xFF, sip & 0xFF);
    printf("Destination IP : %d.%d.%d.%d\n",
           (dip >> 24) & 0xFF, (dip >> 16) & 0xFF, (dip >> 8) & 0xFF, dip & 0xFF);
    printf("\n");
}


void PrintTCPPort(const u_char *TCPH) {
    uint16_t sport = getPortSrc(TCPH);
    uint16_t dport = getPortDest(TCPH);

    printf("Source port : %u\n", ntohs(sport)); 
    printf("Destination port : %u\n", ntohs(dport)); 
    printf("\n");
}

void PrintPayload(const u_char* payload, int length) {
    printf("Payload(10bytes) : ");
    for (int i = 0; i < length; ++i) {
        printf("%02X ", payload[i]);
    }
    printf("\n");
}