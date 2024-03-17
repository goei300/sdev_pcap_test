#include <stdint.h>

// Ethernet Header
typedef struct {
    uint8_t  dest[6];    // Destination MAC Address
    uint8_t  src[6];     // Source MAC Address
    uint16_t type;       // Type (e.g., IP, ARP, etc.)
} EthernetHeader;

// IP Header (simplified version)
typedef struct {
    uint8_t  versionIHL;        // Version + Internet Header Length
    uint8_t  typeOfService;     // Type of Service
    uint16_t totalLength;       // Total Length
    uint16_t identification;    // Identification
    uint16_t flagsFragment;     // Flags + Fragment Offset
    uint8_t  ttl;               // Time to Live
    uint8_t  protocol;          // Protocol
    uint16_t checksum;          // Header Checksum
    uint32_t srcAddr;           // Source Address
    uint32_t destAddr;          // Destination Address
} IPHeader;

// TCP Header (simplified version)
typedef struct {
    uint16_t srcPort;     // Source Port
    uint16_t destPort;    // Destination Port
    uint32_t seqNumber;   // Sequence Number
    uint32_t ackNumber;   // Acknowledgment Number
    uint8_t  dataOffset;  // Data Offset
    uint8_t  flags;       // Flags
    uint16_t window;      // Window
    uint16_t checksum;    // Checksum
    uint16_t urgentPtr;   // Urgent Pointer
} TCPHeader;
