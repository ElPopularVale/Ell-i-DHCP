#ifndef IPSTACK_H
#define IPSTACK_H

#include "stdint.h"
#include <stdbool.h>

extern uint8_t deviceIP[4];
extern uint8_t deviceMAC[6];
extern uint8_t routerIP[4];

#define MAXPACKETLEN 500

typedef struct
{
  uint8_t DestAddrs[6];
  uint8_t SrcAddrs[6];
  uint16_t type;
}  EtherNetII;
// Ethernet packet types
#define ARPPACKET 0x0806
#define IPPACKET 0x0800

typedef struct
{
  EtherNetII eth;
  uint16_t hardware;
  uint16_t protocol;
  uint8_t hardwareSize;
  uint8_t protocolSize;
  uint16_t opCode;
  uint8_t senderMAC[6];
  uint8_t senderIP[4];
  uint8_t targetMAC[6];
  uint8_t targetIP[4];
}ARP;

//ARP opCodes
#define ARPREPLY  0x0002
#define ARPREQUEST 0x0001

//ARP hardware types
#define ETHERNET 0x0001

// Switch to host order for the enc28j60
#define HTONS(x) ((x<<8)|(x>>8))

typedef struct
{
  EtherNetII eth;
  uint8_t hdrlen : 4;
  uint8_t version : 4;
  uint8_t diffsf;
  uint16_t len;
  uint16_t ident;
  uint16_t fragmentOffset1: 5;
  uint16_t flags : 3;
  uint16_t fragmentOffset2 : 8;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t chksum;
  uint8_t source[4];
  uint8_t dest[4];
}IPhdr;

// IP protocols
#define ICMPPROTOCOL 0x01
#define UDPPROTOCOL 0x11

typedef struct
{
  IPhdr ip;
  uint16_t sourcePort;
  uint16_t destPort;
  uint16_t len;
  uint16_t chksum;
}UDPhdr;

typedef struct
{
  IPhdr ip;
  uint8_t type;
  uint8_t code;
  uint16_t chksum;
  uint16_t iden;
  uint16_t seqNum;
}ICMPhdr;

#define ICMPREPLY 0x0
#define ICMPREQUEST 0x8

void add32(uint8_t *op32, uint16_t op16);
uint16_t chksum(uint16_t sum, uint8_t *data, uint16_t len);
void SetupBasicIPPacket(uint8_t* packet, uint8_t protocol, uint8_t* destIP);
void SendArpPacket(uint8_t* targetIP);
void ReplyArpPacket(ARP* arpPacket);
void SendPing(uint8_t* targetIP);
void PingReply(ICMPhdr* ping, uint16_t len);
uint8_t GetPacket(uint8_t protocol, uint8_t* packet);
uint16_t IPstackInit();
uint16_t IPstackIdle();
void sendUdp(char *data, uint8_t* destIP, uint16_t port);

#endif
