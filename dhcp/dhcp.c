#include "dhcp.h"
#include "usart.h"
#include "enc28j60.h"
#include <stdio.h>
#include <string.h>

static const uint8_t xid[4] = { 0xab, 0xcd, 0x43, 0x21 };	//Transaction ID (XID)
static const uint8_t magicCookie[4] = { 99, 130, 83, 99 };	//Magic cookie
uint8_t DHCPServerID[4] = { 0, 0, 0, 0 };					// DHCP Server IP
static const char *hostname = "Ell-i";						//Client host name

void sendDiscover() {
	uint8_t broadcastIP[4] = { 255, 255, 255, 255 };
	uint8_t packet[MAXPACKETLEN];

	SetupBasicIPPacket(packet, UDPPROTOCOL, broadcastIP);

	//Setup DHCP header
	DHCPMsg *m = (DHCPMsg*) packet;
	m->op = DHCP_REQUEST;
	m->htype = DHCP_HTYPE_ETHERNET;
	m->hlen = sizeof(deviceMAC);
	m->hops = 0;
	memcpy(m->xid, xid, sizeof(m->xid));
	m->secs = 0;
	m->flags = HTONS(BOOTP_BROADCAST); /*  Broadcast bit. */
	memset(m->ciaddr, 0, sizeof(m->ciaddr));
	memset(m->yiaddr, 0, sizeof(m->yiaddr));
	memset(m->siaddr, 0, sizeof(m->siaddr));
	memset(m->giaddr, 0, sizeof(m->giaddr));
	memcpy(m->chaddr, deviceMAC, sizeof(deviceMAC));
	memset(&m->chaddr[sizeof(deviceMAC)], 0,
			sizeof(m->chaddr) - sizeof(deviceMAC));
	memset(m->sname, 0, sizeof(m->sname));
	memset(m->file, 0, sizeof(m->file));
	memcpy(m->options, magicCookie, sizeof(magicCookie));

	//DHCP options
	uint8_t *optPtr = &m->options[4];
	*optPtr++ = DHCP_OPTION_MSG_TYPE;
	*optPtr++ = 1;
	*optPtr++ = DHCPDISCOVER;
	*optPtr++ = DHCP_OPTION_HOST_NAME;
	*optPtr++ = strlen(hostname);
	memcpy(optPtr, hostname, strlen(hostname));
	optPtr += strlen(hostname);
	*optPtr++ = DHCP_OPTION_REQ_LIST;
	*optPtr++ = 3;
	*optPtr++ = DHCP_OPTION_SUBNET_MASK;
	*optPtr++ = DHCP_OPTION_ROUTER;
	*optPtr++ = DHCP_OPTION_DNS_SERVER;
	*optPtr++ = DHCP_OPTION_END;
//	printf("DHCP header set\r");

	uint16_t len = optPtr - packet; //Total packet length
	printf("Size of DHCP msg: %u\r", len);

	//Setup UDP/IP header
	memset(m->udp.ip.source, 0, sizeof(deviceIP));
	m->udp.sourcePort = HTONS(68);
	m->udp.destPort = HTONS(67);
	m->udp.len = (uint16_t) HTONS((len-sizeof(IPhdr)));
	m->udp.ip.len = (uint16_t) HTONS((len-sizeof(EtherNetII)));
	m->udp.ip.ident = 0xdeee;
//	printf("UDP/IP header set\r");

	//Calculate UDP and IP checksums
	m->udp.chksum = 0;
	m->udp.ip.chksum = 0;
	uint16_t pseudochksum = (uint16_t) chksum(UDPPROTOCOL + len - sizeof(IPhdr),
			m->udp.ip.source, sizeof(deviceIP) * 2);

	uint16_t chk1, chk2;
	chk1 = ~(chksum(pseudochksum, packet + sizeof(IPhdr), len - sizeof(IPhdr)));
	m->udp.chksum = (uint16_t) HTONS(chk1);
	chk2 = ~(chksum(0, packet + sizeof(EtherNetII),
			sizeof(IPhdr) - sizeof(EtherNetII)));
	m->udp.ip.chksum = (uint16_t) HTONS(chk2);
//	printf("Checksums set\r");

	//Send packet
	enc28j60_send_packet(packet, len);
	printf("DHCP DISCOVER sent\r");
//	print_mem(packet, 100);
}

uint8_t receiveOffer() {
	uint8_t packet[MAXPACKETLEN];
	DHCPMsg *m = (DHCPMsg*) packet;
	do {
		GetPacket(UDPPROTOCOL, packet);
	} while (!(m->udp.destPort == (uint16_t) HTONS(68) && m->op == DHCP_REPLY
			&& memcmp(m->xid, xid, sizeof(xid)) == 0
			&& memcmp(m->chaddr, deviceMAC, sizeof(deviceMAC)) == 0));
	printf("DHCP OFFER received\r");

	//Setup received IP
	memcpy(deviceIP, m->yiaddr, 4);

	//Parse options
	uint8_t *optPtr = &m->options[4];
	uint16_t totalLen = HTONS(m->udp.ip.len) + sizeof(EtherNetII);
	uint8_t* endPtr = packet + totalLen;
	uint8_t type = 0;

	while (optPtr < endPtr) {
		switch (*optPtr) {
		case DHCP_OPTION_SUBNET_MASK:
//	      memcpy(netmask, optPtr + 2, 4);
			break;
		case DHCP_OPTION_ROUTER:
			memcpy(routerIP, optPtr + 2, 4);
			break;
		case DHCP_OPTION_DNS_SERVER:
//	      memcpy(dnsaddr, optPtr + 2, 4);
			break;
		case DHCP_OPTION_MSG_TYPE:
			type = *(optPtr + 2);
			break;
		case DHCP_OPTION_SERVER_ID:
			memcpy(DHCPServerID, optPtr + 2, 4);
			break;
		case DHCP_OPTION_LEASE_TIME:
//	      memcpy(lease_time, optPtr + 2, 4);
			break;
		case DHCP_OPTION_END:
			break;
		}

		optPtr += optPtr[1] + 2;
	}
	return type;
}

void sendRequest() {
	uint8_t broadcastIP[4] = { 255, 255, 255, 255 };
	uint8_t packet[MAXPACKETLEN];

	SetupBasicIPPacket(packet, UDPPROTOCOL, broadcastIP);

	//Setup DHCP header
	DHCPMsg *m = (DHCPMsg*) packet;
	m->op = DHCP_REQUEST;
	m->htype = DHCP_HTYPE_ETHERNET;
	m->hlen = sizeof(deviceMAC);
	m->hops = 0;
	memcpy(m->xid, xid, sizeof(m->xid));
	m->secs = 0;
	m->flags = HTONS(BOOTP_BROADCAST); /*  Broadcast bit. */
	memset(m->ciaddr, 0, sizeof(m->ciaddr));
	memset(m->yiaddr, 0, sizeof(m->yiaddr));
	memset(m->siaddr, 0, sizeof(m->siaddr));
	memset(m->giaddr, 0, sizeof(m->giaddr));
	memcpy(m->chaddr, deviceMAC, sizeof(deviceMAC));
	memset(&m->chaddr[sizeof(deviceMAC)], 0,
			sizeof(m->chaddr) - sizeof(deviceMAC));
	memset(m->sname, 0, sizeof(m->sname));
	memset(m->file, 0, sizeof(m->file));
	memcpy(m->options, magicCookie, sizeof(magicCookie));

	uint8_t *optPtr = &m->options[4];
	*optPtr++ = DHCP_OPTION_MSG_TYPE;
	*optPtr++ = 1;
	*optPtr++ = DHCPREQUEST;
	*optPtr++ = DHCP_OPTION_HOST_NAME;
	*optPtr++ = strlen(hostname);
	memcpy(optPtr, hostname, strlen(hostname));
	optPtr += strlen(hostname);
	*optPtr++ = DHCP_OPTION_SERVER_ID;
	*optPtr++ = 4;
	memcpy(optPtr, DHCPServerID, 4);
	optPtr += 4;
	*optPtr++ = DHCP_OPTION_REQ_IPADDR;
	*optPtr++ = 4;
	memcpy(optPtr, deviceIP, 4);
	optPtr += 4;
	*optPtr++ = DHCP_OPTION_END;

	uint16_t len = optPtr - packet; //Total packet length
//	printf("Size of DHCP msg: %u\r", len);

	//Setup UDP/IP header
	memset(m->udp.ip.source, 0, sizeof(deviceIP));
	m->udp.sourcePort = HTONS(68);
	m->udp.destPort = HTONS(67);
	m->udp.len = (uint16_t) HTONS((len-sizeof(IPhdr)));
	m->udp.ip.len = (uint16_t) HTONS((len-sizeof(EtherNetII)));
	m->udp.ip.ident = 0xdeee;
//	printf("UDP/IP header set\r");

	//Calculate UDP and IP checksums
	m->udp.chksum = 0;
	m->udp.ip.chksum = 0;
	uint16_t pseudochksum = (uint16_t) chksum(UDPPROTOCOL + len - sizeof(IPhdr),
			m->udp.ip.source, sizeof(deviceIP) * 2);

	uint16_t chk1, chk2;
	chk1 = ~(chksum(pseudochksum, packet + sizeof(IPhdr), len - sizeof(IPhdr)));
	m->udp.chksum = (uint16_t) HTONS(chk1);
	chk2 = ~(chksum(0, packet + sizeof(EtherNetII),
			sizeof(IPhdr) - sizeof(EtherNetII)));
	m->udp.ip.chksum = (uint16_t) HTONS(chk2);
//	printf("Checksums set\r");

	//Send packet
	enc28j60_send_packet(packet, len);
	printf("DHCP REQUEST sent\r");
}

uint8_t receiveACK() {
	uint8_t packet[MAXPACKETLEN];
	DHCPMsg *m = (DHCPMsg*) packet;
	do {
		GetPacket(UDPPROTOCOL, packet);
	} while (!(m->udp.destPort == (uint16_t) HTONS(68) && m->op == DHCP_REPLY
			&& memcmp(m->xid, xid, sizeof(xid)) == 0
			&& memcmp(m->chaddr, deviceMAC, sizeof(deviceMAC)) == 0));

	//Parse options
	uint8_t *optPtr = &m->options[4];
	uint16_t totalLen = HTONS(m->udp.ip.len) + sizeof(EtherNetII);
	uint8_t* endPtr = packet + totalLen;
	uint8_t type = 0;

	while (optPtr < endPtr) {
		switch (*optPtr) {
		case DHCP_OPTION_MSG_TYPE:
			type = *(optPtr + 2);
			break;
		case DHCP_OPTION_END:
			break;
		}

		optPtr += optPtr[1] + 2;
	}
	return type;
}
