#pragma once
#include "stdafx.h"

//��̫��֡֡ͷ����
#define TYPE_IPV4 0x0800
#define TYPE_ARP 0x0806
#define TYPE_IPV6 0x86DD

#define PROTOCAL_ICMP 0x01
#define PROTOCAL_TCP 0x06
#define PROTOCAL_UDP 0x11
#define PROTOCAL_IPV6_ICMP 0x3A

typedef struct
{
	u_char dest[6];//Ŀ��MAC
	u_char src[6];//ԴMAC
	u_char type[2];//֡����
}ethernet_header;

/* 4�ֽڵ�IP��ַ */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char  version;//�汾
	u_char  type_of_service;//���ַ���
	u_short header_len;//�ܳ���
	u_short identification;// ��ʶ
	u_char flag;//��־
	u_char fragment_offset;//Ƭƫ��
	u_char time_to_live;//����ʱ��
	u_char protocol;//Э��
	u_char crc[2];//�ײ�У���
	ip_address src_address;//Դ��ַ
	ip_address dst_address;//Ŀ�ĵ�ַ
	u_int option_padding;//ѡ�������
}ip_header;
