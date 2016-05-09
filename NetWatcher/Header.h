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
typedef struct{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct{
	u_char header_length:4;//�ײ�����
	u_char version:4;//�汾
	u_char type_of_service:6;//���ַ���
	u_char congestion_notification : 2;//ӵ��֪ͨ
	u_short total_length;//�ܳ���
	u_short identification;// ��ʶ
	u_short flag_fragment_offset;//��־��Ƭƫ��
	u_char time_to_live;//����ʱ��
	u_char protocol;//Э��
	u_short crc;//�ײ�У���
	ip_address src_address;//Դ��ַ
	ip_address dst_address;//Ŀ�ĵ�ַ
	u_int option_padding;//ѡ�������
}ip_header;

typedef struct {
	u_char byte1[2];
	u_char byte2[2];
	u_char byte3[2];
	u_char byte4[2];
	u_char byte5[2];
	u_char byte6[2];
	u_char byte7[2];
	u_char byte8[2];
}ipv6_address;

typedef struct {
	u_char version:4;//�汾��
	u_char traffic_class;//�������
	u_long flow_label:20;//����ǩ
	u_char playload_length[2];//�غɳ���
	u_char next_header;//ָ������IP�ײ��������һ���ײ�������
	u_char hop_limit;//��ÿ������˰��Ľڵ㴦��1������������Ƽ���0���������˰�
	ipv6_address src_address;//Դ��ַ
	ipv6_address dst_address;//Ŀ�ĵ�ַ
}ipv6_header;

typedef struct {
	u_char src_port[2];//��Դ�˿�
	u_char dst_port[2];//Ŀ�Ķ˿�
	u_int sequence;//���к���
	u_int acknowledge;//ȷ�Ϻ���
	u_char offset : 4;//�ײ�����
	u_char reserved : 3;//����
	u_char NS : 1;//��ʱ���α���
	u_char CWR : 1;//ӵ�����ٴ���
	u_char ECE : 1;
	u_char URG : 1;//������־
	u_char ACK : 1;//ȷ���ֶ���Ч
	u_char PSH : 1;//���콻��
	u_char RST : 1;//Ҫ������
	u_char SYN : 1;//�������Ӻ�ʹ˳���ͬ��
	u_char FIN : 1;//�ͷ�����
	u_short window;//���ڴ�С
	u_short checksum;//�����
	u_short urgent_pointer;//����ָ��
}tcp_header;

typedef struct {
	u_char src_port[2];//Դ�˿�
	u_char dst_port[2];//Ŀ�Ķ˿�
	u_short length;//������
	u_short checksum;//У���
}udp_header;
