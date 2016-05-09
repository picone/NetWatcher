#pragma once
#include "stdafx.h"

//以太网帧帧头类型
#define TYPE_IPV4 0x0800
#define TYPE_ARP 0x0806
#define TYPE_IPV6 0x86DD

#define PROTOCAL_ICMP 0x01
#define PROTOCAL_TCP 0x06
#define PROTOCAL_UDP 0x11
#define PROTOCAL_IPV6_ICMP 0x3A

typedef struct
{
	u_char dest[6];//目的MAC
	u_char src[6];//源MAC
	u_char type[2];//帧类型
}ethernet_header;

/* 4字节的IP地址 */
typedef struct{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct{
	u_char header_length:4;//首部长度
	u_char version:4;//版本
	u_char type_of_service:6;//区分服务
	u_char congestion_notification : 2;//拥塞通知
	u_short total_length;//总长度
	u_short identification;// 标识
	u_short flag_fragment_offset;//标志和片偏移
	u_char time_to_live;//生存时间
	u_char protocol;//协议
	u_short crc;//首部校验和
	ip_address src_address;//源地址
	ip_address dst_address;//目的地址
	u_int option_padding;//选项与填充
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
	u_char version:4;//版本号
	u_char traffic_class;//传输类别
	u_long flow_label:20;//流标签
	u_char playload_length[2];//载荷长度
	u_char next_header;//指明紧跟IP首部后面的下一个首部的类型
	u_char hop_limit;//在每个传输此包的节点处减1，如果跳数限制减到0，就抛弃此包
	ipv6_address src_address;//源地址
	ipv6_address dst_address;//目的地址
}ipv6_header;

typedef struct {
	u_char src_port[2];//来源端口
	u_char dst_port[2];//目的端口
	u_int sequence;//序列号码
	u_int acknowledge;//确认号码
	u_char offset : 4;//首部长度
	u_char reserved : 3;//保留
	u_char NS : 1;//临时隐蔽保护
	u_char CWR : 1;//拥塞减少窗口
	u_char ECE : 1;
	u_char URG : 1;//紧急标志
	u_char ACK : 1;//确认字段有效
	u_char PSH : 1;//尽快交付
	u_char RST : 1;//要求重连
	u_char SYN : 1;//创建连接和使顺序号同步
	u_char FIN : 1;//释放连接
	u_short window;//窗口大小
	u_short checksum;//检验和
	u_short urgent_pointer;//紧急指针
}tcp_header;

typedef struct {
	u_char src_port[2];//源端口
	u_char dst_port[2];//目的端口
	u_short length;//包长度
	u_short checksum;//校验和
}udp_header;
