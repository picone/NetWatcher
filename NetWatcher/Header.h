#pragma once
#include "stdafx.h"

typedef struct
{
	u_char dest[6];//目的MAC
	u_char src[6];//源MAC
	u_char type[2];//帧类型
}ethernet_header;

/* 4字节的IP地址 */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char  version;//版本
	u_char  type_of_service;//区分服务
	u_short header_len;//总长度
	u_short identification;// 标识
	u_char flag;//标志
	u_char fragment_offset;//片偏移
	u_char time_to_live;//生存时间
	u_char protocol;//协议
	u_char crc[2];//首部校验和
	ip_address src_address;//源地址
	ip_address dst_address;//目的地址
	u_int option_padding;//选项与填充
}ip_header;
