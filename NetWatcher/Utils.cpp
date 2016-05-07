#include "stdafx.h"
#include "Utils.h"

#define IPTOSBUFFERS    12
Utils::Utils()
{
}


Utils::~Utils()
{
}

CString Utils::long2ip(ULONG in)
{
	CString result;
	u_char *p;
	p=(u_char *)&in;
	result.Format(_T("%d.%d.%d.%d"), p[0], p[1], p[2], p[3]);
	return result;
}

UINT Utils::atoi(const u_char * in, u_short len)
{
	UINT result = 0;
	UINT o=1;
	for (int i = len-1; i >= 0; i--)
	{
		result+=in[i]*o;
		o *= 16 * 16;
	}
	return result;
}
