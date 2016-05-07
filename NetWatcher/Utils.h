#pragma once
class Utils
{
public:
	Utils();
	~Utils();
	static CString long2ip(ULONG in);
	static UINT atoi(const u_char *in, u_short len);
};
