
// NetWatcher.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CNetWatcherApp: 
// �йش����ʵ�֣������ NetWatcher.cpp
//

class CNetWatcherApp : public CWinApp
{
public:
	CNetWatcherApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CNetWatcherApp theApp;