// SelectInterfaceDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "NetWatcher.h"
#include "SelectInterfaceDlg.h"
#include "afxdialogex.h"
#include "pcap.h"


// CSelectInterfaceDlg 对话框

IMPLEMENT_DYNAMIC(CSelectInterfaceDlg, CDialogEx)

CSelectInterfaceDlg::CSelectInterfaceDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SELECTINTERFACEDLG, pParent)
{

	pcap_if_t *all_devices;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,&all_devices, errbuf) == -1)
	{
		AfxMessageBox(CString(errbuf));
		EndDialog(0);
	}
	else
	{
		int num = 0;
		for (pcap_if_t *p = all_devices; p != NULL; p = p->next)
		{
			AfxMessageBox(CString(p->description));
			num++;
		}
		if (num == 0)
		{
			AfxMessageBox(_T("找不到网卡!"));
		}
		pcap_freealldevs(all_devices);
	}
}

CSelectInterfaceDlg::~CSelectInterfaceDlg()
{
}

void CSelectInterfaceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CSelectInterfaceDlg, CDialogEx)
END_MESSAGE_MAP()


// CSelectInterfaceDlg 消息处理程序
