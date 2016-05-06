// SelectInterfaceDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Utils.h"
#include "NetWatcher.h"
#include "SelectInterfaceDlg.h"
#include "CaptureDlg.h"
#include "afxdialogex.h"
#include "pcap.h"

// CSelectInterfaceDlg 对话框

IMPLEMENT_DYNAMIC(CSelectInterfaceDlg, CDialogEx)

CSelectInterfaceDlg::CSelectInterfaceDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SELECTINTERFACEDLG, pParent)
	, m_filter(_T(""))
	, m_filename(_T("capture.cap"))
{

}

CSelectInterfaceDlg::~CSelectInterfaceDlg()
{
}

void CSelectInterfaceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_INTERFACE, m_list);
	DDX_Text(pDX, IDC_FILTER, m_filter);
	DDX_Text(pDX, IDC_FILENAME, m_filename);
}


BEGIN_MESSAGE_MAP(CSelectInterfaceDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CSelectInterfaceDlg::OnBnClickedOk)
END_MESSAGE_MAP()

BOOL CSelectInterfaceDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	initView();
	initData();
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

void CSelectInterfaceDlg::initView()
{
	m_list.SetExtendedStyle(m_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list.InsertColumn(0,_T("接口名称"),LVCFMT_LEFT,150);
	m_list.InsertColumn(1,_T("接口描述"),LVCFMT_LEFT,310);
	m_list.InsertColumn(2, _T("IPv4地址"), LVCFMT_LEFT, 90);
}

void CSelectInterfaceDlg::initData()
{
	pcap_if_t *all_devices;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devices, errbuf) == -1)
	{
		AfxMessageBox(CString(errbuf));
		CDialogEx::OnCancel();
	}
	else
	{
		int num = 0;
		for (pcap_if_t *p = all_devices; p != NULL; p = p->next)
		{
			m_list.InsertItem(num,CString(p->name));
			m_list.SetItemText(num, 1,CString(p->description));
			for (pcap_addr_t *addr = p->addresses; addr != NULL; addr = addr->next)
			{
				if (addr->addr->sa_family == AF_INET)
				{
					m_list.SetItemText(num, 2, Utils::long2ip(((struct sockaddr_in *)addr->addr)->sin_addr.s_addr));
				}
			}

			num++;
		}
		if (num == 0)
		{
			AfxMessageBox(_T("找不到网卡!"));
			CDialogEx::OnCancel();
		}
		pcap_freealldevs(all_devices);
	}
}

// CSelectInterfaceDlg 消息处理程序
void CSelectInterfaceDlg::OnBnClickedOk()
{
	UpdateData();
	POSITION pos=m_list.GetFirstSelectedItemPosition();
	int row;
	if (pos == NULL)
	{
		AfxMessageBox(_T("请选择一个网卡"));
		return;
	}
	if (m_filename.GetLength() == 0)
	{
		AfxMessageBox(_T("请输入文件名"));
		return;
	}
	row = m_list.GetNextSelectedItem(pos);
	ShowWindow(SW_HIDE);
	CCaptureDlg capture_dlg;
	capture_dlg.setFilename(m_filename);
	capture_dlg.setFilter(m_filter);
	capture_dlg.setInterfaceName(m_list.GetItemText(row, 0));
	capture_dlg.setInterfaceDescription(m_list.GetItemText(row, 1));
	capture_dlg.DoModal();
	CDialogEx::OnOK();
}
