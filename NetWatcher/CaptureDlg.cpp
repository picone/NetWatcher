// CaptureDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "pcap.h"
#include "NetWatcher.h"
#include "CaptureDlg.h"
#include "afxdialogex.h"
#include "Header.h"
#include "Utils.h"
#include <atlconv.h>


// CCaptureDlg 对话框

IMPLEMENT_DYNAMIC(CCaptureDlg, CDialogEx)

CCaptureDlg::CCaptureDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_CAPTUREDLG, pParent)
	, m_interface_description(_T(""))
	, m_filename(_T(""))
	, m_filter(_T(""))
	, pPcap(NULL)
	, capture_thread(NULL)
	, is_suspend(FALSE)
	, m_packet_total(0)
	, m_packet_ipv4(0)
	, m_packet_ipv6(0)
	, m_packet_arp(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

CCaptureDlg::~CCaptureDlg()
{
}

void CCaptureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_INTERFACE_DESCRIPTION, m_interface_description);
	DDX_Text(pDX, IDC_FILENAME, m_filename);
	DDX_Text(pDX, IDC_FILTER, m_filter);
	DDX_Text(pDX, IDC_TOTAL, m_packet_total);
	DDX_Text(pDX, IDC_IPV4, m_packet_ipv4);
	DDX_Text(pDX, IDC_IPV6, m_packet_ipv6);
	DDX_Text(pDX, IDC_ARP, m_packet_arp);
	DDX_Control(pDX, IDC_COMMAND, m_command);
}

void CCaptureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CCaptureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CCaptureDlg::setFilename(LPCTSTR filename)
{
	m_filename = CString(filename);
}

void CCaptureDlg::setFilter(LPCTSTR filter)
{
	m_filter = CString(filter);
}

void CCaptureDlg::setInterfaceName(LPCTSTR interface_name)
{
	m_interface_name = CString(interface_name);
}

void CCaptureDlg::setInterfaceDescription(LPCTSTR interface_description)
{
	m_interface_description = CString(interface_description);
}

pcap_t *CCaptureDlg::getPcap()
{
	return pPcap;
}

pcap_dumper_t *CCaptureDlg::getPcapDumper()
{
	return pDumpFile;
}

void CCaptureDlg::incPacketTotal()
{
	m_packet_total++;
}

void CCaptureDlg::incPacketIPv4()
{
	m_packet_ipv4++;
}

void CCaptureDlg::incPacketIPv6()
{
	m_packet_ipv6++;
}

void CCaptureDlg::incPacketArp()
{
	m_packet_arp++;
}

BOOL CCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	ModifyStyleEx(0, WS_EX_APPWINDOW);
	ShowWindow(SW_SHOW);
	SetIcon(m_hIcon, TRUE);         // 设置大图标
    SetIcon(m_hIcon, FALSE);        // 设置小图标

	if (!initData())
	{
		if (pPcap != NULL)pcap_close(pPcap);
		CDialogEx::OnCancel();
		return FALSE;
	}
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

BEGIN_MESSAGE_MAP(CCaptureDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CCaptureDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_COMMAND, &CCaptureDlg::OnBnClickedCommand)
	ON_MESSAGE(WM_UPDATE_DATA, &CCaptureDlg::OnUpdateData)
//ON_REGISTERED_MESSAGE(WM_UPDATE_DATA, &CCaptureDlg::OnUpdateData)
END_MESSAGE_MAP()

BOOL CCaptureDlg::initData()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_code;
	USES_CONVERSION;
	SetWindowText(_T("抓包中：") + m_interface_name);

	pPcap = pcap_open(W2CA(m_interface_name), 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (pPcap == NULL)
	{
		AfxMessageBox(CString(errbuf));
		return FALSE;
	}
	if (pcap_datalink(pPcap) != DLT_EN10MB)
	{
		AfxMessageBox(_T("不支持的网卡类型"));
		return FALSE;
	}
	if (!m_filter.IsEmpty())//如果有过滤器
	{
		if (pcap_compile(pPcap, &filter_code, W2CA(m_filter), 1, 0xFFFFFF) < 0)
		{
			AfxMessageBox(_T("过滤器有误"));
			return FALSE;
		}
		if (pcap_setfilter(pPcap, &filter_code) < 0)
		{
			AfxMessageBox(_T("设置过滤器失败"));
			return FALSE;
		}
	}
	pDumpFile = pcap_dump_open(pPcap, W2CA(m_filename));
	if (pDumpFile == NULL)
	{
		AfxMessageBox(_T("打开文件有误"));
		return FALSE;
	}
	capture_thread = AfxBeginThread((AFX_THREADPROC)captureThread, this);
	return TRUE;
}

DWORD WINAPI CCaptureDlg::captureThread(LPVOID lpParameter)
{
	CCaptureDlg *dlg = (CCaptureDlg*)lpParameter;
	pcap_loop(dlg->getPcap(), 0, captureCallback, (PUCHAR)lpParameter);
	return 0;
}

void CCaptureDlg::captureCallback(u_char *user_p, const struct pcap_pkthdr *header,const u_char *pkt_data)
{
	CCaptureDlg *dlg = (CCaptureDlg*)user_p;
	u_short type;
	if (dlg == NULL) return;
	pcap_dump((PUCHAR)dlg->getPcapDumper(), header, pkt_data);
	ethernet_header *frame = (ethernet_header*)pkt_data;//二层帧解析
	//u_short type = (u_short)frame->type[0]*16*16+ (u_short)frame->type[1];
	type = Utils::atoi(frame->type,2);
	switch (type)
	{
	case TYPE_IPV4://IPv4
	{
		dlg->incPacketIPv4();
		ip_header *p = (ip_header *)(pkt_data + sizeof(ethernet_header));
		//TODO

		type = p->protocol;
		break;
	}
	case TYPE_ARP://ARP
		dlg->incPacketArp();
		break;
	case TYPE_IPV6://IPv6
		dlg->incPacketIPv6();
		break;
	}
	dlg->incPacketTotal();
	dlg->SendMessage(WM_UPDATE_DATA, FALSE);
}

// CCaptureDlg 消息处理程序
void CCaptureDlg::OnBnClickedOk()
{
	if (capture_thread != NULL)
	{
		if (!is_suspend)capture_thread->SuspendThread();
		TerminateThread(capture_thread, 0);
		delete capture_thread;
		capture_thread = NULL;
		pcap_breakloop(pPcap);
		pcap_dump_flush(pDumpFile);
		pcap_dump_close(pDumpFile);
		pcap_close(pPcap);
	}
}

void CCaptureDlg::OnBnClickedCommand()
{
	if (is_suspend)
	{
		capture_thread->ResumeThread();
		m_command.SetWindowTextW(_T("暂停"));
		is_suspend = FALSE;
	}
	else
	{
		capture_thread->SuspendThread();
		m_command.SetWindowTextW(_T("继续"));
		is_suspend = TRUE;
	}
}

afx_msg LRESULT CCaptureDlg::OnUpdateData(WPARAM wParam, LPARAM lParam)
{
	UpdateData(wParam);
	return 0;
}
