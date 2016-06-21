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
	, m_packet_icmp(0)
	, m_packet_tcp(0)
	, m_packet_udp(0)
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
	DDX_Text(pDX, IDC_ICMP, m_packet_icmp);
	DDX_Text(pDX, IDC_TCP, m_packet_tcp);
	DDX_Text(pDX, IDC_UDP, m_packet_udp);
	DDX_Control(pDX, IDC_PORT_SRC_LIST, m_port_src_list);
	DDX_Control(pDX, IDC_PORT_DST_LIST, m_port_dst_list);
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

void CCaptureDlg::incPacketICMP()
{
	m_packet_icmp++;
}

void CCaptureDlg::incPacketTCP()
{
	m_packet_tcp++;
}

void CCaptureDlg::incPacketUDP()
{
	m_packet_udp++;
}

void CCaptureDlg::incPacketPortSrc(u_short port)
{
	UINT old_num=0;
	if (m_packet_port_src.Lookup(port, old_num))
	{
		m_packet_port_src[port] = old_num + 1;
	}
	else
	{
		m_packet_port_src[port] = 1;
	}
}

void CCaptureDlg::incPacketPortDst(u_short port)
{
	UINT old_num = 0;
	if (m_packet_port_dst.Lookup(port, old_num))
	{
		m_packet_port_dst[port] = old_num + 1;
	}
	else
	{
		m_packet_port_dst[port] = 1;
	}
}

BOOL CCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	ModifyStyleEx(0, WS_EX_APPWINDOW);
	ShowWindow(SW_SHOW);
	SetIcon(m_hIcon, TRUE);         // 设置大图标
    SetIcon(m_hIcon, FALSE);        // 设置小图标

	initView();
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
	ON_MESSAGE(WM_UPDATE_LISTVIEW, &CCaptureDlg::OnUpdateListView)
END_MESSAGE_MAP()

void CCaptureDlg::initView()
{
	m_port_src_list.SetExtendedStyle(m_port_src_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_port_src_list.InsertColumn(0, _T("源端口"), LVCFMT_LEFT, 70);
	m_port_src_list.InsertColumn(1, _T("包数"), LVCFMT_LEFT, 70);
	m_port_dst_list.SetExtendedStyle(m_port_dst_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_port_dst_list.InsertColumn(0, _T("目标端口"), LVCFMT_LEFT, 70);
	m_port_dst_list.InsertColumn(1, _T("包数"), LVCFMT_LEFT, 70);
}

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
	AfxBeginThread((AFX_THREADPROC)updateListViewThread, this);
	return TRUE;
}

DWORD WINAPI CCaptureDlg::captureThread(LPVOID lpParameter)
{
	CCaptureDlg *dlg = (CCaptureDlg*)lpParameter;
	pcap_loop(dlg->getPcap(), 0, captureCallback, (PUCHAR)lpParameter);
	return 0;
}

DWORD WINAPI CCaptureDlg::updateListViewThread(LPVOID lpParameter)
{
	CCaptureDlg *dlg = (CCaptureDlg*)lpParameter;
	while (dlg->isRunning())
	{
		if (!dlg->is_suspend)dlg->SendMessage(WM_UPDATE_LISTVIEW);
		Sleep(5000);
	}
	return 0;
}

void CCaptureDlg::captureCallback(u_char *user_p, const struct pcap_pkthdr *header,const u_char *pkt_data)
{
	CCaptureDlg *dlg = (CCaptureDlg*)user_p;
	u_short type;
	if (dlg == NULL) return;
	pcap_dump((PUCHAR)dlg->getPcapDumper(), header, pkt_data);
	ethernet_header *frame = (ethernet_header*)pkt_data;//二层帧解析
	type = Utils::atoi(frame->type,2);
	switch (type)
	{
	case TYPE_IPV4://IPv4
	{
		dlg->incPacketIPv4();
		ip_header *ip = (ip_header *)(pkt_data + sizeof(ethernet_header));
		switch (ip->protocol)
		{
		case PROTOCAL_ICMP:
		{
			dlg->incPacketICMP();
			break;
		}
		case PROTOCAL_TCP:
		{
			dlg->incPacketTCP();
			tcp_header *tcp = (tcp_header*)(pkt_data + sizeof(ethernet_header) + ip->header_length * 4);
			dlg->incPacketPortSrc(Utils::atoi(tcp->src_port, 2));
			dlg->incPacketPortDst(Utils::atoi(tcp->dst_port, 2));
			break;
		}
		case PROTOCAL_UDP:
		{
			dlg->incPacketUDP();
			udp_header *udp = (udp_header*)(pkt_data + sizeof(ethernet_header) + ip->header_length * 4);
			dlg->incPacketPortSrc(Utils::atoi(udp->src_port, 2));
			dlg->incPacketPortDst(Utils::atoi(udp->dst_port, 2));
			break;
		}
		}
		break;
	}
	case TYPE_ARP://ARP
		dlg->incPacketArp();
		break;
	case TYPE_IPV6://IPv6
	{
		dlg->incPacketIPv6();
		ipv6_header *p = (ipv6_header *)(pkt_data + sizeof(ethernet_header));
		switch (p->next_header)
		{
		case PROTOCAL_IPV6_ICMP:
		{
			dlg->incPacketICMP();
			break;
		}
		}
		break;
	}
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
		m_command.EnableWindow(FALSE);
	}
	if (AfxMessageBox(_T("是否打开文件?"), MB_OKCANCEL) == IDOK) {
		ShellExecute(NULL, _T("open"), _T("capture.cap"), NULL, NULL, SW_NORMAL);
	}
	CDialogEx::OnOK();
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

BOOL CCaptureDlg::isRunning()
{
	return capture_thread != NULL;
}

afx_msg LRESULT CCaptureDlg::OnUpdateData(WPARAM wParam, LPARAM lParam)
{
	UpdateData(wParam);
	return 0;
}

afx_msg LRESULT CCaptureDlg::OnUpdateListView(WPARAM wParam, LPARAM lParam)
{
	POSITION pos;
	u_short port;
	UINT num;
	u_short row = 0;
	CString buffer;
	m_port_src_list.DeleteAllItems();
	pos = m_packet_port_src.GetStartPosition();
	while (pos)
	{
		m_packet_port_src.GetNextAssoc(pos, port, num);
		buffer.Format(_T("%d"), port);
		m_port_src_list.InsertItem(row, buffer);
		buffer.Format(_T("%d"), num);
		m_port_src_list.SetItemText(row, 1, buffer);
		row++;
	}
	row = 0;
	m_port_dst_list.DeleteAllItems();
	pos = m_packet_port_dst.GetStartPosition();
	while (pos)
	{
		m_packet_port_dst.GetNextAssoc(pos, port, num);
		buffer.Format(_T("%d"), port);
		m_port_dst_list.InsertItem(row, buffer);
		buffer.Format(_T("%d"), num);
		m_port_dst_list.SetItemText(row, 1, buffer);
		row++;
	}
	return 0;
}
