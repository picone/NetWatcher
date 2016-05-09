#pragma once
#include "pcap.h"
#include "afxwin.h"

// CCaptureDlg 对话框

class CCaptureDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CCaptureDlg)

public:
	CCaptureDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CCaptureDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CAPTUREDLG };
#endif

protected:
	HICON m_hIcon;
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnUpdateData(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	void setFilename(LPCTSTR filename);
	void setFilter(LPCTSTR filter);
	void setInterfaceName(LPCTSTR interface_name);
	void setInterfaceDescription(LPCTSTR interface_description);
	pcap_t *getPcap();
	pcap_dumper_t *getPcapDumper();
	void incPacketTotal();
	void incPacketIPv4();
	void incPacketIPv6();
	void incPacketArp();
	void incPacketICMP();
	void incPacketTCP();
	void incPacketUDP();
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCommand();
private:
	CString m_filename;
	CString m_filter;
	CString m_interface_name;
	CString m_interface_description;
	pcap_t *pPcap;
	pcap_dumper_t *pDumpFile;
	CWinThread *capture_thread;
	BOOL is_suspend;
	CButton m_command;
	UINT m_packet_total;
	UINT m_packet_ipv4;
	UINT m_packet_ipv6;
	UINT m_packet_arp;
	UINT m_packet_icmp;
	UINT m_packet_tcp;
	UINT m_packet_udp;
	BOOL initData();
	static DWORD WINAPI captureThread(LPVOID lpParameter);
	static void captureCallback(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data);
};
