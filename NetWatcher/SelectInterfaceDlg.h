#pragma once
#include "afxcmn.h"


// CSelectInterfaceDlg �Ի���

class CSelectInterfaceDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CSelectInterfaceDlg)

public:
	CSelectInterfaceDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSelectInterfaceDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SELECTINTERFACEDLG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
private:
	CListCtrl m_list;
	void initView();
	void initData();
public:
	virtual BOOL OnInitDialog();
};
