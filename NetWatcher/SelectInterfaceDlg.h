#pragma once
#include "afxcmn.h"


// CSelectInterfaceDlg 对话框

class CSelectInterfaceDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CSelectInterfaceDlg)

public:
	CSelectInterfaceDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CSelectInterfaceDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SELECTINTERFACEDLG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
private:
	CListCtrl m_list;
	void initView();
	void initData();
public:
	virtual BOOL OnInitDialog();
};
