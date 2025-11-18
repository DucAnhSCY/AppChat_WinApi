#pragma once
#include "afxdialogex.h"


// RegisterDlg dialog

class RegisterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(RegisterDlg)

public:
	RegisterDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~RegisterDlg();
	CString GetRegisteredUsername() const { return m_registeredUsername; }

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_Register };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedRegister();
	afx_msg void OnBnClickedLoginlink();
private:
	CString m_registeredUsername;
};
