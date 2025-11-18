#pragma once
#include "afxdialogex.h"


// LoginDlg dialog

class LoginDlg : public CDialogEx
{
	DECLARE_DYNAMIC(LoginDlg)

public:
	LoginDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~LoginDlg();

	virtual void OnFinalRelease();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_Login };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
	DECLARE_DISPATCH_MAP()
	DECLARE_INTERFACE_MAP()
public:
	afx_msg void OnBnClickedLogin();
	afx_msg void OnBnClickedRegisterlink();
private:
	bool PerformLogin(const CString& username, const CString& password);
	bool SendLoginRequest(SOCKET socket, const CString& username, const CString& password);
	bool ReceiveLoginResponse(SOCKET socket, int& userId, CString& serverUserName, CString& detail);
protected:
	virtual BOOL OnInitDialog();
	virtual void OnOK();
};
