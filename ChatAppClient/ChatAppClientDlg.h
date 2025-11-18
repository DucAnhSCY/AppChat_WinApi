// ChatAppClientDlg.h : header file
//

#pragma once
#include "Struct.h"
#include <map>


// CChatAppClientDlg dialog
class CChatAppClientDlg : public CDialogEx
{
// Construction
public:
	CChatAppClientDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CHATAPPCLIENT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	virtual void OnOK();


// Implementation
protected:
	HICON m_hIcon;
	SOCKET m_listenSocket = INVALID_SOCKET;
	// user list is sourced from the list control (server-provided); no in-memory vector kept
	CRITICAL_SECTION m_csClients;
	int m_myClientId = 0;
	BOOL m_bServerRunning = FALSE;
	BOOL m_isAuthenticated = FALSE;
	int m_authenticatedUserId = 0;
	CString m_authenticatedUsername;
	BOOL RegisterAutoRun(BOOL bRegister);
	BOOL IsAutoRunEnabled();
	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	void Connect();
	static UINT ConnectServerThread(LPVOID pParam);
	static UINT ClientThreadProc(LPVOID pParam);
	void AddMessageToList(const Msg& msg);
	void UpdateUserList(const UserListUpdate& userList);
	void HandleLoginResult(const LoginResult& result);
	bool SendLoginRequest();
	void HandleChatHistory(const ChatHistoryResponse& response);
	bool RequestChatHistory(int friendUserId);
	CListCtrl list_message;
	CListCtrl list_user;
	CString GetUserNameFromList(int userId);
	afx_msg void OnBnClickedButtonSend();
	afx_msg void OnBnClickedButtonSaveMessage();
	CWinThread* pConnecttThread = nullptr;
protected:
	afx_msg void OnLvnItemchangedListUser(NMHDR* pNMHDR, LRESULT* pResult);
private:
	int m_currentFriendUserId;
	bool SaveCurrentConversationToFile();
	std::map<int,int> m_unreadCounts;
	void UpdateUserBadge(int userId);
};
