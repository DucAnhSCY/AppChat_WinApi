// ChatAppClientDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "ChatAppClient.h"
#include "ChatAppClientDlg.h"
#include "LoginDlg.h"
#include "Struct.h"
#include "afxdialogex.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <Shlobj.h>
#include <map>
#include <vector>
#include <string>
#pragma comment(lib, "Shell32.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

namespace
{
bool SendAll(SOCKET socket, const void *data, int length)
{
	const char *buffer = static_cast<const char *>(data);
	int total = 0;
	while (total < length)
	{
		int sent = send(socket, buffer + total, length - total, 0);
		if (sent == SOCKET_ERROR || sent == 0)
		{
			return false;
		}
		total += sent;
	}
	return true;
}
}

// CAboutDlg dialog used for App About
using namespace std;
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CChatAppClientDlg dialog



CChatAppClientDlg::CChatAppClientDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_CHATAPPCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	InitializeCriticalSection(&m_csClients);
	m_isAuthenticated = FALSE;
	m_authenticatedUserId = 0;
	m_currentFriendUserId = 0;
}

void CChatAppClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_SCREEN, list_message);
	DDX_Control(pDX, IDC_LIST_USER, list_user);
}

BEGIN_MESSAGE_MAP(CChatAppClientDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_SEND, &CChatAppClientDlg::OnBnClickedButtonSend)
	ON_BN_CLICKED(IDC_BUTTON_Save_Message, &CChatAppClientDlg::OnBnClickedButtonSaveMessage)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_USER, &CChatAppClientDlg::OnLvnItemchangedListUser)
END_MESSAGE_MAP()


// CChatAppClientDlg message handlers

BOOL CChatAppClientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	list_message.InsertColumn(0, L"Sender", LVCFMT_LEFT, 100);
	list_message.InsertColumn(1, L"Time", LVCFMT_LEFT, 100);
	list_message.InsertColumn(2, L"Message", LVCFMT_LEFT, 300);
	list_user.InsertColumn(0, L"User", LVCFMT_LEFT, 200);
	list_message.SetExtendedStyle(list_message.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	list_user.SetExtendedStyle(list_user.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	SetDefID(IDC_BUTTON_SEND);
	Connect();
	if (!IsAutoRunEnabled())
	{
		RegisterAutoRun(TRUE);
	}
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CChatAppClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CChatAppClientDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CChatAppClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CChatAppClientDlg::OnOK()
{
	OnBnClickedButtonSend();
}

void CChatAppClientDlg::Connect()
{
	pConnecttThread = AfxBeginThread(ConnectServerThread, this);
}
UINT CChatAppClientDlg::ConnectServerThread(LPVOID pParam)
{
	CChatAppClientDlg* pDlg = (CChatAppClientDlg*)pParam;
	WSAData wsaData;
	int wsaerr;
	WORD wVersionRequested = MAKEWORD(2, 2);
	wsaerr = WSAStartup(wVersionRequested, &wsaData);
	if (wsaerr != 0) {
		pDlg->MessageBox(L"The Winsock dll not found!");
		return 0;
	}
	pDlg->m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (pDlg->m_listenSocket == INVALID_SOCKET) {
		pDlg->MessageBox(L"Socket creation failed!");
		WSACleanup();
		return 0;
	}
	sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(9999);
	InetPton(AF_INET, L"127.0.0.1", &server_addr.sin_addr);
	
	if (connect(pDlg->m_listenSocket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
		pDlg->MessageBox(L"Cannot connect to the server");
		closesocket(pDlg->m_listenSocket);
		WSACleanup();
		return 0;
	}
	
	pDlg->m_bServerRunning = TRUE;
	
	recv(pDlg->m_listenSocket, (char*)&pDlg->m_myClientId, sizeof(int), 0);

	CChatAppClientApp& app = theApp;
	pDlg->m_authenticatedUserId = app.m_authenticatedUserId;
	pDlg->m_authenticatedUsername = app.m_authenticatedUsername;

	CString resolvedUsername = pDlg->m_authenticatedUsername;
	if (resolvedUsername.IsEmpty()) {
		resolvedUsername.Format(L"Client%d", pDlg->m_myClientId);
	}
	pDlg->SetWindowText(resolvedUsername);

	ClientInfo* pClientInfo = new ClientInfo();
	pClientInfo->clientSocket = pDlg->m_listenSocket;
	pClientInfo->clientId = pDlg->m_myClientId;
	pClientInfo->userId = pDlg->m_authenticatedUserId;
	pClientInfo->username = resolvedUsername;
	pClientInfo->pDlg = pDlg;
	
	AfxBeginThread(ClientThreadProc, pClientInfo);

	if (!pDlg->SendLoginRequest()) {
		pDlg->MessageBox(L"Failed to send the login request to the server.", L"Error", MB_ICONERROR);
		closesocket(pDlg->m_listenSocket);
		pDlg->m_listenSocket = INVALID_SOCKET;
		pDlg->m_bServerRunning = FALSE;
		WSACleanup();
		return 0;
	}
	
	return 0;
}
UINT CChatAppClientDlg::ClientThreadProc(LPVOID pParam)
{
	ClientInfo* pClientInfo = (ClientInfo*)pParam;
	CChatAppClientDlg* pDlg = (CChatAppClientDlg*)pClientInfo->pDlg;

	while (true) {
		int packetType;
		int ret = recv(pClientInfo->clientSocket, (char*)&packetType, sizeof(int), 0);
		
		if (ret <= 0) {
			break;
		}
		
		if (packetType == PACKET_LOGIN_RESULT) {
			LoginResult loginResult = {};
			ret = recv(pClientInfo->clientSocket, (char*)&loginResult, sizeof(loginResult), 0);
			if (ret > 0) {
				pDlg->HandleLoginResult(loginResult);
			}
			else {
				break;
			}
		}
		else if (packetType == PACKET_MESSAGE) {
			Msg msg;
			ret = recv(pClientInfo->clientSocket, (char*)&msg, sizeof(msg), 0);
			
			if (ret > 0) {
				pDlg->AddMessageToList(msg);
			}
			else {
				break;
			}
		}
		else if (packetType == PACKET_USER_LIST) {
			UserListUpdate userList;
			ret = recv(pClientInfo->clientSocket, (char*)&userList, sizeof(userList), 0);
			
			if (ret > 0) {
				pDlg->UpdateUserList(userList);
			}
			else {
				break;
			}
		}
		else if (packetType == PACKET_CHAT_HISTORY) {
			ChatHistoryResponse history = {};
			ret = recv(pClientInfo->clientSocket, (char*)&history, sizeof(history), 0);
			if (ret > 0) {
				pDlg->HandleChatHistory(history);
			}
			else {
				break;
			}
		}
	}
	
	closesocket(pClientInfo->clientSocket);
	delete pClientInfo;

	return 0;
}
bool CChatAppClientDlg::SendLoginRequest()
{
	if (m_listenSocket == INVALID_SOCKET) {
		return false;
	}

	CChatAppClientApp& app = theApp;
	if (app.m_authenticatedUsername.IsEmpty() || app.m_authenticatedPasswordHash.IsEmpty()) {
		return false;
	}

	Msg msg = {};
	msg.targetUserId = 0;
	msg.senderUserId = m_authenticatedUserId;
	msg.time = std::time(nullptr);
	wcsncpy_s(msg.sender, app.m_authenticatedUsername, _TRUNCATE);
	wcsncpy_s(msg.message, app.m_authenticatedPasswordHash, _TRUNCATE);

	int command = static_cast<int>(ClientCommand::CMD_LOGIN);
	if (!SendAll(m_listenSocket, &command, sizeof(command)))
	{
		return false;
	}
	return SendAll(m_listenSocket, &msg, sizeof(msg));
}
void CChatAppClientDlg::HandleLoginResult(const LoginResult& result)
{
	if (result.success == 1) {
		m_isAuthenticated = TRUE;
		m_authenticatedUserId = result.userId;
		if (wcslen(result.username) > 0) {
			m_authenticatedUsername = result.username;
		}
		CString title = m_authenticatedUsername;
		if (title.IsEmpty()) {
			title.Format(L"Client%d", m_myClientId);
		}
		SetWindowText(title);
		CString notify = result.detail[0] != L'\0' ? result.detail : L"Login successful.";
		MessageBox(notify, L"Information", MB_ICONINFORMATION);
	}
	else {
		CString message = result.detail[0] != L'\0' ? result.detail : L"Login failed.";
		MessageBox(message, L"Login", MB_ICONERROR);
		m_isAuthenticated = FALSE;
		if (m_listenSocket != INVALID_SOCKET) {
			closesocket(m_listenSocket);
			m_listenSocket = INVALID_SOCKET;
		}
		m_bServerRunning = FALSE;
		WSACleanup();
		PostMessage(WM_CLOSE);
	}
}


void CChatAppClientDlg::OnBnClickedButtonSend()
{
	if (!m_isAuthenticated) {
		MessageBox(L"Please log in before sending messages.", L"Not Authenticated", MB_ICONWARNING);
		return;
	}
	Msg msg = {};
	GetDlgItemText(IDC_EDIT_SEND, msg.message, MAX_MESSAGE_LENGTH);
	
	if (wcslen(msg.message) == 0) {
		return;
	}
	
	CString sender = m_authenticatedUsername;
	if (sender.IsEmpty()) {
		GetWindowText(sender);
	}
	wcscpy_s(msg.sender, sender);
	msg.senderUserId = m_authenticatedUserId;
	msg.time = std::time(nullptr);
	int selectedIndex = list_user.GetNextItem(-1, LVNI_SELECTED);
	if (selectedIndex < 0) {
		MessageBox(L"Please select a user before sending a message.", L"Select Recipient", MB_ICONINFORMATION);
		return;
	}

	msg.targetUserId = static_cast<int>(list_user.GetItemData(selectedIndex));
	ClientCommand command = ClientCommand::CMD_PRIVATE_MESSAGE;
	
	int index = list_message.GetItemCount();
	CString senderDisplay;
	if (msg.sender[0] != L'\0') {
		senderDisplay = CString(msg.sender);
	} else {
		senderDisplay = GetUserNameFromList(msg.senderUserId);
		if (senderDisplay.IsEmpty()) senderDisplay = L"Unknown";
	}
	list_message.InsertItem(index, senderDisplay);
	CTime displayTime(msg.time);
	list_message.SetItemText(index, 1, displayTime.Format(L"%H:%M:%S"));
	list_message.SetItemText(index, 2, CString(msg.message));

	int commandValue = static_cast<int>(command);
	SendAll(m_listenSocket, &commandValue, sizeof(commandValue));
	SendAll(m_listenSocket, &msg, sizeof(msg));
	
	SetDlgItemText(IDC_EDIT_SEND, L"");
}
void CChatAppClientDlg::OnBnClickedButtonSaveMessage()
{
	if (m_currentFriendUserId <= 0) {
		MessageBox(L"Please select a conversation first.", L"Save Messages", MB_ICONINFORMATION);
		return ;
	}

	int itemCount = list_message.GetItemCount();
	if (itemCount == 0) {
		MessageBox(L"There are no messages to save.", L"Save Messages", MB_ICONINFORMATION);
		return ;
	}

	// Resolve friend name only from server-provided list control
	CString friendName = GetUserNameFromList(m_currentFriendUserId);
	if (friendName.IsEmpty()) friendName = L"Unknown";
	CString sanitizedName = friendName;
	sanitizedName.Trim();
	static const wchar_t* invalidChars = L"\\/:*?\"<>|";
	for (int i = 0; i < sanitizedName.GetLength(); ++i) {
		wchar_t ch = sanitizedName[i];
		if (ch < 32 || wcschr(invalidChars, ch) != nullptr) {
			sanitizedName.SetAt(i, L'_');
		}
	}
	if (sanitizedName.IsEmpty()) sanitizedName = L"conversation";
	wchar_t folderPath[MAX_PATH] = { 0 };
	HRESULT hr = SHGetFolderPath(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, folderPath);
	if (FAILED(hr) || folderPath[0] == L'\0') {
		if (GetModuleFileName(nullptr, folderPath, MAX_PATH) == 0) {
			MessageBox(L"Unable to determine the output folder.", L"Save Messages", MB_ICONERROR);
			return;
		}
		CString temp(folderPath);
		int lastSlash = temp.ReverseFind(L'\\');
		if (lastSlash != -1) {
			temp = temp.Left(lastSlash + 1);
		}
		else {
			temp = L".\\";
		}
		wcsncpy_s(folderPath, temp, _TRUNCATE);
	}

	CString folder(folderPath);
	folder.TrimRight();
	if (!folder.IsEmpty() && folder[folder.GetLength() - 1] != L'\\') {
		folder += L'\\';
	}

	CTime now = CTime::GetCurrentTime();
	CString fullPath;
	fullPath.Format(L"%sChat_%s_%04d%02d%02d_%02d%02d%02d.txt",
		folder.GetString(), sanitizedName.GetString(), now.GetYear(), now.GetMonth(), now.GetDay(),
		now.GetHour(), now.GetMinute(), now.GetSecond());

	HANDLE hFile = CreateFile(fullPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(L"Unable to create the output file.", L"Save Messages", MB_ICONERROR);
		return;
	}

	CString content;
	content.Format(L"Conversation with %s\r\nMessages: %d\r\n\r\n",
		friendName.IsEmpty() ? L"Unknown" : friendName.GetString(), itemCount);
	for (int i = 0; i < itemCount; ++i) {
		CString sender = list_message.GetItemText(i, 0);
		CString time = list_message.GetItemText(i, 1);
		CString message = list_message.GetItemText(i, 2);
		CString line;
		line.Format(L"[%s] %s: %s\r\n", time.GetString(), sender.GetString(), message.GetString());
		content += line;
	}

	DWORD written = 0;
	const wchar_t bom = 0xFEFF;
	if (!WriteFile(hFile, &bom, sizeof(bom), &written, nullptr)) {
		CloseHandle(hFile);
		MessageBox(L"Failed to write to the output file.", L"Save Messages", MB_ICONERROR);
		return;
	}

	DWORD bytesToWrite = static_cast<DWORD>(content.GetLength() * sizeof(wchar_t));
	if (bytesToWrite > 0) {
		written = 0;
		if (!WriteFile(hFile, content.GetString(), bytesToWrite, &written, nullptr)) {
			CloseHandle(hFile);
			MessageBox(L"Failed to write conversation content.", L"Save Messages", MB_ICONERROR);
			return;
		}
	}

	CloseHandle(hFile);

	CString notify;
	notify.Format(L"Messages saved to:\r\n%s", fullPath.GetString());
	MessageBox(notify, L"Save Messages", MB_ICONINFORMATION);
	return;
}


void CChatAppClientDlg::OnLvnItemchangedListUser(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	*pResult = 0;

	if ((pNMLV->uChanged & LVIF_STATE) == 0) {
		return;
	}

	bool selected = (pNMLV->uNewState & LVIS_SELECTED) != 0;
	bool wasSelected = (pNMLV->uOldState & LVIS_SELECTED) != 0;
	if (selected && !wasSelected) {
		int friendUserId = static_cast<int>(list_user.GetItemData(pNMLV->iItem));
		if (friendUserId > 0) {
			m_currentFriendUserId = friendUserId;
			list_message.DeleteAllItems();
			RequestChatHistory(friendUserId);
		}
	}
}
void CChatAppClientDlg::AddMessageToList(const Msg& msg)
{
	int senderId = msg.senderUserId;
	bool isCurrentConversation = (m_currentFriendUserId > 0 &&
		((senderId == m_currentFriendUserId && msg.targetUserId == m_authenticatedUserId) ||
		 (senderId == m_authenticatedUserId && msg.targetUserId == m_currentFriendUserId))) ||
		(senderId == m_currentFriendUserId && msg.targetUserId == 0);

	if (isCurrentConversation)
	{
		int n = list_message.GetItemCount();
		CTime displayTime;
		if (msg.time <= 0) {
			displayTime = CTime::GetCurrentTime();
		}
		else {
			displayTime = CTime(msg.time);
		}

		CString senderName;
		if (msg.sender[0] != L'\0')
		{
			senderName = msg.sender;
		}
		if (senderName.IsEmpty())
		{
			senderName = GetUserNameFromList(senderId);
		}
		if (senderName.IsEmpty() && senderId == m_authenticatedUserId)
		{
			senderName = m_authenticatedUsername;
		}
		if (senderName.IsEmpty())
		{
			senderName = L"Unknown";
		}

		list_message.InsertItem(n, senderName);
		list_message.SetItemText(n, 1, displayTime.Format(L"%H:%M:%S"));
		list_message.SetItemText(n, 2, CString(msg.message));
	}
	else if (senderId > 0 && senderId != m_authenticatedUserId)
	{
		m_unreadCounts[senderId]++;
		UpdateUserBadge(senderId);
	}
}

CString CChatAppClientDlg::GetUserNameFromList(int userId)
{
	for (int i = 0; i < list_user.GetItemCount(); ++i) {
		if (static_cast<int>(list_user.GetItemData(i)) == userId) {
			CString text = list_user.GetItemText(i, 0);
			int lp = text.ReverseFind(L'(');
			int rp = text.ReverseFind(L')');
			if (lp != -1 && rp > lp) {
				CString inside = text.Mid(lp + 1, rp - lp - 1);
				bool allDigits = true;
				for (int j = 0; j < inside.GetLength(); ++j) {
					if (!iswdigit(inside[j])) { allDigits = false; break; }
				}
				if (allDigits) {
					text = text.Left(lp);
					text.TrimRight();
				}
			}
			return text;
		}
	}
	return CString();
}
void CChatAppClientDlg::UpdateUserList(const UserListUpdate& userList) {
	// Populate list_user directly from server-provided userList (DB). Do not keep m_users cache.
	list_user.DeleteAllItems();
	int indexToSelect = -1;
	for (int i = 0; i < userList.count; i++)
	{
		int index = list_user.GetItemCount();
		list_user.InsertItem(index, userList.users[i].username);
		list_user.SetItemData(index, userList.users[i].userId);
		if (userList.users[i].userId == m_currentFriendUserId) {
			indexToSelect = index;
		}
	}

	if (list_user.GetItemCount() > 0) {
		if (indexToSelect == -1) {
			indexToSelect = 0;
			m_currentFriendUserId = static_cast<int>(list_user.GetItemData(indexToSelect));
		}
		list_user.SetItemState(indexToSelect, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
		list_user.EnsureVisible(indexToSelect, FALSE);
	}
	else {
		m_currentFriendUserId = 0;
		list_message.DeleteAllItems();
	}
}
bool CChatAppClientDlg::RequestChatHistory(int friendUserId)
{
	if (!m_isAuthenticated || m_listenSocket == INVALID_SOCKET || friendUserId <= 0) {
		return false;
	}

	Msg request = {};
	request.targetUserId = friendUserId;
	request.senderUserId = m_authenticatedUserId;
	request.time = std::time(nullptr);
	if (!m_authenticatedUsername.IsEmpty()) {
		wcsncpy_s(request.sender, m_authenticatedUsername, _TRUNCATE);
	}

	int command = static_cast<int>(ClientCommand::CMD_CHAT_HISTORY_REQUEST);
	if (!SendAll(m_listenSocket, &command, sizeof(command)))
	{
		return false;
	}
	return SendAll(m_listenSocket, &request, sizeof(request));
}
void CChatAppClientDlg::HandleChatHistory(const ChatHistoryResponse& response)
{
	if (response.friendUserId != m_currentFriendUserId) {
		return;
	}

	list_message.DeleteAllItems();
	for (int i = 0; i < response.count; ++i) {
		AddMessageToList(response.entries[i]);
	}
	auto it = m_unreadCounts.find(response.friendUserId);
	if (it != m_unreadCounts.end()) {
		m_unreadCounts.erase(it);
		UpdateUserBadge(response.friendUserId);
	}
}
void CChatAppClientDlg::UpdateUserBadge(int userId)
{
	int idx = -1;
	for (int i = 0; i < list_user.GetItemCount(); ++i) {
		if (static_cast<int>(list_user.GetItemData(i)) == userId) {
			idx = i;
			break;
		}
	}
	if (idx == -1) {
		return;
	}
	CString baseName = GetUserNameFromList(userId);
	if (baseName.IsEmpty()) baseName = L"Unknown";
	int count = 0;
	auto it = m_unreadCounts.find(userId);
	if (it != m_unreadCounts.end()) count = it->second;
	if (count > 0) {
		CString text;
		text.Format(L"%s (%d)", baseName.GetString(), count);
		list_user.SetItemText(idx, 0, text);
	}
	else {
		list_user.SetItemText(idx, 0, baseName);
	}
}




BOOL CChatAppClientDlg::RegisterAutoRun(BOOL bRegister)
{
	HKEY hKey;
	LONG result;
	CString appPath;
	CString appName = L"ChatAppClient_2";
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	appPath.Format(L"\"%s\"", szPath);
	result = RegOpenKeyEx(
		HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		0,
		KEY_SET_VALUE | KEY_QUERY_VALUE,
		&hKey
	);

	if (result != ERROR_SUCCESS)
	{
		MessageBox(L"Unable to open the Registry!", L"Error", MB_ICONERROR);
		return FALSE;
	}

	if (bRegister)
	{
		result = RegSetValueEx(
			hKey,
			appName,
			0,
			REG_SZ,
			(BYTE*)(LPCTSTR)appPath,
			(appPath.GetLength() + 1) * sizeof(TCHAR)
		);

		if (result == ERROR_SUCCESS)
		{
			MessageBox(L"Successfully registered to start with Windows!", L"Success", MB_ICONINFORMATION);
		}
		else
		{
			MessageBox(L"Failed to register startup!", L"Error", MB_ICONERROR);
		}
	}
	else
	{
		result = RegDeleteValue(hKey, appName);

		if (result == ERROR_SUCCESS)
		{
			MessageBox(L"Startup registration removed!", L"Success", MB_ICONINFORMATION);
		}
		else if (result == ERROR_FILE_NOT_FOUND)
		{
			MessageBox(L"Application is not registered for startup!", L"Information", MB_ICONINFORMATION);
		}
		else
		{
			MessageBox(L"Failed to remove startup registration!", L"Error", MB_ICONERROR);
		}
	}

	RegCloseKey(hKey);
	return (result == ERROR_SUCCESS);
}
BOOL CChatAppClientDlg::IsAutoRunEnabled()
{
	HKEY hKey;
	LONG result;
	CString appName = L"ChatAppClient_2";

	result = RegOpenKeyEx(
		HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		0,
		KEY_QUERY_VALUE,
		&hKey
	);

	if (result != ERROR_SUCCESS)
	{
		return FALSE;
	}

	DWORD dwType = REG_SZ;
	DWORD dwSize = 0;

	result = RegQueryValueEx(hKey, appName, NULL, &dwType, NULL, &dwSize);

	RegCloseKey(hKey);

	return (result == ERROR_SUCCESS);
}

