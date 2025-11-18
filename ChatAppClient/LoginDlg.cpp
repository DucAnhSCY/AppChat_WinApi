// LoginDlg.cpp : implementation file
//
#include "pch.h"
#include "ChatAppClient.h"
#include "afxdialogex.h"
#include "LoginDlg.h"
#include "RegisterDlg.h"
#include "Struct.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

namespace {
bool SendAll(SOCKET socket, const void* data, int length)
{
	const char* buffer = static_cast<const char*>(data);
	int remaining = length;
	while (remaining > 0) {
		int sent = send(socket, buffer, remaining, 0);
		if (sent == SOCKET_ERROR) {
			return false;
		}
		buffer += sent;
		remaining -= sent;
	}
	return true;
}

bool RecvAll(SOCKET socket, void* data, int length)
{
	char* buffer = static_cast<char*>(data);
	int remaining = length;
	while (remaining > 0) {
		int received = recv(socket, buffer, remaining, 0);
		if (received <= 0) {
			return false;
		}
		buffer += received;
		remaining -= received;
	}
	return true;
}
}

// LoginDlg dialog

IMPLEMENT_DYNAMIC(LoginDlg, CDialogEx)

LoginDlg::LoginDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_Login, pParent)
{
#ifndef _WIN32_WCE
	EnableActiveAccessibility();
#endif

	EnableAutomation();

}

LoginDlg::~LoginDlg()
{
}

void LoginDlg::OnFinalRelease()
{
	// When the last reference for an automation object is released
	// OnFinalRelease is called.  The base class will automatically
	// deletes the object.  Add additional cleanup required for your
	// object before calling the base class.

	CDialogEx::OnFinalRelease();
}

BOOL LoginDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	SetDefID(IDC_Login);
	return TRUE;
}

void LoginDlg::OnOK()
{
	OnBnClickedLogin();
}

void LoginDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(LoginDlg, CDialogEx)
	ON_BN_CLICKED(IDC_Login, &LoginDlg::OnBnClickedLogin)
	ON_BN_CLICKED(IDC_Register_link, &LoginDlg::OnBnClickedRegisterlink)
END_MESSAGE_MAP()

BEGIN_DISPATCH_MAP(LoginDlg, CDialogEx)
END_DISPATCH_MAP()

// Note: we add support for IID_ILoginDlg to support typesafe binding
//  from VBA.  This IID must match the GUID that is attached to the
//  dispinterface in the .IDL file.

// {25352407-cb4d-49cc-9136-3ca73da14283}
static const IID IID_ILoginDlg =
{0x25352407,0xcb4d,0x49cc,{0x91,0x36,0x3c,0xa7,0x3d,0xa1,0x42,0x83}};

BEGIN_INTERFACE_MAP(LoginDlg, CDialogEx)
	INTERFACE_PART(LoginDlg, IID_ILoginDlg, Dispatch)
END_INTERFACE_MAP()


// LoginDlg message handlers

void LoginDlg::OnBnClickedLogin()
{
	CString username;
	CString password;
	GetDlgItemText(IDC_username_text, username);
	GetDlgItemText(IDC_password_text, password);
	username.Trim();
	password.Trim();

	if (username.IsEmpty() || password.IsEmpty()) {
		MessageBox(L"Please enter both username and password.", L"Missing Information", MB_ICONWARNING);
		return;
	}

	if (PerformLogin(username, password)) {
		EndDialog(IDOK);
	}
}


void LoginDlg::OnBnClickedRegisterlink()
{
	ShowWindow(SW_HIDE);
	RegisterDlg registerDlg;
	INT_PTR registerResult = registerDlg.DoModal();
	ShowWindow(SW_SHOW);
	SetForegroundWindow();
	if (registerResult == IDOK) {
		CString registeredUser = registerDlg.GetRegisteredUsername();
		if (!registeredUser.IsEmpty()) {
			SetDlgItemText(IDC_username_text, registeredUser);
		}
		SetDlgItemText(IDC_password_text, L"");
		if (CWnd* pPassword = GetDlgItem(IDC_password_text)) {
			pPassword->SetFocus();
		}
	}
	else if (CWnd* pUser = GetDlgItem(IDC_username_text)) {
		pUser->SetFocus();
	}
}

bool LoginDlg::PerformLogin(const CString& username, const CString& password)
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		MessageBox(L"Unable to initialize Winsock.", L"Error", MB_ICONERROR);
		return false;
	}

	SOCKET authSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (authSocket == INVALID_SOCKET) {
		MessageBox(L"Unable to create login socket.", L"Error", MB_ICONERROR);
		WSACleanup();
		return false;
	}

	sockaddr_in serverAddr = {};
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(9999);
	InetPton(AF_INET, L"127.0.0.1", &serverAddr.sin_addr);

	if (connect(authSocket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
		MessageBox(L"Unable to connect to the service server.", L"Error", MB_ICONERROR);
		closesocket(authSocket);
		WSACleanup();
		return false;
	}

	int tempClientId = 0;
	if (!RecvAll(authSocket, &tempClientId, sizeof(tempClientId))) {
		MessageBox(L"No response received from the server.", L"Error", MB_ICONERROR);
		closesocket(authSocket);
		WSACleanup();
		return false;
	}

	if (!SendLoginRequest(authSocket, username, password)) {
		MessageBox(L"Unable to send the login request.", L"Error", MB_ICONERROR);
		closesocket(authSocket);
		WSACleanup();
		return false;
	}

	int userId = 0;
	CString confirmedUsername;
	CString detail;
	bool success = ReceiveLoginResponse(authSocket, userId, confirmedUsername, detail);

	closesocket(authSocket);
	WSACleanup();

	if (!success) {
		CString message = detail.IsEmpty() ? L"Login failed." : detail;
		MessageBox(message, L"Login", MB_ICONERROR);
		return false;
	}

	CChatAppClientApp& app = theApp;
	app.m_authenticatedUserId = userId;
	app.m_authenticatedUsername = confirmedUsername.IsEmpty() ? username : confirmedUsername;
	app.m_authenticatedPasswordHash = password;
	return true;
}

bool LoginDlg::SendLoginRequest(SOCKET socket, const CString& username, const CString& password)
{
	Msg msg = {};
	msg.targetUserId = 0;
	msg.senderUserId = 0;
	msg.time = std::time(nullptr);
	if (!username.IsEmpty()) {
		wcsncpy_s(msg.sender, username, _TRUNCATE);
	}
	if (!password.IsEmpty()) {
		wcsncpy_s(msg.message, password, _TRUNCATE);
	}
	int command = static_cast<int>(ClientCommand::CMD_LOGIN);
	if (!SendAll(socket, &command, sizeof(command))) {
		return false;
	}
	return SendAll(socket, &msg, sizeof(msg));
}

bool LoginDlg::ReceiveLoginResponse(SOCKET socket, int& userId, CString& serverUserName, CString& detail)
{
	int packetType = 0;
	while (true) {
		if (!RecvAll(socket, &packetType, sizeof(packetType))) {
			detail = L"Lost connection to the server.";
			return false;
		}

		if (packetType == PACKET_LOGIN_RESULT) {
			LoginResult result = {};
			if (!RecvAll(socket, &result, sizeof(result))) {
				detail = L"Lost connection while receiving the login response.";
				return false;
			}

			userId = result.userId;
			serverUserName = result.username;
			detail = result.detail;
			return result.success == 1;
		}
		else if (packetType == PACKET_USER_LIST) {
			UserListUpdate discard;
			if (!RecvAll(socket, &discard, sizeof(discard))) {
				detail = L"Unable to synchronize the user list.";
				return false;
			}
		}
		else if (packetType == PACKET_MESSAGE) {
			Msg discard;
			if (!RecvAll(socket, &discard, sizeof(discard))) {
				detail = L"Unable to synchronize messages.";
				return false;
			}
		}
		else {
			detail = L"Received an unknown packet from the server.";
			return false;
		}
	}
}
