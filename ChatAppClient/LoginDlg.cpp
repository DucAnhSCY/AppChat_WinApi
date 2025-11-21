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
#include <vector>

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

bool ReceivePacket(SOCKET socket, PacketHeader& header, std::vector<char>& payload)
{
	if (!RecvAll(socket, &header, sizeof(header))) {
		return false;
	}
	payload.resize(header.size);
	if (header.size > 0) {
		if (!RecvAll(socket, payload.data(), static_cast<int>(header.size))) {
			return false;
		}
	}
	return true;
}

bool SendPacket(SOCKET socket, const Packet& packet)
{
	PacketHeader header;
	header.type = packet.GetType();
	header.size = static_cast<uint32_t>(packet.GetSize());
	if (!SendAll(socket, &header, sizeof(header))) {
		return false;
	}
	if (header.size > 0) {
		return SendAll(socket, packet.GetData(), static_cast<int>(header.size));
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
	ON_BN_CLICKED(IDC_CHECK_login, &LoginDlg::OnBnClickedCheckLogin)
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
	Packet packet(PacketType::LoginRequest);
	packet.WriteString(std::wstring(username.GetString()));
	packet.WriteString(std::wstring(password.GetString()));
	return SendPacket(socket, packet);
}

bool LoginDlg::ReceiveLoginResponse(SOCKET socket, int& userId, CString& serverUserName, CString& detail)


{
	PacketHeader header;
	std::vector<char> payload;
	while (ReceivePacket(socket, header, payload)) {
		Packet packet(header.type);
		if (!payload.empty()) {
			packet.SetBuffer(payload.data(), payload.size());
		}
		switch (header.type) {
		case PacketType::LoginResponse:
		{
			uint32_t success = 0;
			uint32_t userIdValue = 0;
			std::wstring username;
			std::wstring detailMessage;
			if (!packet.ReadUInt32(success) || !packet.ReadUInt32(userIdValue) ||
				!packet.ReadString(username) || !packet.ReadString(detailMessage)) {
				detail = L"Received malformed login response.";
				return false;
			}
			userId = static_cast<int>(userIdValue);
			serverUserName = username.c_str();
			detail = detailMessage.c_str();
			return success == 1;
		}
		default:
			break;
		}
	}
	detail = L"Lost connection to the server.";
	return false;
}
void LoginDlg::OnBnClickedCheckLogin()
{
	UpdatePasswordVisibility(IDC_CHECK_login, IDC_password_text);
}

void LoginDlg::UpdatePasswordVisibility(UINT checkBoxId, UINT editControlId)
{
	CButton* pCheck = reinterpret_cast<CButton*>(GetDlgItem(checkBoxId));
	CEdit* pEdit = reinterpret_cast<CEdit*>(GetDlgItem(editControlId));
	if (!pCheck || !pEdit)
	{
		return;
	}
	const bool showText = (pCheck->GetCheck() == BST_CHECKED);
	pEdit->SetPasswordChar(showText ? 0 : L'*');
	pEdit->Invalidate();
	pEdit->UpdateWindow();
}