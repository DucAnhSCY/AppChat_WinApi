// RegisterDlg.cpp : implementation file
//

#include "pch.h"
#include "ChatAppClient.h"
#include "afxdialogex.h"
#include "RegisterDlg.h"
#include "Struct.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cwctype>
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

bool IsDigitsOnly(const CString& value)
{
	for (int i = 0; i < value.GetLength(); ++i) {
		if (!iswdigit(value[i])) {
			return false;
		}
	}
	return true;
}

bool LooksLikeEmail(const CString& email)
{
	int atPos = email.Find(L'@');
	int dotPos = email.ReverseFind(L'.');
	return atPos > 0 && dotPos > atPos + 1 && dotPos < email.GetLength() - 1;
}
}

// RegisterDlg dialog

IMPLEMENT_DYNAMIC(RegisterDlg, CDialogEx)

RegisterDlg::RegisterDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_Register, pParent)
{

}

RegisterDlg::~RegisterDlg()
{
}

void RegisterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(RegisterDlg, CDialogEx)
	ON_BN_CLICKED(IDC_Register, &RegisterDlg::OnBnClickedRegister)
	ON_BN_CLICKED(IDC_Login_link, &RegisterDlg::OnBnClickedLoginlink)
END_MESSAGE_MAP()


// RegisterDlg message handlers

void RegisterDlg::OnBnClickedRegister()
{
	CString username;
	CString password;
	CString confirmPassword;
	CString phone;
	CString email;

	GetDlgItemText(IDC_username_text, username);
	GetDlgItemText(IDC_password_text, password);
	GetDlgItemText(IDC_cfpassword_text, confirmPassword);
	GetDlgItemText(IDC_phone_number_text, phone);
	GetDlgItemText(IDC_email_text, email);

	username.Trim();
	password.Trim();
	confirmPassword.Trim();
	phone.Trim();
	email.Trim();

	if (username.IsEmpty()) {
		MessageBox(L"Please enter a username.", L"Registration", MB_ICONWARNING);
		return;
	}

	if (password.IsEmpty()) {
		MessageBox(L"Please enter a password.", L"Registration", MB_ICONWARNING);
		return;
	}

	if (password != confirmPassword) {
		MessageBox(L"Passwords do not match.", L"Registration", MB_ICONWARNING);
		return;
	}

	if (!phone.IsEmpty() && !IsDigitsOnly(phone)) {
		MessageBox(L"Phone number should contain digits only.", L"Registration", MB_ICONWARNING);
		return;
	}

	if (!email.IsEmpty() && !LooksLikeEmail(email)) {
		MessageBox(L"Please enter a valid email address.", L"Registration", MB_ICONWARNING);
		return;
	}

	if (username.Find(L'|') != -1 || password.Find(L'|') != -1 || phone.Find(L'|') != -1 || email.Find(L'|') != -1) {
		MessageBox(L"Character '|' is not allowed in the registration fields.", L"Registration", MB_ICONWARNING);
		return;
	}

	WSADATA wsaData;
	bool wsaStarted = false;
	SOCKET regSocket = INVALID_SOCKET;
	auto cleanup = [&]() {
		if (regSocket != INVALID_SOCKET) {
			closesocket(regSocket);
			regSocket = INVALID_SOCKET;
		}
		if (wsaStarted) {
			WSACleanup();
			wsaStarted = false;
		}
	};

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		MessageBox(L"Unable to initialize Winsock.", L"Error", MB_ICONERROR);
		return;
	}
	wsaStarted = true;

	regSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (regSocket == INVALID_SOCKET) {
		MessageBox(L"Unable to create registration socket.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	sockaddr_in serverAddr = {};
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(9999);
	if (InetPton(AF_INET, L"127.0.0.1", &serverAddr.sin_addr) != 1) {
		MessageBox(L"Unable to parse server address.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	if (connect(regSocket, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
		MessageBox(L"Unable to connect to the service server.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	int tempClientId = 0;
	if (!RecvAll(regSocket, &tempClientId, sizeof(tempClientId))) {
		MessageBox(L"No response received from the server.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	Msg msg = {};
	msg.targetUserId = 0;
	msg.senderUserId = 0;
	msg.time = std::time(nullptr);
	wcsncpy_s(msg.sender, username, _TRUNCATE);

	CString payload;
	payload.Format(L"%s|%s|%s", password.GetString(), phone.GetString(), email.GetString());
	wcsncpy_s(msg.message, payload, _TRUNCATE);

	int command = static_cast<int>(ClientCommand::CMD_REGISTER);
	if (!SendAll(regSocket, &command, sizeof(command)) || !SendAll(regSocket, &msg, sizeof(msg))) {
		MessageBox(L"Unable to send the registration request.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	int packetType = 0;
	if (!RecvAll(regSocket, &packetType, sizeof(packetType))) {
		MessageBox(L"No response received from the server.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	if (packetType != PACKET_LOGIN_RESULT) {
		MessageBox(L"Unexpected response from the server.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	LoginResult result = {};
	if (!RecvAll(regSocket, &result, sizeof(result))) {
		MessageBox(L"Failed to receive the registration result.", L"Error", MB_ICONERROR);
		cleanup();
		return;
	}

	cleanup();

	CString detail = result.detail[0] != L'\0' ? result.detail : (result.success == 1 ? L"Registration successful. You can now log in." : L"Registration failed.");
	if (result.success == 1) {
		m_registeredUsername = username;
		MessageBox(detail, L"Registration", MB_ICONINFORMATION);
		EndDialog(IDOK);
	}
	else {
		MessageBox(detail, L"Registration", MB_ICONERROR);
	}
}
void RegisterDlg::OnBnClickedLoginlink()
{
	EndDialog(IDCANCEL);
}
