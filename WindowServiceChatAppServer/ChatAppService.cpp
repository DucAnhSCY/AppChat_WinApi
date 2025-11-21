#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <iostream>
#include "Struct.h"
#include "ChatAppServer.h"
#include <string>
#include <map>
#include <cstring>
#include <vector>
#include <sstream>
#include <ctime>
#include <strsafe.h>
#include <windows.h>
#include <algorithm>
#pragma comment(lib, "ws2_32.lib")
#include <sqlite3.h>
#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "bcrypt.lib")

using namespace std;

#ifdef _SERVICE
SERVICE_STATUS CChatServerService::m_ServiceStatus = {0};
SERVICE_STATUS_HANDLE CChatServerService::m_ServiceStatusHandle = NULL;
static CChatServerService* g_pService = nullptr;
#define SERVICE_NAME L"ChatAppServerService"
#endif // _SERVICE
static int RecvAll(SOCKET s, void *buf, int len)
{
	char *p = static_cast<char *>(buf);
	int total = 0;
	while (total < len)
	{
		int got = recv(s, p + total, len - total, 0);
		if (got <= 0)
			return got;
		total += got;
	}
	return total;
}

static bool SendAll(SOCKET s, const void *buf, int len)
{
	const char *p = static_cast<const char *>(buf);
	int total = 0;
	while (total < len)
	{
		int sent = send(s, p + total, len - total, 0);
		if (sent == SOCKET_ERROR)
		{
			return false;
		}
		total += sent;
	}
	return true;
}

CChatServerService::CChatServerService()
	: m_listenSocket(INVALID_SOCKET), m_nextClientId(1), m_bServerRunning(FALSE), m_db(nullptr), m_sqlConnected(false)
{
	InitializeCriticalSection(&m_csClients);
}

CChatServerService::~CChatServerService()
{
	StopServer();
	CloseSQLConnection();
	DeleteCriticalSection(&m_csClients);
}

void CChatServerService::LogError(const wchar_t *message)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	wchar_t logFileName[MAX_PATH];
	swprintf_s(logFileName, MAX_PATH, L"C:\\ChatServer\\error_%04d-%02d-%02d_%02d.log",
			   st.wYear, st.wMonth, st.wDay, st.wHour);
	std::wofstream logFile(logFileName, std::ios::app);
	if (logFile.is_open())
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		logFile << L"[" << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
				<< L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond
				<< L"] ERROR: " << message << std::endl;
		logFile.close();
	}
}

void CChatServerService::LogInfo(const wchar_t *message)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	wchar_t logFileName[MAX_PATH];
	swprintf_s(logFileName, MAX_PATH, L"C:\\ChatServer\\info_%04d-%02d-%02d_%02d.log",
			   st.wYear, st.wMonth, st.wDay, st.wHour);
	std::wofstream logFile(logFileName, std::ios::app);
	if (logFile.is_open())
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		logFile << L"[" << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
				<< L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond
				<< L"] INFO: " << message << std::endl;
		logFile.close();
	}
}

#ifdef _SERVICE
// Install service
BOOL CChatServerService::Install()
{
	SC_HANDLE hSCManager;
	TCHAR szUnquotedPath[MAX_PATH];
	SC_HANDLE hService;

	if (!GetModuleFileName(NULL, szUnquotedPath, MAX_PATH))
	{
		printf("Cannot install service (%d)\n", GetLastError());
		return FALSE;
	}
	TCHAR szPath[MAX_PATH];
	StringCbPrintf(szPath, MAX_PATH, TEXT("\"%s\""), szUnquotedPath);

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager == NULL)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	hService = CreateService(
		hSCManager,
		SERVICE_NAME,
		L"Chat Server Service",
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		szPath,
		NULL, NULL, NULL, NULL, NULL);
	if (hService == NULL)
	{
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return TRUE;
}

// Uninstall service
BOOL CChatServerService::Uninstall()
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hSCManager == NULL)
	{
		return FALSE;
	}

	SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);
	if (hService == NULL)
	{
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	SERVICE_STATUS status;
	ControlService(hService, SERVICE_CONTROL_STOP, &status);

	BOOL result = DeleteService(hService);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return result;
}

BOOL CChatServerService::Start()
{
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwOldCheckPoint;
	DWORD dwStartTickCount;
	DWORD dwWaitTime;
	DWORD dwBytesNeeded;

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	SC_HANDLE schService = OpenService(
		schSCManager,
		SERVICE_NAME,
		SERVICE_ALL_ACCESS);

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	if (!QueryServiceStatusEx(
			schService,						// handle to service
			SC_STATUS_PROCESS_INFO,			// information level
			(LPBYTE)&ssStatus,				// address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))				// size needed if buffer is too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
	{
		printf("Cannot start the service because it is already running\n");
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	dwStartTickCount = GetTickCount64();
	dwOldCheckPoint = ssStatus.dwCheckPoint;
	while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is
		// one-tenth of the wait hint but not less than1 second
		// and not more than10 seconds.

		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status until the service is no longer stop pending.

		if (!QueryServiceStatusEx(
				schService,						// handle to service
				SC_STATUS_PROCESS_INFO,			// information level
				(LPBYTE)&ssStatus,				// address of structure
				sizeof(SERVICE_STATUS_PROCESS), // size of structure
				&dwBytesNeeded))				// size needed if buffer is too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.

			dwStartTickCount = GetTickCount64();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount64() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				printf("Timeout waiting for service to stop\n");
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return FALSE;
			}
		}
	}

	// Attempt to start the service.

	if (!StartService(
			schService, // handle to service
			0,			// number of arguments
			NULL))		// no arguments
	{
		printf("StartService failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	else
		printf("Service start pending...\n");

	// Check the status until the service is no longer start pending.

	if (!QueryServiceStatusEx(
			schService,						// handle to service
			SC_STATUS_PROCESS_INFO,			// info level
			(LPBYTE)&ssStatus,				// address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))				// if buffer too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Save the tick count and initial checkpoint.

	dwStartTickCount = GetTickCount64();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is
		// one-tenth the wait hint, but no less than1 second and no
		// more than10 seconds.

		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status again.

		if (!QueryServiceStatusEx(
				schService,						// handle to service
				SC_STATUS_PROCESS_INFO,			// info level
				(LPBYTE)&ssStatus,				// address of structure
				sizeof(SERVICE_STATUS_PROCESS), // size of structure
				&dwBytesNeeded))				// if buffer too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			break;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.

			dwStartTickCount = GetTickCount64();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount64() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				// No progress made within the wait hint.
				break;
			}
		}
	}

	// Determine whether the service is running.

	if (ssStatus.dwCurrentState == SERVICE_RUNNING)
	{
		printf("Service started successfully.\n");
	}
	else
	{
		printf("Service not started. \n");
		printf(" Current State: %d\n", ssStatus.dwCurrentState);
		printf(" Exit Code: %d\n", ssStatus.dwWin32ExitCode);
		printf(" Check Point: %d\n", ssStatus.dwCheckPoint);
		printf(" Wait Hint: %d\n", ssStatus.dwWaitHint);
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return ssStatus.dwCurrentState == SERVICE_RUNNING;
}
BOOL __stdcall CChatServerService::StopDependentServices()
{
	DWORD i;
	DWORD dwBytesNeeded;
	DWORD dwCount;

	LPENUM_SERVICE_STATUS lpDependencies = NULL;
	ENUM_SERVICE_STATUS ess;
	SC_HANDLE hDepService;
	SERVICE_STATUS_PROCESS ssp;
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		return FALSE;
	}
	SC_HANDLE schService = OpenService(
		schSCManager,
		SERVICE_NAME,
		SERVICE_STOP |
			SERVICE_QUERY_STATUS |
			SERVICE_ENUMERATE_DEPENDENTS);
	if (schService == NULL)
	{
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	DWORD dwStartTime = GetTickCount64();
	DWORD dwTimeout = 30000; // 30-second time-out

	// Pass a zero-length buffer to get the required buffer size.
	if (EnumDependentServices(schService, SERVICE_ACTIVE,
							  lpDependencies, 0, &dwBytesNeeded, &dwCount))
	{
		// If the Enum call succeeds, then there are no dependent
		// services, so do nothing.
		return TRUE;
	}
	else
	{
		if (GetLastError() != ERROR_MORE_DATA)
			return FALSE; // Unexpected error

		// Allocate a buffer for the dependencies.
		lpDependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(
			GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);

		if (!lpDependencies)
			return FALSE;

		__try
		{
			// Enumerate the dependencies.
			if (!EnumDependentServices(schService, SERVICE_ACTIVE,
									   lpDependencies, dwBytesNeeded, &dwBytesNeeded,
									   &dwCount))
				return FALSE;

			for (i = 0; i < dwCount; i++)
			{
				ess = *(lpDependencies + i);
				// Open the service.
				hDepService = OpenService(schSCManager,
										  ess.lpServiceName,
										  SERVICE_STOP | SERVICE_QUERY_STATUS);

				if (!hDepService)
					return FALSE;

				__try
				{
					// Send a stop code.
					if (!ControlService(hDepService,
										SERVICE_CONTROL_STOP,
										(LPSERVICE_STATUS)&ssp))
						return FALSE;

					// Wait for the service to stop.
					while (ssp.dwCurrentState != SERVICE_STOPPED)
					{
						Sleep(ssp.dwWaitHint);
						if (!QueryServiceStatusEx(
								hDepService,
								SC_STATUS_PROCESS_INFO,
								(LPBYTE)&ssp,
								sizeof(SERVICE_STATUS_PROCESS),
								&dwBytesNeeded))
							return FALSE;

						if (ssp.dwCurrentState == SERVICE_STOPPED)
							break;

						if (GetTickCount64() - dwStartTime > dwTimeout)
							return FALSE;
					}
				}
				__finally
				{
					// Always release the service handle.
					CloseServiceHandle(hDepService);
				}
			}
		}
		__finally
		{
			// Always free the enumeration buffer.
			HeapFree(GetProcessHeap(), 0, lpDependencies);
		}
	}
	return TRUE;
}
// Stop service
BOOL CChatServerService::Stop()
{

	SERVICE_STATUS_PROCESS ssp;
	DWORD dwStartTime = GetTickCount64();
	DWORD dwBytesNeeded;
	DWORD dwTimeout = 30000; // 30-second time-out
	DWORD dwWaitTime;
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	SC_HANDLE schService = OpenService(
		schSCManager,
		SERVICE_NAME,
		SERVICE_STOP |
			SERVICE_QUERY_STATUS |
			SERVICE_ENUMERATE_DEPENDENTS);
	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	if (!QueryServiceStatusEx(
			schService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		goto stop_cleanup;
	}

	if (ssp.dwCurrentState == SERVICE_STOPPED)
	{
		printf("Service is already stopped.\n");
		goto stop_cleanup;
	}

	// If a stop is pending, wait for it.

	while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
	{
		printf("Service stop pending...\n");

		// Do not wait longer than the wait hint. A good interval is
		// one-tenth of the wait hint but not less than1 second
		// and not more than10 seconds.

		dwWaitTime = ssp.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		if (!QueryServiceStatusEx(
				schService,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ssp,
				sizeof(SERVICE_STATUS_PROCESS),
				&dwBytesNeeded))
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			goto stop_cleanup;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{
			printf("Service stopped successfully.\n");
			goto stop_cleanup;
		}

		if (GetTickCount64() - dwStartTime > dwTimeout)
		{
			printf("Service stop timed out.\n");
			goto stop_cleanup;
		}
	}

	// If the service is running, dependencies must be stopped first.

	if (!g_pService->StopDependentServices())
	{
		printf("StopDependentServices failed\n");
		goto stop_cleanup;
	}

	// Send a stop code to the service.

	if (!ControlService(
			schService,
			SERVICE_CONTROL_STOP,
			(LPSERVICE_STATUS)&ssp))
	{
		printf("ControlService failed (%d)\n", GetLastError());
		goto stop_cleanup;
	}

	// Wait for the service to stop.

	while (ssp.dwCurrentState != SERVICE_STOPPED)
	{
		Sleep(ssp.dwWaitHint);
		if (!QueryServiceStatusEx(
				schService,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ssp,
				sizeof(SERVICE_STATUS_PROCESS),
				&dwBytesNeeded))
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
			goto stop_cleanup;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
			break;

		if (GetTickCount64() - dwStartTime > dwTimeout)
		{
			printf("Wait timed out\n");
			goto stop_cleanup;
		}
	}
	printf("Service stopped successfully\n");

stop_cleanup:
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return ssp.dwCurrentState == SERVICE_STOPPED;
}

// Service Main
void WINAPI CChatServerService::ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	g_pService = new CChatServerService();

	m_ServiceStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
	if (m_ServiceStatusHandle == NULL)
	{
		return;
	}

	m_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	m_ServiceStatus.dwWin32ExitCode = 0;

	SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);

	// Start the server
	g_pService->StartServer();

	// Service is running
	m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);

	while (g_pService->m_bServerRunning)
	{
		Sleep(1000);
	}

	// Service stopped
	m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);

	delete g_pService;
	g_pService = nullptr;
}

// Service control handler
void WINAPI CChatServerService::ServiceCtrlHandler(DWORD ctrl)
{
	switch (ctrl)
	{
	case SERVICE_CONTROL_STOP:
		m_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);

		if (g_pService)
		{
			g_pService->StopServer();
		}
		break;
	}
}
#endif // _SERVICE

// Start server
void CChatServerService::StartServer()
{
	LogInfo(L"Starting Chat Server...");
	OutputDebugStringW(L"Starting Chat Server...\n");

	if (!EnsureSQLConnection())
	{
		LogError(L"Failed to establish SQLite connection. Server startup aborted.");
		OutputDebugStringW(L"Failed to establish SQLite connection. Server startup aborted.\n");
		return;
	}

	WSAData wsaData;
	int wsaerr = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsaerr != 0)
	{
		LogError(L"WSAStartup failed!");
		OutputDebugStringW(L"WSAStartup failed!\n");
		return;
	}

	m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_listenSocket == INVALID_SOCKET)
	{
		WSACleanup();
		LogError(L"Socket creation failed!");
		OutputDebugStringW(L"Socket creation failed!\n");
		return;
	}

	sockaddr_in service;
	service.sin_family = AF_INET;
	InetPton(AF_INET, L"127.0.0.1", &service.sin_addr.s_addr);
	service.sin_port = htons(9999);

	if (bind(m_listenSocket, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR)
	{
		closesocket(m_listenSocket);
		WSACleanup();
		LogError(L"Bind failed!");
		OutputDebugStringW(L"Bind failed!\n");
		return;
	}

	if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		closesocket(m_listenSocket);
		WSACleanup();
		LogError(L"Listen failed!");
		OutputDebugStringW(L"Listen failed!\n");
		return;
	}

	LogInfo(L"Server started successfully on port9999");
	OutputDebugStringW(L"Server started successfully on port9999\n");
	m_bServerRunning = TRUE;

	CreateThread(NULL, 0, AcceptThreadProc, this, 0, NULL);
}

void CChatServerService::StopServer()
{
	LogInfo(L"Stopping Chat Server...");
	OutputDebugStringW(L"Stopping Chat Server...\n");

	m_bServerRunning = FALSE;

	if (m_listenSocket != INVALID_SOCKET)
	{
		closesocket(m_listenSocket);
		m_listenSocket = INVALID_SOCKET;
	}

	EnterCriticalSection(&m_csClients);
	for (auto pClient : m_clients)
	{
		closesocket(pClient->clientSocket);
		delete pClient;
	}
	m_clients.clear();
	m_authenticatedUsers.clear();
	LeaveCriticalSection(&m_csClients);

	WSACleanup();
	CloseSQLConnection();
	LogInfo(L"Server stopped");
	OutputDebugStringW(L"Server stopped\n");
}

BOOL CChatServerService::HashPassword(const std::wstring& password, std::wstring& hash)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status;
	DWORD cbHash = 0, cbData = 0;
	PBYTE pbHash = NULL;
	BOOL result = FALSE;

	// Open an algorithm handle
	if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
	{
		LogError(L"BCryptOpenAlgorithmProvider failed");
		return FALSE;
	}

	// Get the size of the hash
	if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
	{
		LogError(L"BCryptGetProperty failed");
		goto cleanup;
	}

	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		LogError(L"HeapAlloc failed");
		goto cleanup;
	}

	// Create a hash handle
	if (!BCRYPT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)))
	{
		LogError(L"BCryptCreateHash failed");
		goto cleanup;
	}

	// Hash the password
	if (!BCRYPT_SUCCESS(status = BCryptHashData(hHash, (PBYTE)password.c_str(), (ULONG)(password.length() * sizeof(wchar_t)), 0)))
	{
		LogError(L"BCryptHashData failed");
		goto cleanup;
	}

	// Finish the hash
	if (!BCRYPT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0)))
	{
		LogError(L"BCryptFinishHash failed");
		goto cleanup;
	}

	// Convert hash bytes to a hex string
	wchar_t temp[3];
	for (DWORD i = 0; i < cbHash; i++)
	{
		swprintf_s(temp, 3, L"%02x", pbHash[i]);
		hash.append(temp);
	}

	result = TRUE;

cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

	return result;
}

BOOL CChatServerService::VerifyPassword(const std::wstring& password, const std::wstring& storedHash)
{
	std::wstring hashToVerify;
	if (HashPassword(password, hashToVerify))
	{
		return hashToVerify == storedHash;
	}
	return FALSE;
}


DWORD WINAPI CChatServerService::AcceptThreadProc(LPVOID pParam)
{
	CChatServerService *pService = (CChatServerService *)pParam;

	while (pService->m_bServerRunning)
	{
		SOCKET clientSocket = accept(pService->m_listenSocket, NULL, NULL);

		if (clientSocket == INVALID_SOCKET)
		{
			if (pService->m_bServerRunning)
			{
				continue;
			}
			break;
		}

		ClientInfo *pClientInfo = new ClientInfo();
		pClientInfo->clientSocket = clientSocket;
		pClientInfo->pDlg = pService;
		pClientInfo->userId = 0;
		pClientInfo->username[0] = L'\0';

		EnterCriticalSection(&pService->m_csClients);
		pClientInfo->clientId = pService->m_nextClientId++;
		swprintf_s(pClientInfo->username, MAX_SENDER_LENGTH, L"Client%d", pClientInfo->clientId);
		pService->m_clients.push_back(pClientInfo);
		LeaveCriticalSection(&pService->m_csClients);

		send(clientSocket, (char *)&pClientInfo->clientId, sizeof(int), 0);

		CreateThread(NULL, 0, ClientThreadProc, pClientInfo, 0, NULL);
		std::wstring infoMsg = L"New client connected: " + std::wstring(pClientInfo->username);
		pService->LogInfo(infoMsg.c_str());
		OutputDebugStringW(infoMsg.c_str());
	}

	return 0;
}
// Client thread
DWORD WINAPI CChatServerService::ClientThreadProc(LPVOID pParam)
{
	ClientInfo* pClientInfo = (ClientInfo*)pParam;
	CChatServerService* pService = (CChatServerService*)pClientInfo->pDlg;

	while (true)
	{
		PacketHeader header;
		int ret = RecvAll(pClientInfo->clientSocket, &header, sizeof(header));
		if (ret <= 0)
		{
			break;
		}

		std::vector<char> buffer(header.size);
		if (header.size > 0) {
			ret = RecvAll(pClientInfo->clientSocket, buffer.data(), header.size);
			if (ret <= 0)
			{
				break;
			}
		}

		Packet packet(header.type);
		packet.SetBuffer(buffer.data(), header.size);

		if (!pService->IsClientAuthenticated(pClientInfo->clientId))
		{
			if (header.type == PacketType::RegisterRequest)
			{
				std::wstring username, password, phone, email;
				packet.ReadString(username);
				packet.ReadString(password);
				packet.ReadString(phone);
				packet.ReadString(email);


				if (username.empty() || password.empty())
				{
					pService->SendLoginResult(pClientInfo->clientSocket, 0, 0, L"", L"Username and password are required for registration.");
				}
				else
				{
					int newUserId = 0;
					std::wstring hashedPassword;
					if (pService->HashPassword(password, hashedPassword))
					{
						if (pService->RegisterUser(username.c_str(), hashedPassword.c_str(), phone.c_str(), email.c_str(), newUserId))
						{
							pService->SendLoginResult(pClientInfo->clientSocket, 1, newUserId, username, L"Registration successful. You can now log in.");
							std::wstring info = L"User registered: " + username;
							pService->LogInfo(info.c_str());
						}
						else
						{
							pService->SendLoginResult(pClientInfo->clientSocket, 0, 0, L"", L"Registration failed. The username might already exist.");
							std::wstring warn = L"Registration failed for user: " + username;
							pService->LogError(warn.c_str());
						}
					}
					else
					{
						pService->SendLoginResult(pClientInfo->clientSocket, 0, 0, L"", L"Registration failed due to a server-side hashing error.");
						pService->LogError(L"Password hashing failed during registration.");
					}
				}
				continue;
			}

			if (header.type != PacketType::LoginRequest)
			{
				pService->SendLoginResult(pClientInfo->clientSocket, 0, 0, L"", L"Authentication required before sending messages.");
				continue;
			}

			std::wstring username, password;
			packet.ReadString(username);
			packet.ReadString(password);
			
			int userId = 0;
			if (pService->AuthenticateUser(username.c_str(), password.c_str(), userId))
			{
				UserAccount account = {};
				account.userId = userId;
				account.username = username;
				UserAccount dbAccount = account;
				if (pService->GetUserById(userId, dbAccount))
				{
					account = dbAccount;
				}
				pService->m_authenticatedUsers[pClientInfo->clientId] = account;
				wcsncpy_s(pClientInfo->username, account.username.c_str(), _TRUNCATE);
				pClientInfo->userId = account.userId;
				pService->SendLoginResult(pClientInfo->clientSocket, 1, account.userId, account.username, L"Login successful.");
				pService->SendFriendList(pClientInfo->clientSocket, account.userId);
				pService->BroadcastUserStatusUpdate();
				std::wstring info = L"User authenticated: " + account.username;
				pService->LogInfo(info.c_str());
			}
			else
			{
				pService->SendLoginResult(pClientInfo->clientSocket, 0, 0, L"", L"Invalid username or password.");
				pService->LogInfo(L"Failed login attempt detected.");
			}
			continue;
		}

		// Authenticated users only
		switch (header.type)
		{
			case PacketType::ChatHistoryRequest:
			{
				uint32_t friendUserId_u32;
				packet.ReadUInt32(friendUserId_u32);
				int friendUserId = static_cast<int>(friendUserId_u32);

				int senderUserId = pService->GetUserIdForClient(pClientInfo->clientId);
				std::vector<Msg> history;
				if (senderUserId > 0 && friendUserId > 0 && pService->GetChatHistory(senderUserId, friendUserId, history))
				{
					pService->SendChatHistory(pClientInfo->clientSocket, friendUserId, history);
				}
				break;
			}
			case PacketType::ChatMessage:
			{
				uint32_t receiverUserId_u32;
				std::wstring message;
				packet.ReadUInt32(receiverUserId_u32);
				packet.ReadString(message);
				int receiverUserId = static_cast<int>(receiverUserId_u32);

				int senderUserId = pService->GetUserIdForClient(pClientInfo->clientId);
				if (senderUserId > 0 && receiverUserId > 0)
				{
					pService->SaveMessageToDB(senderUserId, receiverUserId, message.c_str());

					int receiverClientId = pService->FindClientIdByUserId(receiverUserId);
					ClientInfo *receiverClient = pService->GetClientById(receiverClientId);
					if (receiverClient != nullptr)
					{
						Packet chatPacket(PacketType::ChatMessage);
						chatPacket.WriteUInt32(static_cast<uint32_t>(senderUserId));
						chatPacket.WriteUInt32(static_cast<uint32_t>(receiverUserId));
						std::wstring senderName = pService->GetUsernameForClient(pClientInfo->clientId);
						chatPacket.WriteString(senderName);
						chatPacket.WriteString(message);
						chatPacket.WriteUInt32(static_cast<uint32_t>(std::time(nullptr)));
						pService->SendPacket(receiverClient->clientSocket, chatPacket);
					}
				}
				std::wstring senderName = pService->GetUsernameForClient(pClientInfo->clientId);
				std::wstring logMsg = L"Private message from " + senderName + L": " + message;
				pService->LogInfo(logMsg.c_str());
				OutputDebugStringW(logMsg.c_str());
				break;
			}
			default:
			{
				pService->LogError(L"Unsupported command received from an authenticated client.");
				break;
			}
		}
	}

	closesocket(pClientInfo->clientSocket);
	pService->RemoveClient(pClientInfo->clientId);
	pService->BroadcastUserStatusUpdate();

	std::wstring infoMsg = L"Client disconnected: " + std::wstring(pClientInfo->username);
	pService->LogInfo(infoMsg.c_str());
	OutputDebugStringW(infoMsg.c_str());
	delete pClientInfo;
	return 0;
}

void CChatServerService::SendPacket(SOCKET socket, const Packet& packet)
{
	PacketHeader header;
	header.type = packet.GetType();
	header.size = static_cast<uint32_t>(packet.GetSize());

	if (!SendAll(socket, &header, sizeof(header)))
	{
		LogError(L"Failed to send packet header.");
		return;
	}

	if (header.size > 0)
	{
		if (!SendAll(socket, packet.GetData(), static_cast<int>(header.size)))
		{
			LogError(L"Failed to send packet payload.");
		}
	}
}


void CChatServerService::RemoveClient(int clientId)
{
	EnterCriticalSection(&m_csClients);
	for (auto it = m_clients.begin(); it != m_clients.end(); ++it)
	{
		if ((*it)->clientId == clientId)
		{
			m_clients.erase(it);
			break;
		}
	}
	m_authenticatedUsers.erase(clientId);
	LeaveCriticalSection(&m_csClients);
}

void CChatServerService::BroadcastUserStatusUpdate()
{
	std::vector<std::pair<SOCKET, int>> targets;
	targets.reserve(m_clients.size());

	EnterCriticalSection(&m_csClients);
	for (auto client : m_clients)
	{
		auto it = m_authenticatedUsers.find(client->clientId);
		if (it == m_authenticatedUsers.end())
		{
			continue;
		}
		targets.emplace_back(client->clientSocket, it->second.userId);
	}
	LeaveCriticalSection(&m_csClients);

	for (const auto &target : targets)
	{
		SendFriendList(target.first, target.second);
	}
}

void CChatServerService::SendLoginResult(SOCKET clientSocket, int success, int userId, const std::wstring &username, const std::wstring &detail)
{
	Packet packet(PacketType::LoginResponse);
	packet.WriteUInt32(success);
	packet.WriteUInt32(userId);
	packet.WriteString(username);
	packet.WriteString(detail);
	SendPacket(clientSocket, packet);
}

void CChatServerService::SendFriendList(SOCKET clientSocket, int userId)
{
	std::vector<UserAccount> friends;
	if (!GetFriendsList(userId, friends))
	{
		return;
	}

	Packet packet(PacketType::FriendList);
	packet.WriteUInt32(static_cast<uint32_t>(friends.size()));

	for (const auto &friendAccount : friends)
	{
		int friendClientId = FindClientIdByUserId(friendAccount.userId);
		uint32_t isOnline = (friendClientId != 0) ? 1 : 0;

		std::wstring displayName = friendAccount.username;
		if (isOnline == 0)
		{
			displayName.append(L" (Offline)");
		}

		packet.WriteUInt32(friendAccount.userId);
		packet.WriteString(displayName);
		packet.WriteUInt32(isOnline);
	}

	SendPacket(clientSocket, packet);
}

void CChatServerService::SendChatHistory(SOCKET clientSocket, int friendUserId, const std::vector<Msg> &messages)
{
	Packet packet(PacketType::ChatHistoryResponse);
	packet.WriteUInt32(friendUserId);
	packet.WriteUInt32(static_cast<uint32_t>(messages.size()));

	for (const auto& msg : messages)
	{
		packet.WriteUInt32(msg.senderUserId);
		packet.WriteUInt32(msg.targetUserId);
		packet.WriteString(msg.sender);
		packet.WriteString(msg.message);
		packet.WriteUInt32(static_cast<uint32_t>(msg.time));
	}

	SendPacket(clientSocket, packet);
}

int CChatServerService::FindClientIdByUserId(int userId)
{
	int clientId = 0;
	EnterCriticalSection(&m_csClients);
	for (auto client : m_clients)
	{
		if (client->userId == userId)
		{
			clientId = client->clientId;
			break;
		}
	}
	LeaveCriticalSection(&m_csClients);
	return clientId;
}

ClientInfo *CChatServerService::GetClientById(int clientId)
{
	ClientInfo *result = nullptr;
	EnterCriticalSection(&m_csClients);
	for (auto client : m_clients)
	{
		if (client->clientId == clientId)
		{
			result = client;
			break;
		}
	}
	LeaveCriticalSection(&m_csClients);
	return result;
}

bool CChatServerService::IsClientAuthenticated(int clientId)
{
	EnterCriticalSection(&m_csClients);
	bool result = m_authenticatedUsers.find(clientId) != m_authenticatedUsers.end();
	LeaveCriticalSection(&m_csClients);
	return result;
}

int CChatServerService::GetUserIdForClient(int clientId)
{
	EnterCriticalSection(&m_csClients);
	int userId = 0;
	auto it = m_authenticatedUsers.find(clientId);
	if (it != m_authenticatedUsers.end())
	{
		userId = it->second.userId;
	}
	LeaveCriticalSection(&m_csClients);
	return userId;
}

std::wstring CChatServerService::GetUsernameForClient(int clientId)
{
	EnterCriticalSection(&m_csClients);
	std::wstring username;
	auto it = m_authenticatedUsers.find(clientId);
	if (it != m_authenticatedUsers.end())
	{
		username = it->second.username;
	}
	LeaveCriticalSection(&m_csClients);
	return username;
}

bool CChatServerService::EnsureSQLConnection()
{
	if (m_sqlConnected)
	{
		return true;
	}
	return InitializeSQLConnection() == TRUE;
}

BOOL CChatServerService::InitializeSQLConnection()
{
	CloseSQLConnection();
	const wchar_t *kDatabaseDirectory = L"F:\\VSCMCCS\\ChatServerDB";
	CreateDirectoryW(kDatabaseDirectory, nullptr);
	std::wstring dbPath = std::wstring(kDatabaseDirectory) + L"\\ChatAppdb.db";
	if (sqlite3_open16(dbPath.c_str(), &m_db) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_open16");
		CloseSQLConnection();
		return FALSE;
	}
	m_sqlConnected = true;

	if (!ExecuteSQLQuery(L"PRAGMA foreign_keys = ON;"))
	{
		CloseSQLConnection();
		return FALSE;
	}

	LogInfo(L"Connected to SQLite successfully.");
	return TRUE;
}

void CChatServerService::CloseSQLConnection()
{
	if (m_db)
	{
		sqlite3_close(m_db);
		m_db = nullptr;
	}
	m_sqlConnected = false;
}

BOOL CChatServerService::ExecuteSQLQuery(const wchar_t *query)
{
	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	if (!query)
	{
		return FALSE;
	}

	sqlite3_stmt *stmt = nullptr;
	if (sqlite3_prepare16_v2(m_db, query, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (ExecuteSQLQuery)");
		return FALSE;
	}

	int rc = SQLITE_OK;
	do
	{
		rc = sqlite3_step(stmt);
	} while (rc == SQLITE_ROW);

	BOOL ok = TRUE;
	if (rc != SQLITE_DONE)
	{
		LogSqliteError(L"sqlite3_step (ExecuteSQLQuery)");
		ok = FALSE;
	}

	sqlite3_finalize(stmt);
	return ok;
}
void CChatServerService::LogSqliteError(const wchar_t *operation)
{
	const char *msg = sqlite3_errmsg(m_db);
	std::wstring wmsg;
	if (msg)
	{
		int needed = MultiByteToWideChar(CP_UTF8, 0, msg, -1, NULL, 0);
		if (needed > 0)
		{
			wmsg.resize(needed - 1);
			MultiByteToWideChar(CP_UTF8, 0, msg, -1, &wmsg[0], needed);
		}
	}
	std::wstringstream ss;
	ss << operation << L" failed: " << wmsg;
	LogError(ss.str().c_str());
}

BOOL CChatServerService::AuthenticateUser(const wchar_t *username, const wchar_t *password, int &userId)
{
	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	sqlite3_stmt *stmt = nullptr;
	const wchar_t *sql = L"SELECT userid, password_hash FROM Account WHERE username = ?";
	if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (AuthenticateUser)");
		return FALSE;
	}

	sqlite3_bind_text16(stmt, 1, username, -1, SQLITE_TRANSIENT);

	int rc = sqlite3_step(stmt);
	BOOL ok = FALSE;
	if (rc == SQLITE_ROW)
	{
		userId = sqlite3_column_int(stmt, 0);
		const wchar_t* storedHash = (const wchar_t*)sqlite3_column_text16(stmt, 1);
		if (storedHash && VerifyPassword(password, storedHash))
		{
			ok = TRUE;
		}
	}
	else if (rc != SQLITE_DONE)
	{
		LogSqliteError(L"sqlite3_step (AuthenticateUser)");
	}

	sqlite3_finalize(stmt);
	return ok;
}

BOOL CChatServerService::RegisterUser(const wchar_t *username, const wchar_t *passwordHash,
									  const wchar_t *phone, const wchar_t *email, int &userId)
{
	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	sqlite3_stmt *stmt = nullptr;
	const wchar_t *sql = L"INSERT INTO Account (username, password_hash, phone, email) VALUES (?, ?, ?, ?)";
	if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (RegisterUser)");
		return FALSE;
	}

	sqlite3_bind_text16(stmt, 1, username, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text16(stmt, 2, passwordHash, -1, SQLITE_TRANSIENT);
	if (phone && wcslen(phone) > 0)
		sqlite3_bind_text16(stmt, 3, phone, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 3);
	if (email && wcslen(email) > 0)
		sqlite3_bind_text16(stmt, 4, email, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 4);

	int rc = sqlite3_step(stmt);
	BOOL ok = FALSE;
	if (rc == SQLITE_DONE)
	{
		userId = static_cast<int>(sqlite3_last_insert_rowid(m_db));
		ok = TRUE;
	}
	else
	{
		LogSqliteError(L"sqlite3_step (RegisterUser)");
	}

	sqlite3_finalize(stmt);
	return ok;
}

BOOL CChatServerService::GetUserById(int userId, UserAccount &userAccount)
{
	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	sqlite3_stmt *stmt = nullptr;
	const wchar_t *sql = L"SELECT userid, username, phone, email FROM Account WHERE userid = ?";
	if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (GetUserById)");
		return FALSE;
	}

	sqlite3_bind_int(stmt, 1, userId);
	int rc = sqlite3_step(stmt);
	BOOL ok = FALSE;
	if (rc == SQLITE_ROW)
	{
		userAccount.userId = sqlite3_column_int(stmt, 0);
		const void *u = sqlite3_column_text16(stmt, 1);
		const void *p = sqlite3_column_text16(stmt, 2);
		const void *e = sqlite3_column_text16(stmt, 3);
		userAccount.username = u ? std::wstring((const wchar_t *)u) : L"";
		userAccount.phone = p ? std::wstring((const wchar_t *)p) : L"";
		userAccount.email = e ? std::wstring((const wchar_t *)e) : L"";
		ok = TRUE;
	}
	else if (rc != SQLITE_DONE)
	{
		LogSqliteError(L"sqlite3_step (GetUserById)");
	}

	sqlite3_finalize(stmt);
	return ok;
}

BOOL CChatServerService::GetFriendsList(int userId, std::vector<UserAccount> &friends)
{
	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	friends.clear();
	sqlite3_stmt *stmt = nullptr;
	const wchar_t *sql =
		L"SELECT A.userid, A.username, A.phone, A.email "
		L"FROM Friendships F "
		L"JOIN Account A ON (A.userid = CASE WHEN F.user_id_1 = ? THEN F.user_id_2 ELSE F.user_id_1 END) "
		L"WHERE (F.user_id_1 = ? OR F.user_id_2 = ?)";

	if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (GetFriendsList)");
		return FALSE;
	}

	sqlite3_bind_int(stmt, 1, userId);
	sqlite3_bind_int(stmt, 2, userId);
	sqlite3_bind_int(stmt, 3, userId);

	int rc = SQLITE_OK;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		UserAccount account;
		account.userId = sqlite3_column_int(stmt, 0);
		const void *u = sqlite3_column_text16(stmt, 1);
		const void *p = sqlite3_column_text16(stmt, 2);
		const void *e = sqlite3_column_text16(stmt, 3);
		account.username = u ? std::wstring((const wchar_t *)u) : L"";
		account.phone = p ? std::wstring((const wchar_t *)p) : L"";
		account.email = e ? std::wstring((const wchar_t *)e) : L"";
		friends.push_back(account);
	}

	if (rc != SQLITE_DONE)
	{
		LogSqliteError(L"sqlite3_step (GetFriendsList)");
		sqlite3_finalize(stmt);
		return FALSE;
	}

	sqlite3_finalize(stmt);
	return TRUE;
}

BOOL CChatServerService::SaveMessageToDB(int senderId, int receiverId, const wchar_t *content)
{
	if (senderId <= 0 || receiverId <= 0)
	{
		return FALSE;
	}

	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	sqlite3_stmt *stmt = nullptr;
	const wchar_t *sql = L"INSERT INTO Msg (sender_id, receiver_id, content, sendDate) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
	if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (SaveMessageToDB)");
		return FALSE;
	}

	sqlite3_bind_int(stmt, 1, senderId);
	sqlite3_bind_int(stmt, 2, receiverId);
	if (content && wcslen(content) > 0)
		sqlite3_bind_text16(stmt, 3, content, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, 3);

	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE)
	{
		LogSqliteError(L"sqlite3_step (SaveMessageToDB)");
		sqlite3_finalize(stmt);
		return FALSE;
	}

	sqlite3_finalize(stmt);
	return TRUE;
}

BOOL CChatServerService::GetChatHistory(int userId1, int userId2, std::vector<Msg> &messages)
{
	if (!EnsureSQLConnection())
	{
		return FALSE;
	}

	messages.clear();
	sqlite3_stmt *stmt = nullptr;
	const wchar_t *sql =
		L"SELECT sender_id, receiver_id, content, strftime('%s', sendDate) "
		L"FROM Msg WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY sendDate";

	if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
	{
		LogSqliteError(L"sqlite3_prepare16_v2 (GetChatHistory)");
		return FALSE;
	}

	sqlite3_bind_int(stmt, 1, userId1);
	sqlite3_bind_int(stmt, 2, userId2);
	sqlite3_bind_int(stmt, 3, userId2);
	sqlite3_bind_int(stmt, 4, userId1);

	int rc = SQLITE_OK;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		Msg msg = {};

		int sender = sqlite3_column_int(stmt, 0);
		UserAccount senderAccount;
		if (GetUserById(sender, senderAccount))
		{
			wcsncpy_s(msg.sender, senderAccount.username.c_str(), _TRUNCATE);
		}
		msg.senderUserId = sender;

		int receiver = sqlite3_column_int(stmt, 1);
		msg.targetUserId = receiver;

		const void *content = sqlite3_column_text16(stmt, 2);
		if (content)
		{
			wcsncpy_s(msg.message, (const wchar_t *)content, _TRUNCATE);
		}

		sqlite3_int64 epoch = sqlite3_column_int64(stmt, 3);
		msg.time = static_cast<time_t>(epoch);

		messages.push_back(msg);
	}

	if (rc != SQLITE_DONE)
	{
		LogSqliteError(L"sqlite3_step (GetChatHistory)");
		sqlite3_finalize(stmt);
		return FALSE;
	}
	sqlite3_finalize(stmt);
	return TRUE;
}
