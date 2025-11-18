#pragma once
#include <Windows.h>
#include <vector>
#include <map>
#include <string>
#include "Struct.h"
#pragma comment(lib, "ws2_32.lib")

// Forward declare sqlite3 to avoid including the header here
struct sqlite3;

struct UserAccount {
    int userId;
    std::wstring username;
    std::wstring phone;
    std::wstring email;
};

class CChatServerService
{
public:
    CChatServerService();
    ~CChatServerService();

#ifdef _SERVICE
    // Windows Service-only APIs
    static BOOL Install();
    static BOOL Uninstall();
    static BOOL Start();
    static BOOL Stop();
    BOOL __stdcall StopDependentServices();
    static void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);
    static void WINAPI ServiceCtrlHandler(DWORD ctrl);
#endif // _SERVICE

    // Core server APIs (usable in both service and console test modes)
    void StartServer();
    void StopServer();

private:
#ifdef _SERVICE
    // Windows Service state (present only when building service)
    static SERVICE_STATUS m_ServiceStatus;
    static SERVICE_STATUS_HANDLE m_ServiceStatusHandle;
#endif // _SERVICE

    SOCKET m_listenSocket;
    std::vector<ClientInfo*> m_clients;
    CRITICAL_SECTION m_csClients;
    int m_nextClientId;
    BOOL m_bServerRunning;

    // SQLite connection handle
    sqlite3* m_db;
    bool m_sqlConnected;
    std::map<int, UserAccount> m_authenticatedUsers;

    //Threads
    static DWORD WINAPI AcceptThreadProc(LPVOID pParam);
    static DWORD WINAPI ClientThreadProc(LPVOID pParam);

    // Message routing
    void SendToClient(int clientId, const Msg& msg);
    void RemoveClient(int clientId);
    void BroadcastUserStatusUpdate();
    void SendLoginResult(SOCKET clientSocket, int success, int userId, const std::wstring& username, const std::wstring& detail);
    void SendFriendListWithOnlineStatus(SOCKET clientSocket, int userId);
    void SendChatHistory(SOCKET clientSocket, int friendUserId, const std::vector<Msg>& messages);
    bool IsClientAuthenticated(int clientId);
    int GetUserIdForClient(int clientId);
    std::wstring GetUsernameForClient(int clientId);
    int FindClientIdByUserId(int userId);

    void LogError(const wchar_t* message);
    void LogInfo(const wchar_t* message);

    // SQLite methods
    BOOL InitializeSQLConnection();
    void CloseSQLConnection();
    BOOL ExecuteSQLQuery(const wchar_t* query);
    bool EnsureSQLConnection();

    // Database operations for Account table
    BOOL AuthenticateUser(const wchar_t* username, const wchar_t* passwordHash, int& userId);
    BOOL RegisterUser(const wchar_t* username, const wchar_t* passwordHash,
        const wchar_t* phone, const wchar_t* email, int& userId);
    BOOL GetUserById(int userId, UserAccount& userAccount);

    // Database operations for Friendships table
    BOOL GetFriendsList(int userId, std::vector<UserAccount>& friends);

    // Database operations for Msg table
    BOOL SaveMessageToDB(int senderId, int receiverId, const wchar_t* content);
    BOOL GetChatHistory(int userId1, int userId2, std::vector<Msg>& messages);

    void LogSqliteError(const wchar_t* operation);
};