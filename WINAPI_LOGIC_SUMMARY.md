# Tổng Hợp Logic WinAPI Trong Ứng Dụng Chat

## Mục Lục
1. [Tổng Quan Kiến Trúc](#1-tổng-quan-kiến-trúc)
2. [WinAPI Socket (Winsock2)](#2-winapi-socket-winsock2)
3. [MFC (Microsoft Foundation Classes)](#3-mfc-microsoft-foundation-classes)
4. [Đa Luồng (Threading)](#4-đa-luồng-threading)
5. [Windows Service](#5-windows-service)
6. [Registry API](#6-registry-api)
7. [File I/O API](#7-file-io-api)
8. [BCrypt API (Mã Hóa)](#8-bcrypt-api-mã-hóa)
9. [Shell API](#9-shell-api)
10. [Critical Section (Đồng Bộ Hóa)](#10-critical-section-đồng-bộ-hóa)
11. [Giao Thức Truyền Thông Tùy Chỉnh](#11-giao-thức-truyền-thông-tùy-chỉnh)
12. [SQLite Database](#12-sqlite-database)

---

## 1. Tổng Quan Kiến Trúc

Hệ thống Chat App được xây dựng theo mô hình **Client-Server** với hai thành phần chính:

### 1.1 Client (ChatAppClient)
- **Công nghệ**: MFC (Microsoft Foundation Classes) Dialog-based Application
- **Chức năng**: Giao diện người dùng, đăng nhập, đăng ký, gửi/nhận tin nhắn
- **Thư viện**: `afxwin.h`, `winsock2.h`, `ws2tcpip.h`

### 1.2 Server (WindowServiceChatAppServer)
- **Công nghệ**: Windows Service hoặc Console Application
- **Chức năng**: Xử lý kết nối, xác thực người dùng, lưu trữ tin nhắn, định tuyến tin nhắn
- **Cơ sở dữ liệu**: SQLite3
- **Thư viện**: `winsock2.h`, `bcrypt.h`, `sqlite3.h`

---

## 2. WinAPI Socket (Winsock2)

### 2.1 Khởi Tạo Winsock

```cpp
// Khởi tạo Winsock với phiên bản 2.2
WSAData wsaData;
WORD wVersionRequested = MAKEWORD(2, 2);
int wsaerr = WSAStartup(wVersionRequested, &wsaData);
if (wsaerr != 0) {
    // Xử lý lỗi
}
```

**Giải thích**: 
- `MAKEWORD(2, 2)`: Yêu cầu phiên bản Winsock 2.2
- `WSAStartup()`: Khởi tạo thư viện Windows Sockets DLL

### 2.2 Tạo Socket

```cpp
// Tạo TCP Socket
SOCKET m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (m_listenSocket == INVALID_SOCKET) {
    WSACleanup();
    return;
}
```

**Tham số**:
- `AF_INET`: Address Family - IPv4
- `SOCK_STREAM`: Socket loại stream (TCP)
- `IPPROTO_TCP`: Protocol TCP

### 2.3 Bind và Listen (Server)

```cpp
sockaddr_in service;
service.sin_family = AF_INET;
InetPton(AF_INET, L"127.0.0.1", &service.sin_addr.s_addr);
service.sin_port = htons(9999);

// Bind socket với địa chỉ
if (bind(m_listenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
    closesocket(m_listenSocket);
    WSACleanup();
    return;
}

// Lắng nghe kết nối
if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
    closesocket(m_listenSocket);
    WSACleanup();
    return;
}
```

**Giải thích**:
- `InetPton()`: Chuyển đổi địa chỉ IP từ chuỗi sang dạng binary
- `htons()`: Host to Network Short - chuyển đổi byte order
- `SOMAXCONN`: Cho phép số lượng kết nối tối đa mà hệ thống hỗ trợ

### 2.4 Accept Kết Nối (Server)

```cpp
SOCKET clientSocket = accept(m_listenSocket, NULL, NULL);
if (clientSocket == INVALID_SOCKET) {
    if (m_bServerRunning) {
        continue;
    }
    break;
}
```

### 2.5 Connect (Client)

```cpp
sockaddr_in server_addr;
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(9999);
InetPton(AF_INET, L"127.0.0.1", &server_addr.sin_addr);

if (connect(m_listenSocket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
    closesocket(m_listenSocket);
    WSACleanup();
    return;
}
```

### 2.6 Gửi/Nhận Dữ Liệu

```cpp
// Hàm gửi toàn bộ dữ liệu (đảm bảo gửi hết)
bool SendAll(SOCKET socket, const void* data, int length) {
    const char* buffer = static_cast<const char*>(data);
    int total = 0;
    while (total < length) {
        int sent = send(socket, buffer + total, length - total, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return false;
        }
        total += sent;
    }
    return true;
}

// Hàm nhận toàn bộ dữ liệu (đảm bảo nhận đủ)
bool RecvAll(SOCKET socket, void* data, int length) {
    char* buffer = static_cast<char*>(data);
    int total = 0;
    while (total < length) {
        int received = recv(socket, buffer + total, length - total, 0);
        if (received <= 0) {
            return false;
        }
        total += received;
    }
    return true;
}
```

**Logic quan trọng**: 
- Hàm `send()` và `recv()` có thể không gửi/nhận hết dữ liệu trong một lần gọi
- Cần vòng lặp để đảm bảo gửi/nhận toàn bộ dữ liệu

### 2.7 Dọn Dẹp

```cpp
closesocket(m_listenSocket);  // Đóng socket
WSACleanup();                  // Giải phóng tài nguyên Winsock
```

---

## 3. MFC (Microsoft Foundation Classes)

### 3.1 Application Class (CWinApp)

```cpp
class CChatAppClientApp : public CWinApp
{
public:
    CChatAppClientApp();
    
    // Biến lưu trữ thông tin đăng nhập
    CString m_authenticatedUsername;
    CString m_authenticatedPasswordHash;
    int m_authenticatedUserId;

    virtual BOOL InitInstance();  // Điểm vào của ứng dụng
    
    DECLARE_MESSAGE_MAP()
};

extern CChatAppClientApp theApp;  // Đối tượng ứng dụng toàn cục
```

**Giải thích**:
- `CWinApp`: Lớp cơ sở cho ứng dụng Windows
- `InitInstance()`: Được gọi khi ứng dụng khởi động
- `theApp`: Singleton object của ứng dụng

### 3.2 Dialog Classes

```cpp
class CChatAppClientDlg : public CDialogEx
{
    // Constructor với tài nguyên dialog
    CChatAppClientDlg(CWnd* pParent = nullptr);
    
    // DDX/DDV Support - Data exchange
    virtual void DoDataExchange(CDataExchange* pDX);
    
    // Message Map
    BEGIN_MESSAGE_MAP(CChatAppClientDlg, CDialogEx)
        ON_WM_SYSCOMMAND()
        ON_WM_PAINT()
        ON_WM_QUERYDRAGICON()
        ON_BN_CLICKED(IDC_BUTTON_SEND, &CChatAppClientDlg::OnBnClickedButtonSend)
        ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_USER, &CChatAppClientDlg::OnLvnItemchangedListUser)
    END_MESSAGE_MAP()
};
```

### 3.3 Message Map Macros

```cpp
BEGIN_MESSAGE_MAP(LoginDlg, CDialogEx)
    ON_BN_CLICKED(IDC_Login, &LoginDlg::OnBnClickedLogin)           // Button click
    ON_BN_CLICKED(IDC_Register_link, &LoginDlg::OnBnClickedRegisterlink)
    ON_BN_CLICKED(IDC_CHECK_login, &LoginDlg::OnBnClickedCheckLogin)
END_MESSAGE_MAP()
```

**Các loại message được xử lý**:
- `ON_BN_CLICKED`: Khi button được click
- `ON_NOTIFY`: Xử lý notification từ common controls
- `ON_WM_PAINT`: Xử lý vẽ lại giao diện
- `ON_WM_SYSCOMMAND`: Xử lý system commands

### 3.4 Dialog Data Exchange (DDX)

```cpp
void CChatAppClientDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST_SCREEN, list_message);  // Liên kết control với biến
    DDX_Control(pDX, IDC_LIST_USER, list_user);
}
```

### 3.5 List Control Operations

```cpp
// Thêm column
list_message.InsertColumn(0, L"Sender", LVCFMT_LEFT, 100);
list_message.InsertColumn(1, L"Time", LVCFMT_LEFT, 100);
list_message.InsertColumn(2, L"Message", LVCFMT_LEFT, 300);

// Thiết lập style
list_message.SetExtendedStyle(list_message.GetExtendedStyle() | 
    LVS_EX_FULLROWSELECT |  // Chọn cả hàng
    LVS_EX_GRIDLINES);       // Hiển thị đường kẻ

// Thêm item
int index = list_message.GetItemCount();
list_message.InsertItem(index, senderDisplay);
list_message.SetItemText(index, 1, displayTime.Format(L"%H:%M:%S"));
list_message.SetItemText(index, 2, CString(msg.message));

// Lưu dữ liệu với item
list_user.SetItemData(index, userList.users[i].userId);

// Lấy item được chọn
int selectedIndex = list_user.GetNextItem(-1, LVNI_SELECTED);
int userId = static_cast<int>(list_user.GetItemData(selectedIndex));
```

### 3.6 Modal Dialog

```cpp
// Hiển thị dialog và chờ kết quả
LoginDlg loginDlg;
INT_PTR loginResponse = loginDlg.DoModal();
if (loginResponse != IDOK) {
    return FALSE;  // Người dùng đóng hoặc cancel
}

// Đóng dialog với kết quả
EndDialog(IDOK);     // Thành công
EndDialog(IDCANCEL); // Hủy bỏ
```

### 3.7 Common Controls Initialization

```cpp
// Khởi tạo Common Controls (cần thiết cho Windows XP trở lên)
INITCOMMONCONTROLSEX InitCtrls;
InitCtrls.dwSize = sizeof(InitCtrls);
InitCtrls.dwICC = ICC_WIN95_CLASSES;  // Các control class Windows 95
InitCommonControlsEx(&InitCtrls);
```

### 3.8 Edit Control Operations

```cpp
// Lấy text từ edit control
CString username;
GetDlgItemText(IDC_username_text, username);

// Set text cho edit control
SetDlgItemText(IDC_EDIT_SEND, L"");

// Password character
CEdit* pEdit = reinterpret_cast<CEdit*>(GetDlgItem(editControlId));
pEdit->SetPasswordChar(showText ? 0 : L'*');  // 0 = hiển thị text, '*' = ẩn
pEdit->Invalidate();
pEdit->UpdateWindow();
```

---

## 4. Đa Luồng (Threading)

### 4.1 MFC Threading (AfxBeginThread)

```cpp
// Tạo worker thread với MFC
pConnecttThread = AfxBeginThread(ConnectServerThread, this);

// Thread procedure phải có signature:
static UINT ConnectServerThread(LPVOID pParam)
{
    CChatAppClientDlg* pDlg = (CChatAppClientDlg*)pParam;
    // Xử lý trong thread
    return 0;
}
```

### 4.2 WinAPI Threading (CreateThread)

```cpp
// Tạo thread với WinAPI
CreateThread(
    NULL,              // Security attributes
    0,                 // Stack size (0 = default)
    AcceptThreadProc,  // Thread function
    this,              // Parameter
    0,                 // Creation flags
    NULL               // Thread ID (không cần)
);

// Thread procedure signature
DWORD WINAPI AcceptThreadProc(LPVOID pParam)
{
    CChatServerService* pService = (CChatServerService*)pParam;
    // Xử lý trong thread
    return 0;
}
```

### 4.3 Các Thread Trong Hệ Thống

**Server**:
1. **Accept Thread**: Chờ và chấp nhận kết nối mới từ client
2. **Client Thread**: Mỗi client có một thread riêng để xử lý giao tiếp

**Client**:
1. **Connect Thread**: Kết nối đến server và gửi yêu cầu đăng nhập
2. **Client Thread**: Nhận tin nhắn từ server và cập nhật UI

---

## 5. Windows Service

### 5.1 Service Entry Point

```cpp
int wmain(int argc, wchar_t* argv[])
{
#ifdef _SERVICE
    // Xử lý command line
    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            CChatServerService::Install();
            return 0;
        }
        else if (_wcsicmp(argv[1], L"uninstall") == 0) {
            CChatServerService::Uninstall();
            return 0;
        }
    }

    // Đăng ký với Service Control Manager
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)L"ChatAppServerService", CChatServerService::ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(ServiceTable);
#endif
}
```

### 5.2 Service Installation

```cpp
BOOL CChatServerService::Install()
{
    // Lấy đường dẫn file thực thi
    TCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szUnquotedPath, MAX_PATH);
    
    // Mở Service Control Manager
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    
    // Tạo service
    SC_HANDLE hService = CreateService(
        hSCManager,
        SERVICE_NAME,                    // Tên service
        L"Chat Server Service",          // Display name
        SERVICE_ALL_ACCESS,              // Quyền truy cập
        SERVICE_WIN32_OWN_PROCESS,       // Loại service
        SERVICE_AUTO_START,              // Khởi động cùng Windows
        SERVICE_ERROR_NORMAL,            // Error control
        szPath,                          // Đường dẫn executable
        NULL, NULL, NULL, NULL, NULL
    );
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}
```

### 5.3 Service Main Function

```cpp
void WINAPI CChatServerService::ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    // Đăng ký control handler
    m_ServiceStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    
    // Cập nhật trạng thái: Đang khởi động
    m_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
    
    // Khởi động server
    g_pService->StartServer();
    
    // Cập nhật trạng thái: Đang chạy
    m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
    
    // Vòng lặp chính
    while (g_pService->m_bServerRunning) {
        Sleep(1000);
    }
    
    // Cập nhật trạng thái: Đã dừng
    m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
}
```

### 5.4 Service Control Handler

```cpp
void WINAPI CChatServerService::ServiceCtrlHandler(DWORD ctrl)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
        // Cập nhật trạng thái: Đang dừng
        m_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
        
        // Dừng server
        if (g_pService) {
            g_pService->StopServer();
        }
        break;
    }
}
```

---

## 6. Registry API

### 6.1 Đăng Ký Auto-Run

```cpp
BOOL CChatAppClientDlg::RegisterAutoRun(BOOL bRegister)
{
    HKEY hKey;
    CString appPath;
    CString appName = L"ChatAppClient_2";
    TCHAR szPath[MAX_PATH];
    
    // Lấy đường dẫn ứng dụng
    GetModuleFileName(NULL, szPath, MAX_PATH);
    appPath.Format(L"\"%s\"", szPath);
    
    // Mở registry key
    LONG result = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        &hKey
    );

    if (bRegister) {
        // Thêm giá trị để chạy cùng Windows
        result = RegSetValueEx(
            hKey,
            appName,
            0,
            REG_SZ,
            (BYTE*)(LPCTSTR)appPath,
            (appPath.GetLength() + 1) * sizeof(TCHAR)
        );
    }
    else {
        // Xóa giá trị
        result = RegDeleteValue(hKey, appName);
    }

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}
```

### 6.2 Kiểm Tra Auto-Run

```cpp
BOOL CChatAppClientDlg::IsAutoRunEnabled()
{
    HKEY hKey;
    LONG result = RegOpenKeyEx(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_QUERY_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD dwType = REG_SZ;
    DWORD dwSize = 0;
    
    // Kiểm tra giá trị có tồn tại không
    result = RegQueryValueEx(hKey, appName, NULL, &dwType, NULL, &dwSize);

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}
```

---

## 7. File I/O API

### 7.1 Lưu Tin Nhắn Ra File

```cpp
void CChatAppClientDlg::OnBnClickedButtonSaveMessage()
{
    // Lấy đường dẫn Documents folder
    wchar_t folderPath[MAX_PATH] = { 0 };
    HRESULT hr = SHGetFolderPath(nullptr, CSIDL_PERSONAL, nullptr, 
                                  SHGFP_TYPE_CURRENT, folderPath);
    
    // Fallback: sử dụng thư mục chứa executable
    if (FAILED(hr) || folderPath[0] == L'\0') {
        GetModuleFileName(nullptr, folderPath, MAX_PATH);
        // Cắt bỏ tên file, giữ lại đường dẫn thư mục
    }

    // Tạo tên file với timestamp
    CTime now = CTime::GetCurrentTime();
    CString fullPath;
    fullPath.Format(L"%sChat_%s_%04d%02d%02d_%02d%02d%02d.txt",
        folder.GetString(), sanitizedName.GetString(), 
        now.GetYear(), now.GetMonth(), now.GetDay(),
        now.GetHour(), now.GetMinute(), now.GetSecond());

    // Tạo file
    HANDLE hFile = CreateFile(
        fullPath, 
        GENERIC_WRITE, 
        0,                          // Không chia sẻ
        nullptr, 
        CREATE_ALWAYS,              // Tạo mới hoặc ghi đè
        FILE_ATTRIBUTE_NORMAL, 
        nullptr
    );

    // Ghi BOM cho UTF-16
    const wchar_t bom = 0xFEFF;
    DWORD written = 0;
    WriteFile(hFile, &bom, sizeof(bom), &written, nullptr);

    // Ghi nội dung
    WriteFile(hFile, content.GetString(), bytesToWrite, &written, nullptr);

    CloseHandle(hFile);
}
```

### 7.2 Logging (Server)

```cpp
void CChatServerService::LogError(const wchar_t* message)
{
    SYSTEMTIME st;
    GetLocalTime(&st);  // Lấy thời gian local

    // Tạo tên file log theo ngày và giờ
    wchar_t logFileName[MAX_PATH];
    swprintf_s(logFileName, MAX_PATH, L"C:\\ChatServer\\error_%04d-%02d-%02d_%02d.log",
               st.wYear, st.wMonth, st.wDay, st.wHour);
    
    // Ghi log (sử dụng C++ streams)
    std::wofstream logFile(logFileName, std::ios::app);
    if (logFile.is_open()) {
        logFile << L"[" << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
                << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond
                << L"] ERROR: " << message << std::endl;
        logFile.close();
    }
}
```

---

## 8. BCrypt API (Mã Hóa)

### 8.1 Hash Mật Khẩu (SHA-256)

```cpp
BOOL CChatServerService::HashPassword(const std::wstring& password, std::wstring& hash)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHash = NULL;
    DWORD cbHash = 0, cbData = 0;

    // Mở algorithm provider
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);

    // Lấy kích thước hash
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);

    // Cấp phát bộ nhớ cho hash
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);

    // Tạo hash handle
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);

    // Hash dữ liệu password
    BCryptHashData(hHash, (PBYTE)password.c_str(), 
                   (ULONG)(password.length() * sizeof(wchar_t)), 0);

    // Hoàn thành hash
    BCryptFinishHash(hHash, pbHash, cbHash, 0);

    // Chuyển đổi sang hex string
    wchar_t temp[3];
    for (DWORD i = 0; i < cbHash; i++) {
        swprintf_s(temp, 3, L"%02x", pbHash[i]);
        hash.append(temp);
    }

    // Cleanup
    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return TRUE;
}
```

### 8.2 Xác Minh Mật Khẩu

```cpp
BOOL CChatServerService::VerifyPassword(const std::wstring& password, 
                                         const std::wstring& storedHash)
{
    std::wstring hashToVerify;
    if (HashPassword(password, hashToVerify)) {
        return hashToVerify == storedHash;  // So sánh chuỗi hash
    }
    return FALSE;
}
```

---

## 9. Shell API

### 9.1 Lấy Đường Dẫn Thư Mục Đặc Biệt

```cpp
// Lấy đường dẫn thư mục Documents
wchar_t folderPath[MAX_PATH] = { 0 };
HRESULT hr = SHGetFolderPath(
    nullptr,           // Owner window (không cần)
    CSIDL_PERSONAL,    // Documents folder
    nullptr,           // Access token (mặc định)
    SHGFP_TYPE_CURRENT, // Lấy đường dẫn hiện tại
    folderPath
);
```

**Các CSIDL thường dùng**:
- `CSIDL_PERSONAL`: Documents
- `CSIDL_DESKTOP`: Desktop
- `CSIDL_APPDATA`: Application Data

### 9.2 Shell Manager (MFC)

```cpp
// Tạo shell manager để hỗ trợ shell controls
CShellManager* pShellManager = new CShellManager;

// Cleanup khi thoát
if (pShellManager != nullptr) {
    delete pShellManager;
}
```

---

## 10. Critical Section (Đồng Bộ Hóa)

### 10.1 Khởi Tạo và Hủy

```cpp
// Trong constructor
InitializeCriticalSection(&m_csClients);

// Trong destructor
DeleteCriticalSection(&m_csClients);
```

### 10.2 Sử Dụng Critical Section

```cpp
void CChatServerService::RemoveClient(int clientId)
{
    EnterCriticalSection(&m_csClients);  // Vào vùng critical
    
    // Thao tác với dữ liệu chia sẻ
    for (auto it = m_clients.begin(); it != m_clients.end(); ++it) {
        if ((*it)->clientId == clientId) {
            m_clients.erase(it);
            break;
        }
    }
    m_authenticatedUsers.erase(clientId);
    
    LeaveCriticalSection(&m_csClients);  // Rời vùng critical
}
```

### 10.3 Các Thao Tác Cần Đồng Bộ

1. **Thêm client mới**
2. **Xóa client khi disconnect**
3. **Tìm kiếm client theo ID**
4. **Cập nhật trạng thái xác thực**
5. **Broadcast tin nhắn đến nhiều client**

---

## 11. Giao Thức Truyền Thông Tùy Chỉnh

### 11.1 Cấu Trúc Packet

```cpp
// Header của mỗi packet
struct PacketHeader {
    PacketType type;   // Loại packet (4 bytes)
    uint32_t size;     // Kích thước payload (4 bytes)
};

// Các loại packet
enum class PacketType : uint32_t {
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    FriendList,
    ChatMessage,
    ChatHistoryRequest,
    ChatHistoryResponse,
};
```

### 11.2 Class Packet (Serialization)

```cpp
class Packet {
private:
    PacketType m_type;
    std::vector<char> m_buffer;
    size_t m_offset = 0;

public:
    // Ghi số nguyên 32-bit
    void WriteUInt32(uint32_t value) {
        WriteData(&value, sizeof(value));
    }

    // Ghi chuỗi Unicode
    void WriteString(const std::wstring& str) {
        uint32_t len = static_cast<uint32_t>(str.length());
        WriteUInt32(len);  // Ghi độ dài trước
        if (len > 0) {
            WriteData(str.c_str(), len * sizeof(wchar_t));
        }
    }

    // Đọc số nguyên 32-bit
    bool ReadUInt32(uint32_t& value) {
        return ReadData(&value, sizeof(value));
    }

    // Đọc chuỗi Unicode
    bool ReadString(std::wstring& str) {
        uint32_t len = 0;
        if (!ReadUInt32(len)) return false;
        if (len == 0) { str.clear(); return true; }
        if (m_offset + len * sizeof(wchar_t) > m_buffer.size()) return false;
        
        str.resize(len);
        return ReadData(&str[0], len * sizeof(wchar_t));
    }
};
```

### 11.3 Gửi Packet

```cpp
bool SendPacket(SOCKET socket, const Packet& packet)
{
    PacketHeader header;
    header.type = packet.GetType();
    header.size = static_cast<uint32_t>(packet.GetSize());
    
    // Gửi header trước
    if (!SendAll(socket, &header, sizeof(header))) {
        return false;
    }
    
    // Gửi payload (nếu có)
    if (header.size > 0) {
        return SendAll(socket, packet.GetData(), static_cast<int>(header.size));
    }
    return true;
}
```

### 11.4 Nhận Packet

```cpp
bool ReceivePacket(SOCKET socket, PacketHeader& header, std::vector<char>& payload)
{
    // Nhận header
    if (!RecvAll(socket, &header, sizeof(header))) {
        return false;
    }
    
    // Nhận payload
    payload.resize(header.size);
    if (header.size > 0) {
        if (!RecvAll(socket, payload.data(), static_cast<int>(header.size))) {
            return false;
        }
    }
    return true;
}
```

### 11.5 Ví Dụ: Login Request/Response

```cpp
// Client gửi login request
Packet packet(PacketType::LoginRequest);
packet.WriteString(std::wstring(username.GetString()));
packet.WriteString(std::wstring(password.GetString()));
SendPacket(socket, packet);

// Server nhận và xử lý
case PacketType::LoginRequest:
{
    std::wstring username, password;
    packet.ReadString(username);
    packet.ReadString(password);
    
    int userId = 0;
    if (AuthenticateUser(username.c_str(), password.c_str(), userId)) {
        SendLoginResult(clientSocket, 1, userId, username, L"Login successful.");
    }
    else {
        SendLoginResult(clientSocket, 0, 0, L"", L"Invalid credentials.");
    }
    break;
}

// Server gửi login response
void SendLoginResult(SOCKET socket, int success, int userId, 
                     const std::wstring& username, const std::wstring& detail)
{
    Packet packet(PacketType::LoginResponse);
    packet.WriteUInt32(success);
    packet.WriteUInt32(userId);
    packet.WriteString(username);
    packet.WriteString(detail);
    SendPacket(socket, packet);
}
```

---

## 12. SQLite Database

### 12.1 Kết Nối Database

```cpp
BOOL CChatServerService::InitializeSQLConnection()
{
    CloseSQLConnection();
    
    // Tạo thư mục nếu chưa có
    const wchar_t* kDatabaseDirectory = L"F:\\VSCMCCS\\ChatServerDB";
    CreateDirectoryW(kDatabaseDirectory, nullptr);
    
    // Mở database (UTF-16)
    std::wstring dbPath = std::wstring(kDatabaseDirectory) + L"\\ChatAppdb.db";
    if (sqlite3_open16(dbPath.c_str(), &m_db) != SQLITE_OK) {
        LogSqliteError(L"sqlite3_open16");
        return FALSE;
    }
    m_sqlConnected = true;

    // Bật foreign keys
    ExecuteSQLQuery(L"PRAGMA foreign_keys = ON;");
    return TRUE;
}
```

### 12.2 Xác Thực Người Dùng

```cpp
BOOL CChatServerService::AuthenticateUser(const wchar_t* username, 
                                           const wchar_t* password, int& userId)
{
    sqlite3_stmt* stmt = nullptr;
    const wchar_t* sql = L"SELECT userid, password_hash FROM Account WHERE username = ?";
    
    // Chuẩn bị statement
    sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr);
    
    // Bind parameter
    sqlite3_bind_text16(stmt, 1, username, -1, SQLITE_TRANSIENT);
    
    // Thực thi và kiểm tra kết quả
    int rc = sqlite3_step(stmt);
    BOOL ok = FALSE;
    if (rc == SQLITE_ROW) {
        userId = sqlite3_column_int(stmt, 0);
        const wchar_t* storedHash = (const wchar_t*)sqlite3_column_text16(stmt, 1);
        if (storedHash && VerifyPassword(password, storedHash)) {
            ok = TRUE;
        }
    }
    
    sqlite3_finalize(stmt);
    return ok;
}
```

### 12.3 Lưu Tin Nhắn

```cpp
BOOL CChatServerService::SaveMessageToDB(int senderId, int receiverId, 
                                          const wchar_t* content)
{
    sqlite3_stmt* stmt = nullptr;
    const wchar_t* sql = L"INSERT INTO Msg (sender_id, receiver_id, content, sendDate) "
                         L"VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
    
    sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr);
    
    sqlite3_bind_int(stmt, 1, senderId);
    sqlite3_bind_int(stmt, 2, receiverId);
    sqlite3_bind_text16(stmt, 3, content, -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return rc == SQLITE_DONE;
}
```

### 12.4 Lấy Lịch Sử Chat

```cpp
BOOL CChatServerService::GetChatHistory(int userId1, int userId2, 
                                         std::vector<Msg>& messages)
{
    const wchar_t* sql =
        L"SELECT sender_id, receiver_id, content, strftime('%s', sendDate) "
        L"FROM Msg WHERE (sender_id = ? AND receiver_id = ?) "
        L"OR (sender_id = ? AND receiver_id = ?) ORDER BY sendDate";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr);

    sqlite3_bind_int(stmt, 1, userId1);
    sqlite3_bind_int(stmt, 2, userId2);
    sqlite3_bind_int(stmt, 3, userId2);
    sqlite3_bind_int(stmt, 4, userId1);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Msg msg = {};
        msg.senderUserId = sqlite3_column_int(stmt, 0);
        msg.targetUserId = sqlite3_column_int(stmt, 1);
        
        const void* content = sqlite3_column_text16(stmt, 2);
        if (content) {
            wcsncpy_s(msg.message, (const wchar_t*)content, _TRUNCATE);
        }
        
        msg.time = static_cast<time_t>(sqlite3_column_int64(stmt, 3));
        messages.push_back(msg);
    }

    sqlite3_finalize(stmt);
    return TRUE;
}
```

---

## Tổng Kết

### Các WinAPI Chính Được Sử Dụng

| Category | APIs |
|----------|------|
| **Socket** | `WSAStartup`, `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `closesocket`, `WSACleanup` |
| **Threading** | `CreateThread`, `AfxBeginThread` |
| **Critical Section** | `InitializeCriticalSection`, `EnterCriticalSection`, `LeaveCriticalSection`, `DeleteCriticalSection` |
| **Registry** | `RegOpenKeyEx`, `RegSetValueEx`, `RegQueryValueEx`, `RegDeleteValue`, `RegCloseKey` |
| **File I/O** | `CreateFile`, `WriteFile`, `CloseHandle`, `GetModuleFileName` |
| **Shell** | `SHGetFolderPath` |
| **BCrypt** | `BCryptOpenAlgorithmProvider`, `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`, `BCryptCloseAlgorithmProvider` |
| **Service** | `StartServiceCtrlDispatcher`, `RegisterServiceCtrlHandler`, `SetServiceStatus`, `OpenSCManager`, `CreateService`, `OpenService`, `DeleteService`, `ControlService` |
| **Time** | `GetLocalTime`, `SYSTEMTIME` |
| **Memory** | `HeapAlloc`, `HeapFree`, `GetProcessHeap` |

### Điểm Nổi Bật Của Thiết Kế

1. **Multithreading**: Xử lý nhiều client đồng thời với thread riêng cho mỗi kết nối
2. **Thread Safety**: Sử dụng Critical Section để đồng bộ hóa truy cập dữ liệu
3. **Custom Protocol**: Thiết kế giao thức packet-based cho truyền thông hiệu quả
4. **Password Security**: Hash mật khẩu với SHA-256 trước khi lưu trữ
5. **Windows Service**: Hỗ trợ chạy như Windows Service cho môi trường production
6. **Auto-Start**: Tích hợp Registry để tự động khởi động với Windows
