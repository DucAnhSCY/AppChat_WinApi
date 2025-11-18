// WindowServiceChatAppServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <winsock2.h>
#include "Struct.h"
#include "ChatAppServer.h"
#include <string>
#include <ws2tcpip.h>
#include <cstring>

static int RunConsoleServer()
{
    std::wcout << L"[Console] Chat server test mode (no Windows Service)." << std::endl;
    std::wcout << L"[Console] Starting server on 127.0.0.1:9999..." << std::endl;

    CChatServerService server;
    server.StartServer();

    std::wcout << L"[Console] Server is running." << std::endl;
    std::wcout << L"[Console] Type 'quit' then ENTER to stop." << std::endl;

    std::wstring line;
    while (std::getline(std::wcin, line)) {
        if (line == L"quit" || line == L"exit") {
            break;
        }
        if (line.empty()) {
            continue;
        }
        std::wcout << L"[Console] Unknown command: " << line << std::endl;
        std::wcout << L"[Console] Available: quit" << std::endl;
    }

    std::wcout << L"[Console] Stopping server..." << std::endl;
    server.StopServer();
    std::wcout << L"[Console] Server stopped." << std::endl;
    return 0;
}

int wmain(int argc, wchar_t* argv[])
{
#ifdef _SERVICE
    // Service build: support install/uninstall and run via SCM
    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            if (CChatServerService::Install()) {
                std::wcout << L"Service installed successfully!" << std::endl;
            }
            else {
                std::wcout << L"Failed to install service. Error: " << GetLastError() << std::endl;
            }
            return 0;
        }
        else if (_wcsicmp(argv[1], L"uninstall") == 0) {
            if (CChatServerService::Uninstall()) {
                std::wcout << L"Service uninstalled successfully!" << std::endl;
            }
            else {
                std::wcout << L"Failed to uninstall service. Error: " << GetLastError() << std::endl;
            }
            return 0;
        }
    }

    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)L"ChatAppServerService", CChatServerService::ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        std::wcout << L"Error: Service must be run by Service Control Manager." << std::endl;
        std::wcout << L"Usage:" << std::endl;
        std::wcout << L"  ChatServer.exe install   - Install service" << std::endl;
        std::wcout << L"  ChatServer.exe uninstall - Uninstall service" << std::endl;
        return 1;
    }

    return 0;
#else
    // Non-service build: run console server for testing
    return RunConsoleServer();
#endif // !_SERVICE
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started:
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
