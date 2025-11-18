#include <map>
#include <string>
#include <vector>
#include <ctime>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

#pragma once

#define MAX_SENDER_LENGTH 50
#define MAX_MESSAGE_LENGTH 256
#define MAX_CLIENTS 100
#define MAX_HISTORY_MESSAGES 100

enum PacketType {
	PACKET_MESSAGE = 1,
	PACKET_USER_LIST = 2,
	PACKET_LOGIN_RESULT = 3,
	PACKET_CHAT_HISTORY = 4
};

enum ClientCommand {
	CMD_LOGIN = 1,
	CMD_REGISTER = 2,
	CMD_CHAT_HISTORY_REQUEST = 3,
	CMD_PRIVATE_MESSAGE = 4
};

struct LoginResult
{
	int success;
	int userId;
	wchar_t username[MAX_SENDER_LENGTH];
	wchar_t detail[128];
};

struct Msg
{
	int targetUserId;
	int senderUserId;
	wchar_t sender[MAX_SENDER_LENGTH];
	time_t time;
	wchar_t message[MAX_MESSAGE_LENGTH];
};

struct UserInfo {
	int userId;
	int isOnline;
	wchar_t username[MAX_SENDER_LENGTH];
};

struct UserListUpdate {
	int count;
	UserInfo users[MAX_CLIENTS];
};

struct ClientInfo
{
	SOCKET clientSocket;
	int clientId;
	int userId;
	wchar_t username[MAX_SENDER_LENGTH];
	void* pDlg;
};

struct ChatHistoryResponse
{
	int friendUserId;
	int count;
	Msg entries[MAX_HISTORY_MESSAGES];
};