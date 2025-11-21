#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#define MAX_SENDER_LENGTH 50
#define MAX_MESSAGE_LENGTH 256
#define MAX_CLIENTS 100
#define MAX_HISTORY_MESSAGES 100

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


struct PacketHeader {
	PacketType type;
	uint32_t size;
};

class Packet {
private:
	PacketType m_type;
	std::vector<char> m_buffer;
	size_t m_offset = 0;

	void WriteData(const void* data, size_t size) {
		m_buffer.insert(m_buffer.end(), (const char*)data, (const char*)data + size);
	}

	bool ReadData(void* data, size_t size) {
		if (m_offset + size > m_buffer.size()) {
			return false;
		}
		memcpy(data, m_buffer.data() + m_offset, size);
		m_offset += size;
		return true;
	}


public:
	Packet(PacketType type = PacketType::LoginRequest) : m_type(type) {}

	PacketType GetType() const {
		return m_type;
	}
	const char* GetData() const {
		return m_buffer.data();
	}
	size_t GetSize() const {
		return m_buffer.size();
	}

	// Write methods
	void WriteUInt32(uint32_t value) {
		WriteData(&value, sizeof(value));
	}

	void WriteString(const std::wstring& str) {
		uint32_t len = static_cast<uint32_t>(str.length());
		WriteUInt32(len);
		WriteData(str.c_str(), len * sizeof(wchar_t));
	}

	// Read methods
	bool ReadUInt32(uint32_t& value) {
		return ReadData(&value, sizeof(value));
	}

	bool ReadString(std::wstring& str) {
		uint32_t len;
		if (!ReadUInt32(len)) return false;
		if (m_offset + len * sizeof(wchar_t) > m_buffer.size()) return false;

		str.resize(len);
		ReadData(&str[0], len * sizeof(wchar_t));
		return true;
	}

	void SetBuffer(const char* data, size_t size) {
		if (data == nullptr || size == 0) {
			m_buffer.clear();
		}
		else {
			m_buffer.assign(data, data + size);
		}
		m_offset = 0;
	}
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