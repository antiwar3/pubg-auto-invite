// dllmain.cpp : 定义 DLL 应用程序的入口点。


#include "glabol.h"



unsigned char code[12];
HMODULE g_this;
#define MAP_FILE_NAME (L"Global\\PubgAutoInvite")
//global var
DWORD64  g_dwJmp;
char g_strProtobuf[1000] = { "0" };
char g_strFriendccount[255] = { "0" };
char g_strMyAccout[255] = { "0" };
char protobufid[100] = { "0" };
DWORD64 g_dwlen = 0;
bool g_isSend = false;
char strBattlEyePath[MAX_PATH] = { "0" };
//extern fun
extern "C" void hookSend();
BOOL InjectDll(UINT32 ProcessId, char *strDllPath);
struct INVITEDATA
{
	bool bIsInvite;//设置为true dll开始组队
	char strFriendId[255];//需要邀请人的pubgid
	char strMyId[255];//自己的pubgid
	char strMyNickName[255];//pubg的nickname
	DWORD strPlayerNum;//组队的人数，包括队长
};
INVITEDATA mInviteData;
DWORD WINAPI SetTimeThread(LPVOID lp)
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	st.wMinute = st.wMinute + 2;
	SetLocalTime(&st);
	Sleep(3000);
	//GetLocalTime(&st);
	//st.wMinute = st.wMinute - 2;
	//SetLocalTime(&st);
	return 0;
}

//导出这个给他们用
bool SendInvite(char *strAccountId)
{
	if (!strlen(strAccountId))
	{
		printf("pubg accountid is null\n");
		return false;
	}
	memset(g_strFriendccount, 0, 255);
	strcpy(g_strFriendccount, strAccountId);
	
	memset(g_strProtobuf, 0, 1000);
	sprintf(g_strProtobuf, ",null,\"UserProxyApi\",\"PartyInvite\",\"%s\",false,{\"IdType\":\"division\",\"GameType\":\"bro\",\"LeagueType\":\"official\",\"SeasonType\":\"2018-06\",\"RegionType\":\"as\",\"PartyType\":\"solo\"}]", g_strFriendccount);
	CloseHandle(CreateThread(0, 0, SetTimeThread, 0, 0, 0));
	g_isSend = true;
	printf("start sendinvite\n");
	return true;
}

bool RecvInvite(char *strFriendAccountId, char *strMyAccountId,char *strMyNickname)
{
	if (!strlen(strFriendAccountId)|| !strlen(strMyAccountId)|| !strlen(strMyNickname))
	{
		printf("pubg accountid is null\n");
		return false;
	}
	memset(g_strMyAccout, 0, 255);
	strcpy(g_strMyAccout, strMyAccountId);
	memset(g_strFriendccount, 0, 255);
	strcpy(g_strFriendccount, strFriendAccountId);
	memset(g_strProtobuf, 0, 1000);
	sprintf(g_strProtobuf, ",null,\"UserProxyApi\",\"PartyInviteResponse\",{\"RequestId\":\"f992524cdcb64812a10de784a5390bb6\",\"InviteAccountId\":\"%s\",\"InvitedAccountId\":\"%s\",\"IsFriend\":true,\"IsEventMode\":false,\"DivisionId\":{\"IdType\":\"division\",\"GameType\":\"bro\",\"LeagueType\":\"official\",\"SeasonType\":\"2018 - 06\",\"RegionType\":\"as\",\"PartyType\":\"duo\"}},\"%s\",true]", g_strFriendccount, g_strMyAccout, strMyNickname);
	CloseHandle(CreateThread(0, 0, SetTimeThread, 0, 0, 0));
	g_isSend = true;
	printf("start recvinvite\n");
	return true;
}

bool LeaveTeam()
{
	memset(g_strProtobuf, 0, 1000);
	sprintf(g_strProtobuf, ", null, \"UserProxyApi\", \"PartyLeave\"]");
	CloseHandle(CreateThread(0, 0, SetTimeThread, 0, 0, 0));
	g_isSend = true;
	printf("start leaveteam\n");
	return true;
}

DWORD WINAPI HookThread(LPVOID lp)
{
	DWORD64 hModule = (DWORD64)GetModuleHandleA("CoherentGTCore.dll");
	//48 8B C4 48 89 58 10 48 89 68 18 48 89 70 20 57 48 81 EC 80 00 00 00 4C 89 48 A8 48 8B F1 4C 89 40 A0 48 8D 48 D0

	DWORD64 dwHook = hModule + 0x2e4617;
	g_dwJmp = hModule + 0x2e4626;
	//随便判断下地址，万一游戏升级了
	//if (*(DWORD*)dwHook = 0x4ccf8b4d)
	//{
	
		DWORD oldflag;
		if (VirtualProtect((PVOID)dwHook, 12, PAGE_EXECUTE_READWRITE, &oldflag))
		{
			code[0] = 0x48;
			code[1] = 0xbe;
			code[10] = 0x56;
			code[11] = 0xC3;
			DWORD64 dwFunAddr = (DWORD64)hookSend;
			RtlMoveMemory(code + 2, &dwFunAddr, 8);
			WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwHook, code, 12, NULL);
			VirtualProtect((PVOID)dwHook, 12, oldflag, &oldflag);
			printf("hook sucess\n");
		}
	//}
// 	else
// 	{
// 		MessageBoxA(NULL, "游戏版本不对", "提示", NULL);
// 	}
	return 0;
}

extern "C"
{
	void __stdcall MakeProtobuf(char *protoid)
	{
		
		char protobuf[500] = { "0" };
		strcpy(protobuf, protoid);
		strcat(protobuf, g_strProtobuf);
		memset(g_strProtobuf, 0, 1000);
		strcpy(g_strProtobuf, protobuf);
		
		g_dwlen = strlen(g_strProtobuf);
		printf("%s %x\n", g_strProtobuf,g_dwlen);

	}
}


DWORD WINAPI TestThread(LPVOID lp)
{
	while (1)
	{
		Sleep(500);
		if (::GetKeyState(VK_F1) < 0)
		{
			printf("press f1\n");
			 //account.a8c2ccf2be9a498fa3df137f8e61bdad王毅
		     SendInvite("account.e532d4129f9c4bb5ba624f50d0d383a2");
			Sleep(1000);
		}
		if (::GetKeyState(VK_F2) < 0)
		{
			printf("press f2\n");
			RecvInvite("account.2bf8e5a3da6944c099c591463774a781","account.ef236544a5464013befd6bac28b770b1","xbxbnono1");
			//RecvInvite(mInviteData.strFriendId, mInviteData.strMyId, mInviteData.strMyNickName);
			Sleep(1000);
		}
		if (::GetKeyState(VK_F3) < 0)
		{
			printf("press f2\n");
			//RecvInvite("account.2bf8e5a3da6944c099c591463774a781","account.ef236544a5464013befd6bac28b770b1","xbxbnono1");
			LeaveTeam();
			Sleep(1000);
		}

		
	}
	return 0;
}
void MyAddPubgNickName(char *szWebData)
{

	
	if (strstr(szWebData, "FollowUser"))
	{

		
		if (strstr(szWebData, "account"))
		{
			char* p1 = strstr(szWebData, "account");
			char* p2 = strstr(p1, "\"");
			if (p1&&p2)
			{
				DWORD len = p2 - p1;
			
				memset(mInviteData.strFriendId, 0, 255);
				memcpy(&mInviteData.strFriendId, (char*)p1, len);
				printf("add: %s\n", mInviteData.strFriendId);
			}
		}

	}
}
extern "C"
{
	bool CheckData(DWORD64 p)
	{
		if (g_isSend)
		{
			
			char *szWebData = (char*)(p);
			if (strstr(szWebData, "UserProxyApi"))
			{
				if (strstr(szWebData, "Ping"))
				{
					if (strstr(szWebData, ","))
					{
						int len = strstr(szWebData, ",") - szWebData;
						if (len < 100)
						{
							g_isSend = false;
							memcpy(protobufid, szWebData, len);
							MakeProtobuf(protobufid);
							return true;
						}
					}

				}
			
			}
		}
		MyAddPubgNickName((char*)p);
		return false;
	}
}

bool GetShareMemory()
{
	bool bRet = false;
	SharedMemory *pSharedMemory = NULL;
	pSharedMemory = new SharedMemory();
	pSharedMemory->Lock(INFINITE);
	if (pSharedMemory->Open(MAP_FILE_NAME, FALSE))
	{
		pSharedMemory->MapAt(0, sizeof(INVITEDATA));
		LPVOID pVoid = pSharedMemory->GetMemory();

		memcpy(&mInviteData, pVoid, sizeof(mInviteData));

		pSharedMemory->Unlock();
		pSharedMemory->Close();

		delete pSharedMemory;
		bRet = true;
	}
	else printf("sharememory error\n");

	//MessageBoxA(0, mInviteData.strFriendId, 0, 0);
	return bRet;
}



struct testee_config : public websocketpp::config::asio {
	// pull default settings from our core config  
	typedef websocketpp::config::asio core;

	typedef core::concurrency_type concurrency_type;
	typedef core::request_type request_type;
	typedef core::response_type response_type;
	typedef core::message_type message_type;
	typedef core::con_msg_manager_type con_msg_manager_type;
	typedef core::endpoint_msg_manager_type endpoint_msg_manager_type;

	typedef core::alog_type alog_type;
	typedef core::elog_type elog_type;
	typedef core::rng_type rng_type;
	typedef core::endpoint_base endpoint_base;

	static bool const enable_multithreading = false;

	struct transport_config : public core::transport_config {
		typedef core::concurrency_type concurrency_type;
		typedef core::elog_type elog_type;
		typedef core::alog_type alog_type;
		typedef core::request_type request_type;
		typedef core::response_type response_type;

		static bool const enable_multithreading = false;
	};

	typedef websocketpp::transport::asio::endpoint<transport_config>
		transport_type;

	static const websocketpp::log::level elog_level =
		websocketpp::log::elevel::all;
	static const websocketpp::log::level alog_level =
		websocketpp::log::alevel::all;
};
typedef websocketpp::server<testee_config> server;




void Base64_Decode(const char* Data, int DataByte, std::string &strDecode)
{
	//解码表
	char DecodeTable[] =
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		62, // '+'
		0, 0, 0,
		63, // '/'
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // '0'-'9'
		0, 0, 0, 0, 0, 0, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // 'A'-'Z'
		0, 0, 0, 0, 0, 0,
		26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // 'a'-'z'
	};
	//返回值
	int nValue;
	int i = 0;
	while (i < DataByte)
	{
		if (*Data != '\r' && *Data != '\n')
		{
			nValue = DecodeTable[*Data++] << 18;
			nValue += DecodeTable[*Data++] << 12;
			strDecode += (nValue & 0x00FF0000) >> 16;
			if (*Data != '=')
			{
				nValue += DecodeTable[*Data++] << 6;
				strDecode += (nValue & 0x0000FF00) >> 8;
				if (*Data != '=')
				{
					nValue += DecodeTable[*Data++];
					strDecode += nValue & 0x000000FF;
				}
			}
			i += 4;
		}
		else
		{
			Data++;
			i++;
		}
	}
}

void Base64_Encode(const char* Data, int DataByte, std::string &strEncode)
{
	char *EncodeTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned char Tmp[4] = { 0 };
	for (int i = 0; i < (int)(DataByte / 3); i++)
	{
		Tmp[1] = (unsigned char)*Data++;
		Tmp[2] = (unsigned char)*Data++;
		Tmp[3] = (unsigned char)*Data++;
		strEncode += EncodeTable[Tmp[1] >> 2];
		strEncode += EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3F];
		strEncode += EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3F];
		strEncode += EncodeTable[Tmp[3] & 0x3F];
	}
	//对剩余数据进行编码
	int Mod = DataByte % 3;
	if (Mod == 1)
	{
		Tmp[1] = (unsigned char)*Data++;
		strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
		strEncode += EncodeTable[((Tmp[1] & 0x03) << 4)];
		strEncode += "==";
	}
	else if (Mod == 2)
	{
		Tmp[1] = (unsigned char)*Data++;
		Tmp[2] = (unsigned char)*Data++;
		strEncode += EncodeTable[(Tmp[1] & 0xFC) >> 2];
		strEncode += EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xF0) >> 4)];
		strEncode += EncodeTable[((Tmp[2] & 0x0F) << 2)];
		strEncode += '=';
	}
}


typedef struct _URL_INFO
{
	WCHAR szScheme[512];
	WCHAR szHostName[512];
	WCHAR szUserName[512];
	WCHAR szPassword[512];
	WCHAR szUrlPath[512];
	WCHAR szExtraInfo[512];
}URL_INFO, *PURL_INFO;

void ANSIToUnicode(const std::string &str, std::wstring &out)
{
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), NULL, 0);
	out.resize(len);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), (LPWSTR)out.data(), len);
}

#define DEBUG_OUTPUTA(fmt, ...) OutputDebugStringA(CFormatStringA<>(fmt, __VA_ARGS__).get())
bool GetPubgRoleId(char* rolename,std::string &roleid)
{
	
	bool bRet = false;
	URL_INFO url_info = { 0 };
	URL_COMPONENTSW lpUrlComponents = { 0 };
	lpUrlComponents.dwStructSize = sizeof(lpUrlComponents);
	lpUrlComponents.lpszExtraInfo = url_info.szExtraInfo;
	lpUrlComponents.lpszHostName = url_info.szHostName;
	lpUrlComponents.lpszPassword = url_info.szPassword;
	lpUrlComponents.lpszScheme = url_info.szScheme;
	lpUrlComponents.lpszUrlPath = url_info.szUrlPath;
	lpUrlComponents.lpszUserName = url_info.szUserName;

	lpUrlComponents.dwExtraInfoLength =
		lpUrlComponents.dwHostNameLength =
		lpUrlComponents.dwPasswordLength =
		lpUrlComponents.dwSchemeLength =
		lpUrlComponents.dwUrlPathLength =
		lpUrlComponents.dwUserNameLength = 512;
	char url[256];
	sprintf_s(url, sizeof(url), "http://api.battlecare.qq.com/pubg/get_role_info_by_name?role_name=%s", rolename);

	std::wstring wUrl;
	ANSIToUnicode(url, wUrl);

	if (WinHttpCrackUrl(wUrl.c_str(), 0, ICU_ESCAPE, &lpUrlComponents))

	{
		// 创建一个会话
		HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
		if (hSession)
		{
			DWORD dwReadBytes, dwSizeDW = sizeof(dwSizeDW), dwIndex = 0;
			// 创建一个连接
			HINTERNET hConnect = WinHttpConnect(hSession, lpUrlComponents.lpszHostName, lpUrlComponents.nPort, 0);
			if (hConnect)
			{
				// 创建一个请求，获取数据
				std::wstring path = lpUrlComponents.lpszUrlPath;
				path += lpUrlComponents.lpszExtraInfo;
				HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), L"HTTP/1.1", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
				//WinHttpAddRequestHeaders(hRequest, L"Content-type: application/x-www-form-urlencoded\r\n", _countof(L"Content-type: application/x-www-form-urlencoded\r\n") - 1, WINHTTP_ADDREQ_FLAG_ADD);
				//WinHttpAddRequestHeaders(hRequest, L"cookie: puin=237213;tgp_id=115477613;tgp_ticket=624C9683AE9D495E1D4CC6995527F850B70285E0432D91DE8DD35FB2F2B18247FD511B1A7A5F6908D8CA2E831E332EC04B61EDE54B28BE38C34C65ACFED2C1D216477DF9C8E22935A8297AC27BDE72DA56DDEB0965587C8F66DE9B00A02D09CC320838FC2D5746756D55E61A42F1FB20\r\n", _countof(L"cookie: puin=237213;tgp_ticket=624C9683AE9D495E1D4CC6995527F850B70285E0432D91DE8DD35FB2F2B18247FD511B1A7A5F6908D8CA2E831E332EC04B61EDE54B28BE38C34C65ACFED2C1D216477DF9C8E22935A8297AC27BDE72DA56DDEB0965587C8F66DE9B00A02D09CC320838FC2D5746756D55E61A42F1FB20;tgp_id=115477613\r\n") - 1, WINHTTP_ADDREQ_FLAG_ADD);

				std::stringstream ss;
				if (hRequest)
				{

					if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
					{
						
						WinHttpReceiveResponse(hRequest, 0);


						while (1)
						{
							char buf[128];
							dwReadBytes = 0;
							WinHttpReadData(hRequest, buf, 128, &dwReadBytes);
							if (!dwReadBytes)
								break;
							ss.write(buf, dwReadBytes);
						}
						std::string payload = ss.str();


						OutputDebugStringA(payload.c_str());
						using namespace rapidjson;
						Document doc;
						if (!doc.Parse(payload.c_str(), payload.length()).HasParseError() && doc.IsObject())
						{
				
							if (doc.HasMember("retCode") && doc["retCode"].IsInt())
							{
								
								auto retcode = doc["retCode"].GetInt();
								if (!retcode)//无错误
								{
									
									auto &data_val = doc.FindMember("data");
									if (data_val != doc.MemberEnd()
										&& data_val->value.IsObject())
									{
										auto &data_obj = data_val->value.GetObjectW();
									
											auto &troleid = data_obj.FindMember("role_id");
											roleid = troleid->value.GetString();
											bRet = true;
										
									}
		
								}
								else
								{
									DEBUG_OUTPUTA("retcode error\n");
								}
			
								
							}

						}
						else
						{

						
							DEBUG_OUTPUTA("json parse error");
						}
					}
					else
					{
						DEBUG_OUTPUTA("failed to WinHttpSendRequest, %d", GetLastError());
					}
					WinHttpCloseHandle(hRequest);
				}
				else
				{
					DEBUG_OUTPUTA("failed to WinHttpOpenRequest, %d", GetLastError());
				}
				WinHttpCloseHandle(hConnect);
			}
			else
			{
				DEBUG_OUTPUTA("failed to WinHttpConnect, %d", GetLastError());
			}
			WinHttpCloseHandle(hSession);
		}
		else
		{
			DEBUG_OUTPUTA("failed to WinHttpOpen, %d", GetLastError());
		}
	}
	else
	{
		DEBUG_OUTPUTA("failed to WinHttpCrackUrl, %d", GetLastError());
	}
	return bRet;
}
void on_http(server* s, websocketpp::connection_hdl hdl)
{
	server::connection_ptr con = s->get_con_from_hdl(hdl);
	websocketpp::http::parser::request rt = con->get_request();
	const std::string& strUri = rt.get_uri();
	const std::string& strMethod = rt.get_method();
	const std::string& strBody = rt.get_body();
	const std::string& strVersion = rt.get_version();
	//std::cout << "接收到一个" << strMethod.c_str() << "请求：" << strUri.c_str() << "线程ID=" << ::GetCurrentThreadId() << std::endl;
	//std::cout << strBody << std::endl;

	bool bSuccess = false;
	if (strMethod.compare("POST") == 0)
	{
		if (strUri.compare("/pubgautoinvite") == 0)
		{
			using namespace rapidjson;

			std::string errmsg;
			Document doc;
			doc.Parse(strBody.c_str(), strBody.length());
			if (!doc.HasParseError())
			{
				//std::cout << "member count = "<< doc.MemberCount() << std::endl;

				if (doc.HasMember("friendnickname") && doc["friendnickname"].IsString()
					&& doc.HasMember("mypubgnickname") && doc["mypubgnickname"].IsString()
				
					)
				{
					auto strFriendNickName = doc["friendnickname"].GetString();
					auto strMyNickName = doc["mypubgnickname"].GetString();
					std::string strMyRoleId,strFriendRoleId;
					StringBuffer buffer;
					Writer<StringBuffer> writer(buffer);
					Document newDoc;
					newDoc.SetObject();
					Document::AllocatorType &allocator = newDoc.GetAllocator();
					if (GetPubgRoleId((char*)strMyNickName, strMyRoleId) && GetPubgRoleId((char*)strFriendNickName, strFriendRoleId))
					{
						//printf("%s %s\n", strMyRoleId.c_str(), strFriendRoleId.c_str());
						RecvInvite((char*)strFriendRoleId.c_str(), (char*)strMyRoleId.c_str(), (char*)strMyNickName);
						newDoc.AddMember("data", rapidjson::StringRef("ok", strlen("ok")), allocator);
						newDoc.AddMember("errcode", 0, allocator);
					}
					else
					{
						newDoc.AddMember("data", rapidjson::StringRef("getroleid error", strlen("getroleid error")), allocator);
						newDoc.AddMember("errcode", 1, allocator);
					}
		
					newDoc.Accept(writer);
					con->set_body(buffer.GetString());
					con->set_status(websocketpp::http::status_code::value(websocketpp::http::status_code::ok));
					return;
				}
				else
				{
					errmsg = "missing json member";
				}
			}
			else
			{
				errmsg = "json parse error";
			}

			Document newDoc;
			newDoc.SetObject();
			Document::AllocatorType &allocator = newDoc.GetAllocator();

			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);

			newDoc.AddMember("msg", rapidjson::StringRef(errmsg.c_str(), errmsg.length()), allocator);
			newDoc.AddMember("errcode", 1, allocator);
			newDoc.Accept(writer);

			std::cout << "err: " << errmsg << std::endl;

			con->set_body(buffer.GetString());
			con->set_status(websocketpp::http::status_code::value(websocketpp::http::status_code::ok));
			return;
		}
	}
	con->set_body("404 not found");
	con->set_status(websocketpp::http::status_code::value(websocketpp::http::status_code::not_found));
}

void on_socket_init(websocketpp::connection_hdl, boost::asio::ip::tcp::socket & s) {
	boost::asio::ip::tcp::no_delay option(true);
	s.set_option(option);
}

DWORD WINAPI ServerThread(LPVOID lp)
{
	server testee_server;

	// Total silence  
	testee_server.clear_access_channels(websocketpp::log::alevel::all);
	testee_server.clear_error_channels(websocketpp::log::alevel::all);

	// Initialize ASIO  
	testee_server.init_asio();
	testee_server.set_reuse_addr(true);

	// Register our message handler  
	testee_server.set_socket_init_handler(std::bind(&on_socket_init, std::placeholders::_1, std::placeholders::_2));
	testee_server.set_http_handler(std::bind(&on_http, &testee_server, std::placeholders::_1));
	// Listen on specified port with extended listen backlog  
	testee_server.set_listen_backlog(8193);
	testee_server.listen(6657);

	// Start the server accept loop  
	testee_server.start_accept();

	// Start the ASIO io_service run loop  
	testee_server.run();
	return 1;
}


bool InitPath()
{
	bool bRet = false;
	DWORD dwPid;
	dwPid = GetProcessId(L"TslGame_BE.exe");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPid);
	if (hProcess)
	{
		HMODULE hModule;
		DWORD needed;
		EnumProcessModules(hProcess, &hModule, sizeof(hModule), &needed);
		if (hModule)
		{
			char path[255] = { "0" };
			if (GetModuleFileNameExA(hProcess, hModule, path, sizeof(path)))
			{
				PathRemoveFileSpecA(path);
				strcpy(strBattlEyePath, path);
				bRet = true;
			}
		}

	}
	return bRet;
}


DWORD WINAPI InjectThread(LPVOID lp)
{
	while (1)
	{
		Sleep(500);
		HWND  hGame = FindWindow(L"UnrealWindow", NULL);
		if (hGame)
		{
			Sleep(5000);
			DWORD pid;
			GetWindowThreadProcessId(hGame, &pid);
			char strExePath[MAX_PATH] = { "0" };
			//GetCurrentDirectoryA(MAX_PATH, strExePath);
			GetModuleFileNameA(g_this, strExePath, MAX_PATH);
			PathRemoveFileSpecA(strExePath);
			strcat(strExePath, "\\PubgAutoInvite.dll");
			printf("%s\n", strExePath);
			if (!InjectDll(pid, strExePath))printf("inject failed\n");
			else printf("inject sucess\n");
			break;
		}

	}
	return 1;
}

DWORD WINAPI ThreadClickButton(LPVOID lp)
{
	int start = 1;
	while (1)
	{
		Sleep(100);
		HWND hBattlEyebat = FindWindowA(NULL, "BattlEye Launcher");
		if (hBattlEyebat)
		{
			HWND hButton1 = FindWindowExA(hBattlEyebat, NULL, NULL, "是(&Y)");
			if (hButton1)
			{
				printf("find &Y\n");
				SendMessage(hButton1, WM_LBUTTONDOWN, 0, 0);
				SendMessage(hButton1, WM_LBUTTONUP, 0, 0);
				CreateThread(0, 0, InjectThread, 0, 0, 0);
				start = start + 1;
			}
			HWND hButton2 = FindWindowExA(hBattlEyebat, NULL, NULL, "确定");
			if (hButton2)
			{
				printf("find 确定\n");
				SendMessage(hButton2, WM_LBUTTONDOWN, 0, 0);
				SendMessage(hButton2, WM_LBUTTONUP, 0, 0);


			}

		}
	}
}


DWORD WINAPI ThreadWaitGame(LPVOID lp)
{
	CreateThread(0, 0, ThreadClickButton, 0, 0, 0);
	DWORD dwNowTickcount = 0;
	while (1)
	{
		Sleep(500);

		HWND  hGame = FindWindow(L"UnrealWindow", NULL);
		if (hGame)
		{
			printf("find game\n");
			SetForegroundWindow(hGame);
			Sleep(1000);
			CreateThread(0, 0, InjectThread, 0, 0, 0);
// 			if (InitPath())
// 			{
// 				STARTUPINFO si = { sizeof(si) };
// 				PROCESS_INFORMATION pi = { 0 };
// 				printf("%s\n", strBattlEyePath);
// 				strcat(strBattlEyePath, "\\BattlEye");
// 				SetCurrentDirectoryA(strBattlEyePath);
// 				strcat(strBattlEyePath, "\\Uninstall_BattlEye.bat");
// 				system(strBattlEyePath);
// 			}

			break;
			//SetWindowText(hGame, L"test");
		}
	}
	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		char strPath[MAX_PATH] = { "0" };
		GetModuleFileNameA(NULL, strPath, MAX_PATH);
		char strExeName[200] = { "0" };
		strcpy(strExeName, PathFindFileNameA(strPath));

		g_this = hModule;
		if (!strcmp(strExeName, "TslGame.exe"))
		{
			if (AllocConsole())
			{
				freopen("CONOUT$", "w", stdout);
				printf("Im In!\n");
			}
// 			if (GetShareMemory())
// 			{
				CloseHandle(CreateThread(0, 0, HookThread, 0, 0, 0));
				CloseHandle(CreateThread(0, 0, ServerThread, 0, 0, 0));
				CloseHandle(CreateThread(0, 0, TestThread, 0, 0, 0));
// 			}
// 			else
// 			{
// 				printf("sharememory error 1\n");
// 			}

		}
		else
		{
			CreateThread(0, 0, ThreadWaitGame, 0, 0, 0);
		}
		
		

		
	}break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

