//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "windows.h"
#include "stdio.h"
#include "FindBanned.h"
// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//




#pragma comment(lib,"WS2_32.lib")
unsigned char code[12];
DWORD64  g_dwJmp;
char g_strProtobuf[1000] = { "0" };
DWORD64 g_dwlen;
extern "C" void hookSend();
BOOL g_isSend = FALSE;
BOOL g_isExit = FALSE;
char g_strstate[100] = { "nothing" };


unsigned char  g_Banned2[39] = { 

0x59,0x00,0x6F,0x00,0x75,0x00,0x20,0x00,0x68,0x00,0x61,0x00,0x76,0x00,0x65,0x00,0x20,0x00,0x62,0x00,0x65,0x00,0x65,0x00,0x6E,0x00,0x20,0x00,0x62,0x00,0

x61,0x00,0x6E,0x00,0x6E,0x00,0x65,0x00,0x64 };




BOOL GetBaseAddress(PBYTE const pCharacter, DWORD dwSize, DWORD offset, DWORD flag, HANDLE hProcess, DWORD filter)
{

	__try {
		BOOL bRet = FALSE;
		printf("scanprocess please waiting\n");
		SYSTEM_INFO si;
		HANDLE RemotehProcess;
		PBYTE pCurPos, pTemp;
		MEMORY_BASIC_INFORMATION mbi;
		int i = 0;//一共找到多少个
				  //如果dwSize为0，IsBadReadPtr()返回0，即FALSE，但!dwSize为TRUE
				  //如果dwSize不为0，而且pCharacter可读，返回FLASE，!dwSize为FALSE
				  //如果dwSize不为0，但pCharacter不可读，IsBadReadPtr返回TRUE，!dwSize是FLASE
		if (IsBadReadPtr(pCharacter, dwSize) || !dwSize)
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			return bRet;
		}
		//初始化操作
		GetSystemInfo(&si);
		RemotehProcess = hProcess;
		//开始扫描可执行内存
		for (pCurPos = (LPBYTE)si.lpMinimumApplicationAddress; pCurPos < (LPBYTE)si.lpMaximumApplicationAddress - dwSize; pCurPos = (PBYTE)

mbi.BaseAddress + mbi.RegionSize)
		{
			//printf("%x\n", pCurPos);
			//查询页面属性
			VirtualQueryEx(RemotehProcess, pCurPos, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			if (mbi.RegionSize == filter)
			{
				if (mbi.State == MEM_COMMIT  && dwSize <= mbi.RegionSize)
				{
					if (mbi.Protect == PAGE_READWRITE)
					{
						DWORD pos = 0;
						DWORD searchLen = dwSize - 1;
						for (pTemp = (PBYTE)mbi.BaseAddress; pTemp < (PBYTE)mbi.BaseAddress + mbi.RegionSize; pTemp++)
						{

							if ((PBYTE)mbi.BaseAddress + mbi.RegionSize - pTemp > dwSize)
							{
								if (*(PBYTE)pTemp == pCharacter[pos])
								{
									pos++;
									if (pos == dwSize)
									{
										return TRUE;
									}

								}
								else
								{
									pos = 0;
								}
							}

						}

					}

				}

			}


		}

		SetLastError(ERROR_NOT_FOUND);
		return bRet;
	}
	__except (1)
	{
		return FALSE;
	}

}







DWORD WINAPI ThreadFindBanned(LPVOID lp)
{
	Sleep(8000);
	BOOL dwRet = GetBaseAddress((PBYTE)g_Banned2, 39, 0, 0, GetCurrentProcess(), 0x100000);
	if (dwRet)
	{
		printf("find banned !!!!!!! addr : %x\r\n", dwRet);
		memset(g_strstate, 0, 100);
		strcpy(g_strstate, "banned");
		g_isSend = TRUE;
		g_isExit = TRUE;
	}
	else
	{
		printf("not find\n");
		printf("nothing\n");
		memset(g_strstate, 0, 100);
		strcpy(g_strstate, "nothing");
		g_isSend = TRUE;
		g_isExit = TRUE;

	}
	return 1;
}
 extern "C"
 {
	BOOL CheckData(DWORD64 p, DWORD64 len)
	{
		if (len)
		{
			char *szWebData = (char*)(p);
			if (strstr(szWebData, "UserProxyApi"))
			{
				if (strstr(szWebData, "GetFollowingsAndRecents"))
				{
					printf("nothing\n");
					memset(g_strstate, 0, 100);
					strcpy(g_strstate, "nothing");
					g_isSend = TRUE;
					g_isExit = TRUE;
				}
			}
		}
		else
		{
			// 			memset(g_strstate, 0, 100);
			// 			strcpy_s(g_strstate, "banned");
			// 			g_isSend = true;
			CreateThread(0, 0, ThreadFindBanned, 0, 0, 0);
		}
		return FALSE;
	}

}

//点击游戏内部，不然不开始刷新大厅
void ClienkGame(RECT rt)
{
	int nx = 0;
	int ny = 0;
	POINT  pt = { 0,0 };
	nx = (rt.right - rt.left)*0.84;
	ny = (rt.bottom - rt.top)*0.93;

	pt.x = rt.left + nx;
	pt.y = rt.top + ny;

	SetCursorPos(pt.x, pt.y);
	Sleep(500);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	return;
}

DWORD g_dwCount = 0;
DWORD WINAPI WaitGame(LPVOID lp)
{
	DWORD dwNowTickcount = 0;
	while (1)
	{
		HWND  hGame = FindWindow("UnrealWindow", NULL);
		SetForegroundWindow(hGame);
		RECT rt;
		GetWindowRect(hGame, &rt);
		ClienkGame(rt);
		Sleep(3000);
		dwNowTickcount = GetTickCount();
		if (dwNowTickcount - g_dwCount > 1000 * 60 * 2)
		{
			memset(g_strstate, 0, 100);
			strcpy(g_strstate, "loginfailed");
			g_isSend = TRUE;
			Sleep(3000);

		}
	}
}

DWORD WINAPI HookThread(LPVOID lp)
{
	//48 8B C4 48 89 58 10 48 89 68 18 48 89 70 20 57 48 81 EC 80 00 00 00 4C 89 48 A8 48 8B F1 4C 89 40 A0 48 8D 48 D0
	CloseHandle(CreateThread(0, 0, WaitGame, 0, 0, 0));
	DWORD64 hModule = (DWORD64)GetModuleHandleA("CoherentGTCore.dll");


	DWORD64 dwHook = hModule + 0x2e4567;
	g_dwJmp = hModule + 0x2e4576;
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




BOOL connectserver()
{
	WSADATA wsd;
	SOCKET sockClient;
	SOCKADDR_IN addrSrv;

	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("start up failed!\n");
		return 0;
	}

	sockClient = socket(AF_INET, SOCK_STREAM, 0);
	if (INVALID_SOCKET == sockClient)
	{
		printf("create client socket error!\n");
		return 0;
	}
	addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(6000);
	if (SOCKET_ERROR == connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR)))    //连接服务器端
	{
		printf("connect server error!\n");
		return 0;
	}
	while (1)
	{
		Sleep(1000);
		if (g_isSend == TRUE)
		{
			send(sockClient, g_strstate, strlen(g_strstate), 0);
			break;
		}

	}
	closesocket(sockClient);
	WSACleanup();

}

DWORD WINAPI ConnectThread(LPVOID lp)
{
	connectserver();
	return 1;
}


BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			if (AllocConsole())
			{
				freopen("CONOUT$", "w", stdout);
				printf("Im In!\n");
			}
			g_dwCount = GetTickCount();
			CloseHandle(CreateThread(0, 0, HookThread, 0, 0, 0));
			CloseHandle(CreateThread(0, 0, ConnectThread, 0, 0, 0));
			//MessageBoxA( NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK );
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
