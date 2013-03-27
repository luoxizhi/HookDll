// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "BrowserHookDll.h"
#include <string>
using std::string;

#define LOG_PATH ("D:\\log.txt")

#pragma data_seg(".HookSeg")
HWND	g_hParent	= NULL;
HHOOK	g_hHook		= NULL;
#pragma data_seg()
#pragma comment(linker,"/SECTION:.HookSeg,RWS")

HINSTANCE	g_Instance	= NULL;

void TraceLog(string fileContent)
{
	string line;
	__int64 file_handle;
	file_handle = (__int64)::CreateFile(LOG_PATH, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if( file_handle < 0 ){
		file_handle = (__int64)::CreateFile(LOG_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}else{
		::SetFilePointer((HANDLE)file_handle, 0, NULL, FILE_END);
	}
	if( file_handle >= 0 ){            
		DWORD write_count;
		line = fileContent + "\r\n";
		::WriteFile((HANDLE)file_handle, line.c_str(), (DWORD)line.size(), &write_count, NULL);
		CloseHandle((HANDLE)file_handle);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	char processName[256];
	char processID[256];
	ZeroMemory(processName, 256);
	ZeroMemory(processID, 256);
	sprintf_s(processID, 256, "processid = %d\t g_hHook = %d\t", GetCurrentProcessId(), g_hHook);
	GetModuleFileName(GetModuleHandle(NULL), processName, 256);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_Instance = (HINSTANCE)hModule;		
		TraceLog(string("attached. ")+processID+processName);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		TraceLog(string("deattached. ")+processID+processName);
		break;
	}
	return TRUE;
}

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if( nCode < 0 )
		return CallNextHookEx(g_hHook, nCode, wParam, lParam);

	if( g_hParent ){
		switch(nCode){
		case HCBT_ACTIVATE:		
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_ACTIVATE_MSG), wParam, lParam); 
			TraceLog("send activate msg.");
			break;
		case HCBT_CREATEWND:	
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_CREATEWND_MSG), wParam, lParam); 
			TraceLog("send createwnd msg.");
			break;
		case HCBT_DESTROYWND:	
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_DESTROYWND_MSG), wParam, lParam);
			TraceLog("send destorywnd msg.");
			break;
		case HCBT_MINMAX:		
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_MINMAX_MSG), wParam, lParam); 
			TraceLog("send minmax msg.");
			break;
		case HCBT_MOVESIZE:		
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_MOVESIZE_MSG), wParam, lParam); 
			TraceLog("send movesize msg.");
			break;
		case HCBT_SETFOCUS:		
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_SETFOCUS_MSG), wParam, lParam); 
			TraceLog("send setfocus msg.");
			break;
		case HCBT_SYSCOMMAND:	
			::SendMessage(g_hParent, ::RegisterWindowMessage(BHD_CBT_SYSCOMMAND_MSG), wParam, lParam); 
			TraceLog("send syscommand msg.");
			break;
		default: break;
		}		
	}

	return ::CallNextHookEx(g_hHook, nCode, wParam, lParam);
}


__declspec(dllexport) BOOL InstallHook(HWND hWnd)
{
	if( g_hHook == NULL ){
		g_hHook = ::SetWindowsHookEx(WH_CBT, CBTProc, g_Instance, 0);
	}	
	g_hParent = hWnd;
	TraceLog("call installhook.");
	return g_hHook != NULL;
}

__declspec(dllexport) BOOL UnInstallHook()
{
	g_hParent = NULL;
	BOOL result = ::UnhookWindowsHookEx(g_hHook);
	TraceLog("call uninstallhook.");
	g_hHook = NULL;
	return result;
}
