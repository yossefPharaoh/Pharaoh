#include "stdafx.h"
#include "AntiDump.h"
#include <tlhelp32.h>
#include "shield.h"
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "Psapi.lib")
#pragma comment (lib, "detours.lib")
int ScanAdderssStamp = 0;
MDump mDumps[] = {
	{ 0x00A99334, { 0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xF0, 0x53, 0xB8 }, "TMX" }, // TMX
	{ 0x01099f56, { 0xE8, 0x0B, 0x05, 0x00, 0x00, 0xE9, 0x6B, 0xFD }, "Hex-Work" }, // Hex-Work
	{ 0x00402938, { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xD0, 0x39 }, "Window-Title-Changer" }, // window-title-changer
	{ 0x00B77285, { 0xE8, 0x2A, 0x05, 0x00, 0x00, 0xE9, 0x7A, 0xFE }, "Process Explorer" }, // Process Explorer x32
	{ 0x0011C61E2, { 0xE8, 0x74, 0x48, 0x00, 0x00, 0xE9, 0x00, 0x00 }, "x32dbg" }, // x32dbg
	{ 0x00401000, { 0xEB, 0x10, 0x66, 0x62, 0x3A, 0x43, 0x2B, 0x2B }, "OllyDbg" }, // OllyDbg
	{ 0x0042BC3E, { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xE8, 0x87 }, "Pe Tools" }, //Pe Tools
	{ 0x0040468E, { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xB8, 0x5D }, "CokFreeAutoClicker" }, //CokFreeAutoClicker
	{ 0x00436EE7, { 0xE8, 0xCA, 0x0A, 0x00, 0x00, 0xE9, 0x7A, 0xFE }, "AutoKeyboard" }, //AutoKeyboard read
	{ 0x00416310, { 0xE8, 0xA7, 0xC0, 0x00, 0x00, 0xE9, 0x79, 0xFE }, "GS AutoClicker" }, //GS AutoClicker
	{ 0x00432C40, { 0xC6, 0x05, 0x10, 0x32, 0x43, 0x00, 0x00, 0xB9 }, "Cheat Engine" }, //Cheat Engine
	{ 0x00403BA0, { 0xC6, 0x05, 0x80, 0xBD, 0x9D, 0x00, 0x00, 0xB9 }, "Cheat Engine" }, //Cheat Engine
	{ 0x0092CAA0, { 0xC6, 0x05, 0x00, 0xE2, 0x92, 0x00, 0x00, 0xB9 }, "Cheat Engine" },  //Cheat Engine
	{ 0x00403BA0, { 0xC6, 0x05, 0x80, 0xCD, 0x9D, 0x00, 0x00, 0xB9 }, "Cheat Engine" },  //Cheat Engine
	{ 0x009327D0, { 0xC6, 0x05, 0x00, 0x42, 0x93, 0x00, 0x00, 0xB9 }, "Cheat Engine" },  //Cheat Engine // AutoMata
	{ 0x0097C920, { 0xC6, 0x05, 0x90, 0xE2, 0x97, 0x00, 0x00, 0xB9 }, "Cheat Engine" }  //Cheat Engine-MOHAMEDSA3IED
};
bool DumpScan(SOCKET SOCK){
	bool bReturn = false;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapShot != INVALID_HANDLE_VALUE){
		PROCESSENTRY32 mP32;
		mP32.dwSize = sizeof(mP32);
		BOOL hRes = Process32First(hSnapShot, &mP32);
		do {
			char c_szText[260];
			for (int x = 0; x <= 259; ++x)
				c_szText[x] = mP32.szExeFile[x];

			/*for (size_t i = 0; i < strlen(c_szText); i++)
			c_szText[i] = tolower(c_szText[i]);*/
			char *programname = &c_szText[0];
			if (!strcmp(programname, "csrss.exe")
				|| !strcmp(programname, "services.exe")//|| !strcmp(programname, "winlogon.exe")
				|| !strcmp(programname, "ekrn.exe") || !strcmp(programname, "lsass.exe")
				//|| !strcmp(programname, "dwm.exe") || !strcmp(programname, "explorer.exe")
				|| !strcmp(programname, "smss.exe") || !strcmp(programname, "httpd.exe")
				|| !strcmp(programname, "SearchProtocolHost.exe") || !strcmp(programname, "UI0Detect.exe")
				|| !strcmp(programname, "wininit.exe") || !strcmp(programname, "lsm.exe")
				|| !strcmp(programname, "spoolsv.exe") || !strcmp(programname, "IpOverUsbSvc.exe")
				|| !strcmp(programname, "sqlservr.exe") || !strcmp(programname, "mysqld.exe")
				|| !strcmp(programname, "sqlwriter.exe") || !strcmp(programname, "jusched.exe")
				|| !strcmp(programname, "IDMan.exe") || !strcmp(programname, "SearchIndexer.exe")
				|| !strcmp(programname, "IEMonitor.exe") || !strcmp(programname, "wmpnetwk.exe")
				|| !strcmp(programname, "devenv.exe") || !strcmp(programname, "WUDFHost.exe")
				|| !strcmp(programname, "MSBuild.exe") || !strcmp(programname, "conhost.exe")
				|| !strcmp(programname, "mspdbsrv.exe") || !strcmp(programname, "vcpkgsrv.exe")
				|| !strcmp(programname, "eguiProxy.exe") || !strcmp(programname, "mstsc.exe"))
				continue;
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, mP32.th32ProcessID);
			if (hProcess != NULL){
				for (int i = 0; i < (sizeof(mDumps) / sizeof(MDump)); i++){
					unsigned char pBytes[8];
					__w64 unsigned long pBytesRead;
					if (ReadProcessMemory(hProcess, (LPCVOID)mDumps[i].dwAddress, (LPVOID)pBytes, 8, &pBytesRead)){
						if (pBytesRead == 8){
							if (!memcmp(pBytes, mDumps[i].pBytes, 8)){
								bReturn = true;
								TerminateProcess(hProcess, NULL);
							}
						}
					}
				}CloseHandle(hProcess);
			}Sleep(20);
		} while (Process32Next(hSnapShot, &mP32));
	}
	CloseHandle(hSnapShot);
	return bReturn;
}

MapAdresses Address[] = { // 2d 6609 DX8

	{ 0x0076A1B5, { 0x75, 0x25, 0xFF, 0x15 }, "DownFast" }, // high jump - DownFast
	{ 0x0076A0DC, { 0x10, 0x7E, 0x36, 0xFF }, "DownFast" }, // high jump - DownFast
	{ 0x0073252E, { 0x8B, 0xBE, 0x28, 0x01 }, "DownFast" }, // high jump - DownFast
	{ 0x0088A611, { 0x83, 0x7E, 0x0C, 0x00 }, "ShowAllSkill" }, // show all skill
	{ 0x006CB335, { 0x3D, 0x00, 0x01, 0x00 }, "ScreenZoom" }, // screen zoom
	{ 0x00744F99, { 0x74, 0x30, 0x8B, 0x74 }, "HidePlayer" }, // HidePlayer
	{ 0x006F00DB, { 0x75, 0x14, 0xE8, 0x4F }, "HP Fast" }, // HP Fast
	{ 0x0074FC52, { 0x75, 0x17, 0x68, 0xD8 }, "PM Command" }, // pm command
	{ 0x008880DD, { 0x03, 0x70, 0x04, 0xE8 }, "Skill Time" }, // Skill Time
	{ 0x008899F3, { 0x74, 0x3E, 0x80, 0x7D }, "MagicType" }, // MagicType
	{ 0x0075AEBC, { 0x74, 0x20, 0xFF, 0x15 }, "Revive Move" }, // Revive Move
	{ 0x0075AE7D, { 0x74, 0x34, 0xFF, 0x15 }, "Revive Momment" }, // Revive Momment
	{ 0x00888FA7, { 0x0F, 0x84, 0x6E, 0xFD }, "Water Revive" }, // WaterRevive
	{ 0x0075AEF2, { 0x75, 0x20, 0xFF, 0x15 }, "Revive Here" }, // Revive Here
};
bool ScanAddress(SOCKET SOCK)
{
	bool Agin = false;

	for (int i = 0; i < (sizeof(Address) / sizeof(MDump)); i++)
	{
		unsigned char pBytes[4];
		__w64 unsigned long pBytesRead;

		if (ReadProcessMemory(GetCurrentProcess(), (LPVOID)Address[i].dwAddress, (LPVOID)pBytes, 4, &pBytesRead))
		{
			if (pBytesRead == 4)
			{
				if (memcmp(pBytes, Address[i].pBytes, 4))
				{
					Agin = true;
					char px[100];
					//char msg[100];
					sprintf(px, "Memory Editing:[%s]", Address[i].Hackapp);
					HACK_DETECTED(px, SOCK);
					//sprintf(msg, "Close any kind of hacks/Memory Editing:[%s]", Address[i].Hackapp);;
				}
			}
		}
		Sleep(20);
	}
	return Agin;
}
DWORD WINAPI Scan(LPVOID lpParam)
{
	SOCKET SOCK;
	SOCK = *((SOCKET*)lpParam);
	Sleep(60000);
	while (true)
	{
		ScanAdderssStamp = GetTickCount() / 3;	
		DumpScan(SOCK);
		Sleep(1000);
		ScanAddress(SOCK);
	}
	return true;
}
int ProtectionDump() {
	HANDLE hToken; LUID luid; TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){ return FALSE; }
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)){ return FALSE; }
	tkp.PrivilegeCount = 1; tkp.Privileges[0].Luid = luid; tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL)) { return FALSE; }
	if (!CloseHandle(hToken)) { return FALSE; } HANDLE  thread_Handle = CreateThread(NULL, 0, Scan, (SOCKET*)INVALID_SOCKET, 0, NULL);
	return TRUE;
}