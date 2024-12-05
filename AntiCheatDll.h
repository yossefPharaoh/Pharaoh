#include "stdafx.h"
#include "stdafx.h"
#include <tlhelp32.h>
#include "shield.h"
#include <stdlib.h>
#include <winsock2.h>
#include <stdio.h>
#include <psapi.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "Psapi.lib")
#pragma comment (lib, "detours.lib")
int PrintModules(DWORD processID, SOCKET SOCK)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return 1;
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)){
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++){
			char szModName[MAX_PATH];
			if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
			{
				/*for (int i = 0; i < cheats_count; i++)
				{
				for (int i = 0; szModName[i]; i++)
				{
				szModName[i] = tolower(szModName[i]);
				}
				if (strstr(szModName, cheats_names[i]))
				{
				HACK_DETECTED(szModName, SOCK);
				}
				} */
				if (strstr(szModName, "AutoItX3")){
					HACK_DETECTED(szModName);
				}
			}
		}
	}
	CloseHandle(hProcess);
	return 0;
}
int ProtectionCheatDll(SOCKET SOCK) {

	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;

	// Get the list of process identifiers.

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return 1;

	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the names of the modules for each process.

	for (i = 0; i < cProcesses; i++){
		PrintModules(aProcesses[i], SOCK);
	}

	return TRUE;
}