#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include "vector" 
#include <iostream>	
#include "shield.h"

int LotOFClicker = 0, click = 0;
int RightClick(int key){
	return (GetAsyncKeyState(key) & 0x8000 != 0);
}
int ClickerStamp = 0;
bool ControlC(unsigned char k) {
	USHORT status = GetAsyncKeyState(k);
	return (((status & 0x8000) >> 15) == 1) || ((status & 1) == 1);
}
DWORD WINAPI CheakSpeedClick(LPVOID lpParam)
{
	Sleep(60000);
	while (true)
	{
		ClickerStamp = GetTickCount() / 4;
		if (RightClick(VK_RBUTTON)/* && ControlC(VK_CONTROL)*/)
		{

			click++;
			if (click >= 45)
			{
				LotOFClicker++;
				click = NULL;
				if (LotOFClicker > 3)
				{
					char p[100];
					sprintf(p, "Play~With~Clicker");
					LogError("Ending because of clicker Sdetection.");
					HACK_DETECTED(p);
					HANDLE thread_Handle;
					thread_Handle = CreateThread(NULL, 0,
						EXIT, NULL, 0, NULL);
					MessageBoxA(0, "Clicker running!/Close it!", "OK", MB_OK);
					exit(0);
				}
			}
		}
		else{
			Sleep(10);
		}
	}
	return true;
}
DWORD WINAPI restartclick(LPVOID lpParam)
{
	while (true)
	{
		click = NULL;
		Sleep(5000);
	}
	return true;
}
int StartTheardClicker() { CreateThread(NULL, 0, CheakSpeedClick, 0, 0, NULL); CreateThread(NULL, 0, restartclick, NULL, 0, NULL); return TRUE; }