#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <synchapi.h>
#include <process.h>
#include <ctype.h>
#include <thread>
#include <TlHelp32.h>
#include <cstdio>
using namespace std;
char dir[256];
char file[256];
char process[256];
BOOL IsRunAsAdministrator();
HANDLE GetProcessByName(PCSTR name);
void ElevateNow();
int getdir();
bool run;
void filedel();
HANDLE thread1;

BOOL IsRunAsAdministrator()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:

	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsRunAsAdmin;
}
void ElevateNow()
{
	BOOL bAlreadyRunningAsAdministrator = FALSE;
	try
	{
		bAlreadyRunningAsAdministrator = IsRunAsAdministrator();
	}
	catch (...)
	{
		_asm nop
	}
	if (!bAlreadyRunningAsAdministrator)
	{
		char szPath[MAX_PATH];
		if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
		{


			SHELLEXECUTEINFO sei = { sizeof(sei) };

			sei.lpVerb = "runas";
			sei.lpFile = szPath;
			sei.hwnd = NULL;
			sei.nShow = SW_NORMAL;

			if (!ShellExecuteEx(&sei))
			{
				DWORD dwError = GetLastError();
				if (dwError == ERROR_CANCELLED)
					//Annoys you to Elevate it LOL
					CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ElevateNow, 0, 0, 0);
			}
		}

	}
	else
	{
		///Code
	}
}
HANDLE GetProcessByName(PCSTR name)
{
	DWORD pid = 0;
	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);
	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (string(process.szExeFile) == string(name))
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}
	CloseHandle(snapshot);

	if (pid != 0)
	{
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	} 
	return NULL;
}
int main()
{
	if (IsRunAsAdministrator())
	{
		if(getdir() == 1)
		{
			run = true;
			thread1 = (HANDLE)CreateThread(0, 0, (LPTHREAD_START_ROUTINE)filedel, 0, 0, 0);
			STARTUPINFO si = { sizeof(STARTUPINFO) };
			PROCESS_INFORMATION pi;
			CreateProcess(process, NULL, 0, 0, 0, 0, 0, 0, &si, &pi);
			WaitForSingleObject(pi.hProcess, INFINITE);
			if (GetProcessByName("steam.exe") == NULL)
			{
				run = false;
			}
			WaitForSingleObject(thread1, INFINITE);
			exit(0);
		} else exit(1);
	}
	else
	{
		ElevateNow();

	}
}
/*bool fileExists(const char *fileName)
{
	ifstream infile(fileName);
	return infile.good();
}*/
int getdir()
{
	if (GetEnvironmentVariable("steam", dir, sizeof(dir)) == 0)
	{
		ifstream test;
		test.open("C:\\Windows\\SysWOW64\\license.rtf");
		if (test.is_open())
		{
			strncpy(dir, "C:\\Program Files (x86)\\Steam", sizeof(dir));
			test.close();
		}
		else
		{
			strncpy(dir, "C:\\Program Files\\Steam", sizeof(dir));
			test.close();
		}
	}
	strcpy(file, dir);
	strcat(file, "\\.crash");
	strcpy(process, dir);
	strcat(process, "\\steam.exe");
	if(dir == NULL && file == NULL && process == NULL)
	{
		return 0;
	} else {
	return 1;
	}
}
void filedel()
{
	ifstream delfile;
	while(1)
	{
		if(GetProcessByName("steam.exe") != NULL)
		{ 
			delfile.open(file, ios::in);
			if(delfile.is_open())
			{ 
				delfile.close();
				remove(file);
				Sleep(800);
			}
		}
		else
		{
			Sleep(2000);
			remove(file);
			CloseHandle(thread1);

		}
	}
}
