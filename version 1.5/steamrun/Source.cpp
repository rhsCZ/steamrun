#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <synchapi.h>
using namespace std;
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
/*bool fileExists(const char *fileName)
{
	ifstream infile(fileName);
	return infile.good();
}*/
int main()
{
	
	if (IsRunAsAdministrator())
	{
		char dir[256];
		char file[256];
		char process[256];
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
			strcpy(file, dir);
			strcat(file, "\\.crash");
			strcpy(process, dir);
			strcat(process, "\\steam.exe");
			remove(file);
			Sleep(1000);
			STARTUPINFO si = { sizeof(STARTUPINFO) };
			PROCESS_INFORMATION pi;
			CreateProcess(process, NULL,
				0, 0, 0, 0, 0, 0, &si, &pi);
			Sleep(5000);
			remove(file);
			WaitForSingleObject(pi.hProcess, INFINITE);
			Sleep(5000);
			remove(file);
			exit(0);
		}
	}
	else
	{
		ElevateNow();
		
	}
	return 0;
}