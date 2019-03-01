#include <stdio.h>
#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>
#include <WinUser.h>
#include <processthreadsapi.h>
//#pragma warning (disable : 4302)
//#pragma warning (disable : 4477)
using namespace std;
char process[256];
BOOL IsRunAsAdministrator();
BOOL IsWow64();
void ElevateNow();
int getdir();
int main(int argc, char** argv);
unsigned long GetRegKey();
bool showProcessInformation(unsigned int pid, const char *filename);
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
					CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ElevateNow, 0, 0, 0);
			}
		}

	}
	else
	{
		exit(5);
	}
}
BOOL IsWow64()
{
	fstream testfile;
	testfile.open("C:\\Windows\\SysWOW64\\license.rtf");
	if (testfile.is_open())
	{
		testfile.close();
		return true;
	}
	else
	{
		testfile.close();
		return false;
	}
}
unsigned long GetRegKey()
{
	DWORD dwValue = 0;
	HKEY hKey;
	LONG result;
	unsigned long type = REG_DWORD, size = 1024;
	if (IsWow64())
	{
		result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey);
	}
	else
	{
		result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey);
	}
	if (result == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, "SteamPID", NULL, &type, (LPBYTE)&dwValue, &size);
	}
	RegCloseKey(hKey);
	return dwValue;
}
int getdir()
{
	HKEY hKey = {0};
	LONG result;
	char dir[500];
	unsigned long type = REG_SZ, size = 500;
	if (GetEnvironmentVariable("steam", dir, sizeof(dir)) == 0)
	{
		
		if (IsWow64())
		{
			result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey);
		}
		else
		{
			result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey);
		}
	}
	if (result == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, "InstallPath", NULL, &type, (LPBYTE)&dir, &size);
	}
	RegCloseKey(hKey);
	sprintf(process, "\"%s", dir);
	strcat(process, "\\steam.exe\" -noverifyfiles -silent\0");
	if (dir == NULL && process == NULL)
	{
		return 0;
	}
	else {
		return 1;
	}
}
bool showProcessInformation(unsigned int pid, const char *filename)
{
	DWORD pidx = pid;
	PROCESSENTRY32 peInfo;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, pidx);
	if (hSnapshot)
	{
		peInfo.dwSize = sizeof(PROCESSENTRY32); // this line is REQUIRED
		BOOL nextProcess = Process32First(hSnapshot, &peInfo);
		bool found = false;
		while (nextProcess)
		{
			if (peInfo.th32ProcessID == pid)
			{
				found = true;
				break;
			}
		nextProcess = Process32Next(hSnapshot, &peInfo);
		}
		if (found == true && strcmp(peInfo.szExeFile, filename) == 0)
		{
			CloseHandle(hSnapshot);
			return true;
		}
		else
		{
			CloseHandle(hSnapshot);
			return false;
		}
	
	}
	else 
	{
		return false;
	}
}

int main(int argc, char** argv)
{
	
	if(IsRunAsAdministrator())
	{
		goto main;
	}
	else ElevateNow();
main:
		if (getdir() == 1)
		{
				if (GetRegKey() == 0 || (!showProcessInformation(GetRegKey(), "Steam.exe") && !showProcessInformation(GetRegKey(), "steam.exe")))
				{
					PROCESS_INFORMATION pi;
					STARTUPINFO si = {sizeof(STARTUPINFO)};
					CreateProcessA(0, process, 0, 0, false, 0, 0, 0,&si,&pi);
					CloseHandle(pi.hThread);
					exit(0);
				}
				else goto exit;
		}
		else
		{
			exit(2);
		}
exit:
	exit(3);
}


