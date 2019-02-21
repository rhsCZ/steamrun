#include <stdio.h>
#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>
#include <processthreadsapi.h>
#pragma warning (disable : 4302)
#pragma warning (disable : 4477)
using namespace std;
char dir[256];
char file[256];
char process[256];
char pid2[256];
HANDLE thread1;
PROCESS_INFORMATION pi;
STARTUPINFO si = { sizeof(STARTUPINFO) };
bool wow64 = false;
int pid15;
bool error = false;
bool run2 = false;
BOOL IsRunAsAdministrator();
BOOL IsWow64();
void ElevateNow();
int getdir();
void filedel();
void WriteZero();
unsigned long GetRegKey();
bool fileExists(const char *fileName);
bool showProcessInformation(unsigned int pid, const char *filename);
char exe[150] = {0};
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
bool fileExists(const char *fileName)
{
	ifstream infile(fileName);
	return infile.good();
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
	strcpy(file, dir);
	strcat(file, "\\.crash");
	strcpy(process, dir);
	strcat(process, "\\steam.exe");
	strcpy(pid2, dir);
	strcat(pid2, "\\steamrun.pid");
	if (dir == NULL && file == NULL && process == NULL)
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
			sprintf(exe, "%s", peInfo.szExeFile);
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
void filedel()
{
	ifstream delfile;
	while (1)
	{
		if(run2 == true)
		{
			if (fileExists(file))
			{
				HANDLE h = CreateFile((LPCSTR)file, GENERIC_READ | GENERIC_WRITE, 0, NULL, 5, FILE_ATTRIBUTE_NORMAL, NULL);
				CloseHandle(h);
				Sleep(800);
			}

		}
		else break;
	}
	Sleep(2000);
	if (fileExists(file))
	{
		HANDLE h = CreateFile((LPCSTR)file, GENERIC_READ | GENERIC_WRITE, 0, NULL, 5, FILE_ATTRIBUTE_NORMAL, NULL);
		CloseHandle(h);
		CloseHandle(thread1);
	} else CloseHandle(thread1);
}
void WriteZero()
{
	HANDLE h = CreateFile((LPCSTR)pid2, GENERIC_READ | GENERIC_WRITE, 0, NULL, 5, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(h, "000000", 1, NULL, NULL);
	CloseHandle(h);
}
int main()
{
	if (IsRunAsAdministrator())
	{	
		if(getdir() == 1)
		{
			if (error == false)
			{
				goto program;
			}
			else goto exit;
			program:
			char pid3[12] = {0};
			if (!fileExists(pid2))
			{
				
				 HANDLE h = CreateFile((LPCSTR)pid2, GENERIC_READ | GENERIC_WRITE,0,NULL,1,FILE_ATTRIBUTE_NORMAL,NULL);
				 CloseHandle(h);
			}
			HANDLE h = CreateFile((LPCSTR)pid2, GENERIC_READ | GENERIC_WRITE, 0, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);
			if (GetLastError() != ERROR_FILE_NOT_FOUND)
			{
				ReadFile(h, pid3, 10, NULL, NULL);
				CloseHandle(h);
				sscanf(pid3, "%d", &pid15);
			}
			
			if(pid15 == 0 || !showProcessInformation(GetRegKey(), "steamrun.exe"))
			{
				char buff[20] = {0,0,0,0,0,0,0,0,0,0,0,0};
				sprintf(buff, "%u", GetCurrentProcessId());
				h = CreateFile((LPCSTR)pid2, GENERIC_READ | GENERIC_WRITE, 0, NULL, 5, FILE_ATTRIBUTE_NORMAL, NULL);
				WriteFile(h, buff, sizeof(GetCurrentProcessId()), NULL, NULL);
				CloseHandle(h);
				if(GetRegKey() == 0 || (!showProcessInformation(GetRegKey(),"Steam.exe") || !showProcessInformation(GetRegKey(), "steam.exe")))
				{
					HKEY hKey = { 0 };
					LONG result = 0;
					unsigned long type = REG_DWORD, size = 0;
					if (GetRegKey() >= 1)
					{
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
							RegSetValueEx(hKey, "SteamPID", NULL, type, 0, size);
						}
						else goto exit;
					} 
					CreateProcessA(process, NULL, 0, 0, 0, 0, 0, 0, &si, &pi);
					pid15 = pi.dwProcessId;
					thread1 = (HANDLE)CreateThread(0, 0, (LPTHREAD_START_ROUTINE)filedel, 0, 0, 0);
					run2 = true;
					WaitForSingleObject(pi.hProcess, INFINITE);
					run2 = false;
				}
				else
				{
					HANDLE proces = OpenProcess(SYNCHRONIZE, FALSE, GetRegKey());
					pid15 = GetRegKey();
					thread1 = (HANDLE)CreateThread(0, 0, (LPTHREAD_START_ROUTINE)filedel, 0, 0, 0);
					run2 = true;
					WaitForSingleObject(proces, INFINITE);
					run2 = false;
				}
				WaitForSingleObject(thread1, INFINITE);
				WriteZero();
					exit(0);
			}
			else
			{
				
				if (!showProcessInformation(pid15,"steamrun.exe"))
				{
					WriteZero();
					goto program;
				}
				else goto exit;
				exit(1);
			}
		}
		else
		{
			exit(2);
		}
	}
	else
	{
		ElevateNow();

	}
exit:
	exit(3);
}


