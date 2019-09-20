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
BOOL IsWow64();
int getdir();
int main(int argc, char** argv);
unsigned long GetRegKey();
bool showProcessInformation(unsigned int pid, const char *filename);
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
	HKEY hKey = {NULL};
	LONG result = 0;
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
		if (result != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
		}
	}
	if (result == ERROR_SUCCESS && hKey != NULL)
	{
		RegQueryValueEx(hKey, "InstallPath", NULL, &type, (LPBYTE)&dir, &size);
		RegCloseKey(hKey);
	} 
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

		if (getdir() == 1)
		{
				if (GetRegKey() == 0 || (!showProcessInformation(GetRegKey(), "Steam.exe") && !showProcessInformation(GetRegKey(), "steam.exe")))
				{
					PROCESS_INFORMATION pi;
					STARTUPINFO si = {sizeof(STARTUPINFO)};
					CreateProcessA(0, process, 0, 0, false, 0, 0, 0,&si,&pi);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
					exit(0);
				}
				else goto exit;
		}
exit:
	exit(3);
}


