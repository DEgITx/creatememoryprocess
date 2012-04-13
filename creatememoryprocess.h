#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
    #include <windows.h>
#else
    #error Process Forking Requires a Windows Operating System
#endif

#define CPDEBUG

__declspec(dllexport) bool WINAPI CreateMemoryProcess(LPVOID lpImage, char* pPath = "");
__declspec(dllexport) bool WINAPI CreateMemoryProcessFromFile(char* fPath, char* fInjected = "");

#ifdef __cplusplus
}
#endif