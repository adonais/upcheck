#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include "thunderagent.hpp"

#ifdef __cplusplus
extern "C"
#endif
bool WINAPI 
thunder_download(char *b_url, char *b_refer, char *b_cookies)
{
    HRESULT hr;
    ThunderAgentLib::IAgent2 *pAgent = NULL;
    if (NULL == b_url)
    {
        return false;
    }
    CoInitialize(NULL);
    hr = CoCreateInstance(__uuidof(ThunderAgentLib::Agent), NULL, CLSCTX_INPROC_SERVER, __uuidof(ThunderAgentLib::IAgent2), (void**)&pAgent);
    if (FAILED(hr))
    {
        printf("CoCreateInstance error\n");
	CoUninitialize();
        return false;
    }
    _bstr_t url(b_url);
    _bstr_t refer(b_refer);
    _bstr_t cookies(b_cookies);
    pAgent->AddTask2(url, _bstr_t(""), _bstr_t(""), _bstr_t(""), refer, 1, 0, -1, cookies);
    pAgent->CommitTasks2(1);
    pAgent->Release(); 
    CoUninitialize();
    return true;
}
