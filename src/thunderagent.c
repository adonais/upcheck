#ifdef _MSC_VER
#pragma warning(disable : 4049) /* more than 64k source lines */
#pragma comment(lib, "oleaut32.lib")
#endif

/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include <stdio.h>
#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

/* Forward Declarations */

#ifndef __IAgent_FWD_DEFINED__
#define __IAgent_FWD_DEFINED__
typedef interface IAgent IAgent;

#endif /* __IAgent_FWD_DEFINED__ */

#ifndef __IAgent2_FWD_DEFINED__
#define __IAgent2_FWD_DEFINED__
typedef interface IAgent2 IAgent2;

#endif /* __IAgent2_FWD_DEFINED__ */

#ifndef __Agent_FWD_DEFINED__
#define __Agent_FWD_DEFINED__

#ifdef __cplusplus
typedef class Agent Agent;
#else
typedef struct Agent Agent;
#endif /* __cplusplus */

#endif /* __Agent_FWD_DEFINED__ */

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef __ThunderAgentLib_LIBRARY_DEFINED__
#define __ThunderAgentLib_LIBRARY_DEFINED__

    /* library ThunderAgentLib */
    /* [custom][custom][custom][helpstring][version][uuid] */

    typedef /* [public][public] */
        enum __MIDL___MIDL_itf_ThunderAgent6472E102E352E366_0001_0004_0001
    {
        ECT_Undefine = 0xffffffff,
        ECT_Agent5 = 1
    } _tag_Enum_CallType;

#ifndef __IAgent_INTERFACE_DEFINED__
#define __IAgent_INTERFACE_DEFINED__

    /* interface IAgent */
    /* [object][oleautomation][nonextensible][dual][helpstring][uuid] */

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("1622F56A-0C55-464C-B472-377845DEF21D")
    IAgent : public IDispatch
    {
      public:
        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE GetInfo(
            /* [in] */ BSTR bstrInfoName,
            /* [retval][out] */ BSTR * pbstrResult) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE AddTask(
            /* [in] */ BSTR bstrUrl,
            /* [defaultvalue][optional][in] */ BSTR bstrFileName = (BSTR) L"",
            /* [defaultvalue][optional][in] */ BSTR bstrPath = (BSTR) L"",
            /* [defaultvalue][optional][in] */ BSTR bstrComments = (BSTR) L"",
            /* [defaultvalue][optional][in] */ BSTR bstrReferUrl = (BSTR) L"",
            /* [defaultvalue][optional][in] */ int nStartMode = -1,
            /* [defaultvalue][optional][in] */ int nOnlyFromOrigin = 0,
            /* [defaultvalue][optional][in] */ int nOriginThreadCount = -1) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE CommitTasks(
            /* [retval][out] */ int *pResult) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE CancelTasks(void) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE GetTaskInfo(
            /* [in] */ BSTR bstrUrl,
            /* [in] */ BSTR bstrInfoName,
            /* [retval][out] */ BSTR * pbstrResult) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE GetInfoStruct(
            /* [in] */ int pInfo) = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE GetTaskInfoStruct(
            /* [in] */ int pTaskInfo) = 0;
    };

#else /* C style interface */

    typedef struct IAgentVtbl
    {
        BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)
        (IAgent *This,
         /* [in] */ REFIID riid,
         /* [annotation][iid_is][out] */
         _COM_Outptr_ void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(IAgent *This);

        ULONG(STDMETHODCALLTYPE *Release)(IAgent *This);

        HRESULT(STDMETHODCALLTYPE *GetTypeInfoCount)
        (IAgent *This,
         /* [out] */ UINT *pctinfo);

        HRESULT(STDMETHODCALLTYPE *GetTypeInfo)
        (IAgent *This,
         /* [in] */ UINT iTInfo,
         /* [in] */ LCID lcid,
         /* [out] */ ITypeInfo **ppTInfo);

        HRESULT(STDMETHODCALLTYPE *GetIDsOfNames)
        (IAgent *This,
         /* [in] */ REFIID riid,
         /* [size_is][in] */ LPOLESTR *rgszNames,
         /* [range][in] */ UINT cNames,
         /* [in] */ LCID lcid,
         /* [size_is][out] */ DISPID *rgDispId);

        /* [local] */ HRESULT(STDMETHODCALLTYPE *Invoke)(IAgent *This,
                                                         /* [annotation][in] */
                                                         _In_ DISPID dispIdMember,
                                                         /* [annotation][in] */
                                                         _In_ REFIID riid,
                                                         /* [annotation][in] */
                                                         _In_ LCID lcid,
                                                         /* [annotation][in] */
                                                         _In_ WORD wFlags,
                                                         /* [annotation][out][in] */
                                                         _In_ DISPPARAMS *pDispParams,
                                                         /* [annotation][out] */
                                                         _Out_opt_ VARIANT *pVarResult,
                                                         /* [annotation][out] */
                                                         _Out_opt_ EXCEPINFO *pExcepInfo,
                                                         /* [annotation][out] */
                                                         _Out_opt_ UINT *puArgErr);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetInfo)(IAgent *This,
                                                                   /* [in] */ BSTR bstrInfoName,
                                                                   /* [retval][out] */ BSTR *pbstrResult);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *AddTask)(IAgent *This,
                                                                   /* [in] */ BSTR bstrUrl,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrFileName,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrPath,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrComments,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrReferUrl,
                                                                   /* [defaultvalue][optional][in] */ int nStartMode,
                                                                   /* [defaultvalue][optional][in] */ int nOnlyFromOrigin,
                                                                   /* [defaultvalue][optional][in] */ int nOriginThreadCount);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *CommitTasks)(IAgent *This,
                                                                       /* [retval][out] */ int *pResult);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *CancelTasks)(IAgent *This);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetTaskInfo)(IAgent *This,
                                                                       /* [in] */ BSTR bstrUrl,
                                                                       /* [in] */ BSTR bstrInfoName,
                                                                       /* [retval][out] */ BSTR *pbstrResult);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetInfoStruct)(IAgent *This,
                                                                         /* [in] */ int pInfo);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetTaskInfoStruct)(IAgent *This,
                                                                             /* [in] */ int pTaskInfo);

        END_INTERFACE
    } IAgentVtbl;

    interface IAgent { CONST_VTBL struct IAgentVtbl *lpVtbl; };

#ifdef COBJMACROS

#define IAgent_QueryInterface(This, riid, ppvObject) ((This)->lpVtbl->QueryInterface(This, riid, ppvObject))

#define IAgent_AddRef(This) ((This)->lpVtbl->AddRef(This))

#define IAgent_Release(This) ((This)->lpVtbl->Release(This))

#define IAgent_GetTypeInfoCount(This, pctinfo) ((This)->lpVtbl->GetTypeInfoCount(This, pctinfo))

#define IAgent_GetTypeInfo(This, iTInfo, lcid, ppTInfo) ((This)->lpVtbl->GetTypeInfo(This, iTInfo, lcid, ppTInfo))

#define IAgent_GetIDsOfNames(This, riid, rgszNames, cNames, lcid, rgDispId) \
    ((This)->lpVtbl->GetIDsOfNames(This, riid, rgszNames, cNames, lcid, rgDispId))

#define IAgent_Invoke(This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr) \
    ((This)->lpVtbl->Invoke(This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr))

#define IAgent_GetInfo(This, bstrInfoName, pbstrResult) ((This)->lpVtbl->GetInfo(This, bstrInfoName, pbstrResult))

#define IAgent_AddTask(This, bstrUrl, bstrFileName, bstrPath, bstrComments, bstrReferUrl, nStartMode, nOnlyFromOrigin, nOriginThreadCount) \
    ((This)->lpVtbl->AddTask(This, bstrUrl, bstrFileName, bstrPath, bstrComments, bstrReferUrl, nStartMode, nOnlyFromOrigin, nOriginThreadCount))

#define IAgent_CommitTasks(This, pResult) ((This)->lpVtbl->CommitTasks(This, pResult))

#define IAgent_CancelTasks(This) ((This)->lpVtbl->CancelTasks(This))

#define IAgent_GetTaskInfo(This, bstrUrl, bstrInfoName, pbstrResult) \
    ((This)->lpVtbl->GetTaskInfo(This, bstrUrl, bstrInfoName, pbstrResult))

#define IAgent_GetInfoStruct(This, pInfo) ((This)->lpVtbl->GetInfoStruct(This, pInfo))

#define IAgent_GetTaskInfoStruct(This, pTaskInfo) ((This)->lpVtbl->GetTaskInfoStruct(This, pTaskInfo))

#endif /* COBJMACROS */

#endif /* C style interface */

#endif /* __IAgent_INTERFACE_DEFINED__ */

#ifndef __IAgent2_INTERFACE_DEFINED__
#define __IAgent2_INTERFACE_DEFINED__

    /* interface IAgent2 */
    /* [object][oleautomation][dual][helpstring][uuid] */

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("1ADEFB0D-0FFA-4470-8AB0-B921080F0642")
    IAgent2 : public IAgent
    {
      public:
        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE AddTask2(
            /* [in] */ BSTR bstrUrl,
            /* [defaultvalue][optional][in] */ BSTR bstrFileName = (BSTR) L"",
            /* [defaultvalue][optional][in] */ BSTR bstrPath = (BSTR) L"",
            /* [defaultvalue][optional][in] */ BSTR bstrComments = (BSTR) L"",
            /* [defaultvalue][optional][in] */ BSTR bstrReferUrl = (BSTR) L"",
            /* [defaultvalue][optional][in] */ int nStartMode = -1,
            /* [defaultvalue][optional][in] */ int nOnlyFromOrigin = 0,
            /* [defaultvalue][optional][in] */ int nOriginThreadCount = -1,
            /* [defaultvalue][optional][in] */ BSTR bstrCookie = (BSTR) L"") = 0;

        virtual /* [helpstring][id] */ HRESULT STDMETHODCALLTYPE CommitTasks2(
            /* [in] */ int nIsAsync,
            /* [retval][out] */ int *pResult) = 0;
    };

#else /* C style interface */

    typedef struct IAgent2Vtbl
    {
        BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE *QueryInterface)
        (IAgent2 *This,
         /* [in] */ REFIID riid,
         /* [annotation][iid_is][out] */
         _COM_Outptr_ void **ppvObject);

        ULONG(STDMETHODCALLTYPE *AddRef)(IAgent2 *This);

        ULONG(STDMETHODCALLTYPE *Release)(IAgent2 *This);

        HRESULT(STDMETHODCALLTYPE *GetTypeInfoCount)
        (IAgent2 *This,
         /* [out] */ UINT *pctinfo);

        HRESULT(STDMETHODCALLTYPE *GetTypeInfo)
        (IAgent2 *This,
         /* [in] */ UINT iTInfo,
         /* [in] */ LCID lcid,
         /* [out] */ ITypeInfo **ppTInfo);

        HRESULT(STDMETHODCALLTYPE *GetIDsOfNames)
        (IAgent2 *This,
         /* [in] */ REFIID riid,
         /* [size_is][in] */ LPOLESTR *rgszNames,
         /* [range][in] */ UINT cNames,
         /* [in] */ LCID lcid,
         /* [size_is][out] */ DISPID *rgDispId);

        /* [local] */ HRESULT(STDMETHODCALLTYPE *Invoke)(IAgent2 *This,
                                                         /* [annotation][in] */
                                                         _In_ DISPID dispIdMember,
                                                         /* [annotation][in] */
                                                         _In_ REFIID riid,
                                                         /* [annotation][in] */
                                                         _In_ LCID lcid,
                                                         /* [annotation][in] */
                                                         _In_ WORD wFlags,
                                                         /* [annotation][out][in] */
                                                         _In_ DISPPARAMS *pDispParams,
                                                         /* [annotation][out] */
                                                         _Out_opt_ VARIANT *pVarResult,
                                                         /* [annotation][out] */
                                                         _Out_opt_ EXCEPINFO *pExcepInfo,
                                                         /* [annotation][out] */
                                                         _Out_opt_ UINT *puArgErr);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetInfo)(IAgent2 *This,
                                                                   /* [in] */ BSTR bstrInfoName,
                                                                   /* [retval][out] */ BSTR *pbstrResult);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *AddTask)(IAgent2 *This,
                                                                   /* [in] */ BSTR bstrUrl,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrFileName,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrPath,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrComments,
                                                                   /* [defaultvalue][optional][in] */ BSTR bstrReferUrl,
                                                                   /* [defaultvalue][optional][in] */ int nStartMode,
                                                                   /* [defaultvalue][optional][in] */ int nOnlyFromOrigin,
                                                                   /* [defaultvalue][optional][in] */ int nOriginThreadCount);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *CommitTasks)(IAgent2 *This,
                                                                       /* [retval][out] */ int *pResult);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *CancelTasks)(IAgent2 *This);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetTaskInfo)(IAgent2 *This,
                                                                       /* [in] */ BSTR bstrUrl,
                                                                       /* [in] */ BSTR bstrInfoName,
                                                                       /* [retval][out] */ BSTR *pbstrResult);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetInfoStruct)(IAgent2 *This,
                                                                         /* [in] */ int pInfo);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *GetTaskInfoStruct)(IAgent2 *This,
                                                                             /* [in] */ int pTaskInfo);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *AddTask2)(IAgent2 *This,
                                                                    /* [in] */ BSTR bstrUrl,
                                                                    /* [defaultvalue][optional][in] */ BSTR bstrFileName,
                                                                    /* [defaultvalue][optional][in] */ BSTR bstrPath,
                                                                    /* [defaultvalue][optional][in] */ BSTR bstrComments,
                                                                    /* [defaultvalue][optional][in] */ BSTR bstrReferUrl,
                                                                    /* [defaultvalue][optional][in] */ int nStartMode,
                                                                    /* [defaultvalue][optional][in] */ int nOnlyFromOrigin,
                                                                    /* [defaultvalue][optional][in] */ int nOriginThreadCount,
                                                                    /* [defaultvalue][optional][in] */ BSTR bstrCookie);

        /* [helpstring][id] */ HRESULT(STDMETHODCALLTYPE *CommitTasks2)(IAgent2 *This,
                                                                        /* [in] */ int nIsAsync,
                                                                        /* [retval][out] */ int *pResult);

        END_INTERFACE
    } IAgent2Vtbl;

    interface IAgent2 { CONST_VTBL struct IAgent2Vtbl *lpVtbl; };

#ifdef COBJMACROS

#define IAgent2_QueryInterface(This, riid, ppvObject) ((This)->lpVtbl->QueryInterface(This, riid, ppvObject))

#define IAgent2_AddRef(This) ((This)->lpVtbl->AddRef(This))

#define IAgent2_Release(This) ((This)->lpVtbl->Release(This))

#define IAgent2_GetTypeInfoCount(This, pctinfo) ((This)->lpVtbl->GetTypeInfoCount(This, pctinfo))

#define IAgent2_GetTypeInfo(This, iTInfo, lcid, ppTInfo) ((This)->lpVtbl->GetTypeInfo(This, iTInfo, lcid, ppTInfo))

#define IAgent2_GetIDsOfNames(This, riid, rgszNames, cNames, lcid, rgDispId) \
    ((This)->lpVtbl->GetIDsOfNames(This, riid, rgszNames, cNames, lcid, rgDispId))

#define IAgent2_Invoke(This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr) \
    ((This)->lpVtbl->Invoke(This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr))

#define IAgent2_GetInfo(This, bstrInfoName, pbstrResult) ((This)->lpVtbl->GetInfo(This, bstrInfoName, pbstrResult))

#define IAgent2_AddTask(This, bstrUrl, bstrFileName, bstrPath, bstrComments, bstrReferUrl, nStartMode, nOnlyFromOrigin, nOriginThreadCount) \
    ((This)->lpVtbl->AddTask(This, bstrUrl, bstrFileName, bstrPath, bstrComments, bstrReferUrl, nStartMode, nOnlyFromOrigin, nOriginThreadCount))

#define IAgent2_CommitTasks(This, pResult) ((This)->lpVtbl->CommitTasks(This, pResult))

#define IAgent2_CancelTasks(This) ((This)->lpVtbl->CancelTasks(This))

#define IAgent2_GetTaskInfo(This, bstrUrl, bstrInfoName, pbstrResult) \
    ((This)->lpVtbl->GetTaskInfo(This, bstrUrl, bstrInfoName, pbstrResult))

#define IAgent2_GetInfoStruct(This, pInfo) ((This)->lpVtbl->GetInfoStruct(This, pInfo))

#define IAgent2_GetTaskInfoStruct(This, pTaskInfo) ((This)->lpVtbl->GetTaskInfoStruct(This, pTaskInfo))

#define IAgent2_AddTask2(This, bstrUrl, bstrFileName, bstrPath, bstrComments, bstrReferUrl, nStartMode, nOnlyFromOrigin, nOriginThreadCount, bstrCookie) \
    ((This)->lpVtbl->AddTask2(This, bstrUrl, bstrFileName, bstrPath, bstrComments, bstrReferUrl, nStartMode, nOnlyFromOrigin, nOriginThreadCount, bstrCookie))

#define IAgent2_CommitTasks2(This, nIsAsync, pResult) ((This)->lpVtbl->CommitTasks2(This, nIsAsync, pResult))

#endif /* COBJMACROS */

#endif /* C style interface */

#endif /* __IAgent2_INTERFACE_DEFINED__ */

    EXTERN_C const CLSID CLSID_Agent;

#ifdef __cplusplus

#if defined(_M_IX86) || (defined __i386__)
    class DECLSPEC_UUID("485463B7-8FB2-4B3B-B29B-8B919B0EACCE") Agent;
#else
    class DECLSPEC_UUID("002AE4F2-96AB-4DFA-AE2E-605217F8A84C") Agent;
#endif

#endif /* __ThunderAgentLib_LIBRARY_DEFINED__ */

    /* Additional Prototypes for ALL interfaces */

    /* end of Additional Prototypes */

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type, name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

    typedef struct _IID
    {
        unsigned long x;
        unsigned short s1;
        unsigned short s2;
        unsigned char c[8];
    } IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
    typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type, name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    __declspec(selectany) const type name = { l, w1, w2, { b1, b2, b3, b4, b5, b6, b7, b8 } }

#endif // !_MIDL_USE_GUIDDEF_

#if defined(_M_IX86) || (defined __i386__)
    MIDL_DEFINE_GUID(IID, LIBID_ThunderAgentLib, 0x26D657AE, 0xA466, 0x4F44, 0xAB, 0x1D, 0x5C, 0xFF, 0xFA, 0xDB, 0xED, 0x97);
#else
    MIDL_DEFINE_GUID(IID, LIBID_ThunderAgentLib, 0x01560F06, 0xCEE2, 0x46FF, 0x89, 0x97, 0x30, 0x8A, 0x36, 0x61, 0x75, 0xE9);
#endif

    MIDL_DEFINE_GUID(IID, IID_IAgent, 0x1622F56A, 0x0C55, 0x464C, 0xB4, 0x72, 0x37, 0x78, 0x45, 0xDE, 0xF2, 0x1D);

    MIDL_DEFINE_GUID(IID, IID_IAgent2, 0x1ADEFB0D, 0x0FFA, 0x4470, 0x8A, 0xB0, 0xB9, 0x21, 0x08, 0x0F, 0x06, 0x42);

#if defined(_M_IX86) || (defined __i386__)
    MIDL_DEFINE_GUID(CLSID, CLSID_Agent, 0x485463B7, 0x8FB2, 0x4B3B, 0xB2, 0x9B, 0x8B, 0x91, 0x9B, 0x0E, 0xAC, 0xCE);
#else
    MIDL_DEFINE_GUID(CLSID, CLSID_Agent, 0x002AE4F2, 0x96AB, 0x4DFA, 0xAE, 0x2E, 0x60, 0x52, 0x17, 0xF8, 0xA8, 0x4C);
#endif
#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif

#endif /* __ThunderAgentLib_LIBRARY_DEFINED__ */
/* printf macro */
#include "spinlock.h"

static BSTR
str_bstr(LPCSTR str)
{
    BSTR bstr = NULL;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (!wlen)
    {
        return NULL;
    }
    bstr = SysAllocStringLen(0, wlen);
    if (!MultiByteToWideChar(CP_UTF8, 0, str, -1, bstr, wlen))
    {
        SysFreeString(bstr);
        return NULL;
    }
    return bstr;
}

int
thunder_lookup()
{
    IAgent2 *pAgent = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_Agent, NULL, CLSCTX_INPROC_SERVER, &IID_IAgent2, (void **) &pAgent);
    if (FAILED(hr))
    {
        return 0;
    }
    if (pAgent)
    {
        IAgent2_Release(pAgent);
    }
    return 1;
}

int
thunder_download(LPCSTR b_url, LPCSTR b_refer, LPCSTR b_cookies)
{
    HRESULT hr = 1;
    IAgent2 *pAgent = NULL;
    BSTR url = NULL, refer = NULL, cookies = NULL;
    if (NULL == b_url || *b_url == '\0')
    {
        return 0;
    }
    do
    {
        int ret = 0;
        hr = CoCreateInstance(&CLSID_Agent, NULL, CLSCTX_INPROC_SERVER, &IID_IAgent2, (void **) &pAgent);
        if (FAILED(hr) || pAgent == NULL)
        {
            printf("CoCreateInstance error, err=%lu\n", GetLastError());
            break;
        }
        url = str_bstr(b_url);
        refer = str_bstr(b_refer);
        cookies = str_bstr(b_cookies);
        if (!(url && refer && cookies))
        {
            printf("str_bstr return null\n");
            break;
        }
        hr = IAgent2_AddTask2(pAgent, url, NULL, NULL, NULL, refer, 1, 0, -1, cookies);
        if (FAILED(hr))
        {
            printf("IAgent2_AddTask2 error, cause: %lu\n", GetLastError());
            break;
        }
        hr = IAgent2_CommitTasks2(pAgent, 1, &ret);
        if (FAILED(hr))
        {
            printf("IAgent2_CommitTasks2 error, cause: %lu\n", GetLastError());
        }
        printf("ret = %d\n", ret);
    } while(0);
    if (url)
    {
        SysFreeString(url);
    }
    if (refer)
    {
        SysFreeString(refer);
    }
    if (cookies)
    {
        SysFreeString(cookies);
    }
    if (pAgent)
    {
        IAgent2_Release(pAgent);
    }
    return SUCCEEDED(hr);
}
