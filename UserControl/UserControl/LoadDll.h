#pragma once

#include "stdafx.h"

typedef NET_API_STATUS(_stdcall *_NetUserEnumT)(
    _In_    LPCWSTR servername,
    _In_    DWORD   level,
    _In_    DWORD   filter,
    _Out_   LPBYTE  *bufptr,
    _In_    DWORD   prefmaxlen,
    _Out_   LPDWORD entriesread,
    _Out_   LPDWORD totalentries,
    _Inout_ LPDWORD resume_handle
    );

typedef NET_API_STATUS(_stdcall *_NetApiBufferFreeT)(
    _In_ LPVOID Buffer
    );

typedef NET_API_STATUS(_stdcall *_NetUserGetLocalGroupsT)(
    _In_  LPCWSTR servername,
    _In_  LPCWSTR username,
    _In_  DWORD   level,
    _In_  DWORD   flags,
    _Out_ LPBYTE  *bufptr,
    _In_  DWORD   prefmaxlen,
    _Out_ LPDWORD entriesread,
    _Out_ LPDWORD totalentries
    );

typedef NET_API_STATUS(_stdcall *_NetUserGetGroupsT)(
    _In_  LPCWSTR servername,
    _In_  LPCWSTR username,
    _In_  DWORD   level,
    _Out_ LPBYTE  *bufptr,
    _In_  DWORD   prefmaxlen,
    _Out_ LPDWORD entriesread,
    _Out_ LPDWORD totalentries
    );

typedef NET_API_STATUS(_stdcall *_NetUserAddT)(
    _In_  LMSTR   servername,
    _In_  DWORD   level,
    _In_  LPBYTE  buf,
    _Out_ LPDWORD parm_err
    );

typedef NET_API_STATUS(_stdcall *_NetUserDelT)(
    _In_ LPCWSTR servername,
    _In_ LPCWSTR username
    );

typedef NET_API_STATUS(_stdcall *_NetLocalGroupAddMembersT)(
    _In_ LPCWSTR servername,
    _In_ LPCWSTR groupname,
    _In_ DWORD   level,
    _In_ LPBYTE  buf,
    _In_ DWORD   totalentries
);

typedef NET_API_STATUS(_stdcall *_NetLocalGroupDelMembersT)(
    _In_ LPCWSTR servername,
    _In_ LPCWSTR groupname,
    _In_ DWORD   level,
    _In_ LPBYTE  buf,
    _In_ DWORD   totalentries
);

typedef NET_API_STATUS(_stdcall *_NetLocalGroupAddT)(
    _In_  LPCWSTR servername,
    _In_  DWORD   level,
    _In_  LPBYTE  buf,
    _Out_ LPDWORD parm_err
);

typedef NET_API_STATUS(_stdcall *_NetLocalGroupDelT)(
    _In_ LPCWSTR servername,
    _In_ LPCWSTR groupname
);

//--------------------------------------------------------------------------------

typedef BOOL(WINAPI *_ConvertSidToStringSidT)(
    _In_  PSID   Sid,
    _Out_ LPTSTR *StringSid
    );

typedef BOOL(WINAPI *_LookupAccountNameT)(
    _In_opt_  LPCTSTR       lpSystemName,
    _In_      LPCTSTR       lpAccountName,
    _Out_opt_ PSID          Sid,
    _Inout_   LPDWORD       cbSid,
    _Out_opt_ LPTSTR        ReferencedDomainName,
    _Inout_   LPDWORD       cchReferencedDomainName,
    _Out_     PSID_NAME_USE peUse
    );

typedef BOOL(WINAPI *_AdjustTokenPrivilegesT)(
    _In_      HANDLE            TokenHandle,
    _In_      BOOL              DisableAllPrivileges,
    _In_opt_  PTOKEN_PRIVILEGES NewState,
    _In_      DWORD             BufferLength,
    _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PDWORD            ReturnLength
);

typedef NTSTATUS(_stdcall *_LsaAddAccountRightsT)(
    _In_ LSA_HANDLE          PolicyHandle,
    _In_ PSID                AccountSid,
    _In_ PLSA_UNICODE_STRING UserRights,
    _In_ ULONG               CountOfRights
);

typedef NTSTATUS(_stdcall *_LsaRemoveAccountRightsT)(
    _In_ LSA_HANDLE          PolicyHandle,
    _In_ PSID                AccountSid,
    _In_ BOOLEAN             AllRights,
    _In_ PLSA_UNICODE_STRING UserRights,
    _In_ ULONG               CountOfRights
);

typedef ULONG(_stdcall *_LsaNtStatusToWinErrorT)(
    _In_ NTSTATUS Status
);

typedef NTSTATUS(_stdcall *_LsaOpenPolicyT)(
    _In_    PLSA_UNICODE_STRING    SystemName,
    _In_    PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
    _In_    ACCESS_MASK            DesiredAccess,
    _Inout_ PLSA_HANDLE            PolicyHandle
);

typedef NTSTATUS(_stdcall *_LsaEnumerateAccountRightsT)(
    _In_  LSA_HANDLE          PolicyHandle,
    _In_  PSID                AccountSid,
    _Out_ PLSA_UNICODE_STRING *UserRights,
    _Out_ PULONG              CountOfRights
);


//--------------------------------------------------------------------------------

void Load_Dll(void);
void Unload_Dll(void);