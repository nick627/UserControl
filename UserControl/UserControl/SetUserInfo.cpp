#include "stdafx.h"
#include "LoadDll.h"
#include "ExternSymbols.h"
#include "GetUserInfo.h"
#include "SetUserInfo.h"

struct PrivilegeConststruct
{
    LPWSTR PrivilegeStr;
    LPWSTR DescriptionStr;
};

PrivilegeConststruct _privileges__lpwstr_array[] =
{
    {   (LPWSTR)L"SeAssignPrimaryTokenPrivilege",
        (LPWSTR)L"Required to assign the primary token of a process. User Right : Replace a process - level token."},

    {   (LPWSTR)L"SeAuditPrivilege",
        (LPWSTR)L"Required to generate audit - log entries.Give this privilege to secure servers. User Right : Generate security audits."},

    {   (LPWSTR)L"SeBackupPrivilege",
        (LPWSTR)L"User Right : Back up files and directories."},

    {   (LPWSTR)L"SeChangeNotifyPrivilege",
        (LPWSTR)L"User Right : Bypass traverse checking."},

    {   (LPWSTR)L"SeCreateGlobalPrivilege",
        (LPWSTR)L"User Right : Create global objects."},

    {   (LPWSTR)L"SeCreatePagefilePrivilege",
        (LPWSTR)L"Required to create a paging file. User Right : Create a pagefile."},

    {   (LPWSTR)L"SeCreatePermanentPrivilege",
        (LPWSTR)L"Required to create a permanent object. User Right : Create permanent shared objects."},

    {   (LPWSTR)L"SeCreateSymbolicLinkPrivilege",
        (LPWSTR)L"Required to create a symbolic link. User Right : Create symbolic links."},

    {   (LPWSTR)L"SeCreateTokenPrivilege",
        (LPWSTR)L"Required to create a primary token. User Right : Create a token object."},

    {   (LPWSTR)L"SeDebugPrivilege",
        (LPWSTR)L"Required to debug and adjust the memory of a process owned by another account. User Right : Debug programs." },

    {   (LPWSTR)L"SeEnableDelegationPrivilege",
        (LPWSTR)L"Required to mark user and computer accounts as trusted for delegation. User Right : Enable computer and user accounts to be trusted for delegation." },

    {   (LPWSTR)L"SeImpersonatePrivilege",
        (LPWSTR)L"Required to impersonate. User Right : Impersonate a client after authentication." },

    {   (LPWSTR)L"SeIncreaseBasePriorityPrivilege",
        (LPWSTR)L"Required to increase the base priority of a process. User Right : Increase scheduling priority." },

    {   (LPWSTR)L"SeIncreaseQuotaPrivilege",
        (LPWSTR)L"Required to increase the quota assigned to a process. User Right : Adjust memory quotas for a process." },

    {   (LPWSTR)L"SeIncreaseWorkingSetPrivilege",
        (LPWSTR)L"Required to allocate more memory for applications that run in the context of users. User Right : Increase a process working set." },

    {   (LPWSTR)L"SeLoadDriverPrivilege",
        (LPWSTR)L"Required to load or unload a device driver. User Right : Load and unload device drivers." },

    {   (LPWSTR)L"SeLockMemoryPrivilege",
        (LPWSTR)L"Required to lock physical pages in memory. User Right : Lock pages in memory." },

    {   (LPWSTR)L"SeMachineAccountPrivilege",
        (LPWSTR)L"Required to create a computer account. User Right : Add workstations to domain." },

    {   (LPWSTR)L"SeManageVolumePrivilege",
        (LPWSTR)L"Required to enable volume management privileges. User Right : Manage the files on a volume." },

    {   (LPWSTR)L"SeProfileSingleProcessPrivilege",
        (LPWSTR)L"Required to gather profiling information for a single process. User Right : Profile single process." },

    {   (LPWSTR)L"SeRelabelPrivilege",
        (LPWSTR)L"Required to modify the mandatory integrity level of an object. User Right : Modify an object label." },

    {   (LPWSTR)L"SeRemoteShutdownPrivilege",
        (LPWSTR)L"Required to shut down a system using a network request. User Right : Force shutdown from a remote system." },

    {   (LPWSTR)L"SeRestorePrivilege",
        (LPWSTR)L"User Right : Restore files and directories." },

    {   (LPWSTR)L"SeSecurityPrivilege",
        (LPWSTR)L"User Right : Manage auditing and security log." },

    {   (LPWSTR)L"SeShutdownPrivilege",
        (LPWSTR)L"Required to shut down a local system. User Right : Shut down the system." },

    {   (LPWSTR)L"SeSyncAgentPrivilege",
        (LPWSTR)L"User Right : Synchronize directory service data." },

    {   (LPWSTR)L"SeSystemEnvironmentPrivilege",
        (LPWSTR)L"Required to modify the nonvolatile RAM of systems that use this type of memory to store configuration information. User Right : Modify firmware environment values." },

    {   (LPWSTR)L"SeSystemProfilePrivilege",
        (LPWSTR)L"Required to gather profiling information for the entire system. User Right : Profile system performance." },

    {   (LPWSTR)L"SeSystemtimePrivilege",
        (LPWSTR)L"Required to modify the system time. User Right : Change the system time." },

    {   (LPWSTR)L"SeTakeOwnershipPrivilege",
        (LPWSTR)L"User Right : Take ownership of files or other objects." },

    {   (LPWSTR)L"SeTcbPrivilege",
        (LPWSTR)L"User Right : Act as part of the operating system." },

    {   (LPWSTR)L"SeTimeZonePrivilege",
        (LPWSTR)L"Required to adjust the time zone associated with the computer's internal clock. User Right : Change the time zone." },

    {   (LPWSTR)L"SeTrustedCredManAccessPrivilege",
        (LPWSTR)L"Required to access Credential Manager as a trusted caller. User Right : Access Credential Manager as a trusted caller." },

    {   (LPWSTR)L"SeUndockPrivilege",
        (LPWSTR)L"Required to undock a laptop. User Right : Remove computer from docking station." },

    {   (LPWSTR)L"SeUnsolicitedInputPrivilege",
        (LPWSTR)L"Required to read unsolicited input from a terminal device. User Right : Not applicable." }

};

void list_Privileges(void)
{
    for (size_t i = 0; i < sizeof(_privileges__lpwstr_array)/ sizeof(PrivilegeConststruct); i++)
    {
        wprintf(L"%d: %s\n%s\n", i, _privileges__lpwstr_array[i].PrivilegeStr, _privileges__lpwstr_array[i].DescriptionStr);
    }
}

int Add_User(LPWSTR lpszUser, LPWSTR lpszPassword)
{
    USER_INFO_1               user_info;
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;

    // Set up the USER_INFO_1 structure. 

    user_info.usri1_name = lpszUser;
    user_info.usri1_password = lpszPassword;
    user_info.usri1_priv = USER_PRIV_USER;
    user_info.usri1_home_dir = (LPWSTR)TEXT("");
    user_info.usri1_comment = (LPWSTR)TEXT("Sample User");
    user_info.usri1_flags = UF_SCRIPT;
    user_info.usri1_script_path = (LPWSTR)TEXT("");

    nStatus = NetUserAddPtr(NULL,        // PDC name 
        1,                    // level 
        (LPBYTE)&user_info,  // input buffer 
        &parm_err);          // parameter in error 

    switch (nStatus)
    {
    case 0:
        printf("User successfully created.\n");
        break;
    case NERR_UserExists:
        printf("User already exists.\n");
        nStatus = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        printf("Invalid parameter error adding user; parameter index = %d\n", parm_err);
        return(nStatus);
    default:
        printf("Error adding user: %d\n", nStatus);
        return(nStatus);
    }

    return(nStatus);
}

int Delete_User(LPWSTR lpszUser)
{
    return NetUserDelPtr(NULL, lpszUser);
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivilegesPtr(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

bool InitLsaString(
    PLSA_UNICODE_STRING pLsaString,
    LPCWSTR pwszString
)
{
    DWORD dwLen = 0;

    if (NULL == pLsaString)
        return FALSE;

    if (NULL != pwszString)
    {
        dwLen = wcslen(pwszString);
        if (dwLen > 0x7ffe)   // String is too large
            return FALSE;
    }

    // Store the string.
    pLsaString->Buffer = (WCHAR *)pwszString;
    pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

    return TRUE;
}

int Set_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;
    NET_API_STATUS            nStatus = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    if (!LookupAccountNamePtr(NULL, (LPWSTR)lpszUser, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"can't LookupAccountName\n");
        return 0;
    }

    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"err\n");
        return 0;
    }

    LSA_UNICODE_STRING UserRights;
    InitLsaString(&UserRights, _privileges__lpwstr_array[_privilege_index].PrivilegeStr);
    nStatus= LsaAddAccountRightsPtr(policy_handle, userSID, &UserRights, 1);
    DWORD err = LsaNtStatusToWinErrorPtr(nStatus);
    return 0;
}

int Clear_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;
    NET_API_STATUS            nStatus = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    if (!LookupAccountNamePtr(NULL, (LPWSTR)lpszUser, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"can't LookupAccountName\n");
        return 0;
    }

    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"err\n");
        return 0;
    }
   
    LSA_UNICODE_STRING UserRights;
    InitLsaString(&UserRights, _privileges__lpwstr_array[_privilege_index].PrivilegeStr);
    LsaRemoveAccountRightsPtr(policy_handle, userSID, FALSE, &UserRights, 1);
    DWORD err = LsaNtStatusToWinErrorPtr(nStatus);
    return 0;
}

int Clear_All_User_Privileges(LPWSTR lpszUser)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    if (!LookupAccountNamePtr(NULL, (LPWSTR)lpszUser, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"can't LookupAccountName\n");
        return 0;
    }

    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"err\n");
        return 0;
    }

    LsaRemoveAccountRightsPtr(policy_handle, userSID, TRUE, NULL, 0);

    return 0;
}

int Assign_User_To_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup)
{
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;

    localgroup_members.lgrmi3_domainandname = lpszUser;

    nStatus = NetLocalGroupAddMembersPtr(NULL,        // PDC name 
        lpszLocalGroup,               // group name 
        3,                            // name 
        (LPBYTE)&localgroup_members, // buffer 
        1);                          // count

    switch (nStatus)
    {
    case 0:
        printf("User successfully added to local group.\n");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        printf("User already in local group.\n");
        nStatus = 0;
        break;
    default:
        printf("Error adding user to local group: %d\n", nStatus);
        break;
    }
    return(nStatus);
}

int Exclude_User_From_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup)
{
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;

    localgroup_members.lgrmi3_domainandname = lpszUser;

    nStatus = NetLocalGroupDelMembersPtr(NULL,        // PDC name 
        lpszLocalGroup,               // group name 
        3,                            // name 
        (LPBYTE)&localgroup_members, // buffer 
        1);                          // count

    switch (nStatus)
    {
    case 0:
        printf("User successfully removed from local group.\n");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        printf("No such user in local group.\n");
        nStatus = 0;
        break;
    default:
        printf("Error removing user from local group: %d\n", nStatus);
        break;
    }
    return(nStatus);
}
                                                                   
int Add_Group(LPWSTR lpszLocalGroup)
{
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;
    LOCALGROUP_INFO_1         localgroup_info;
    // Set up the LOCALGROUP_INFO_1 structure. 

    localgroup_info.lgrpi1_name = lpszLocalGroup;
    localgroup_info.lgrpi1_comment = (LPWSTR)TEXT("Sample local group.");

    nStatus = NetLocalGroupAddPtr(NULL, 1, (LPBYTE)&localgroup_info, &parm_err);

    switch (nStatus)
    {
    case 0:
        printf("Local group successfully created.\n");
        break;
    case ERROR_ALIAS_EXISTS:
        printf("Local group already exists.\n");
        nStatus = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        printf("Invalid parameter error adding local group; parameter index = %d\n", nStatus, parm_err);
        return(nStatus);
    default:
        printf("Error adding local group: %d\n", nStatus);
        return(nStatus);
    }
    return(nStatus);
}

int Delete_Group(LPWSTR lpszLocalGroup)
{
    return NetLocalGroupDelPtr(NULL, lpszLocalGroup);
}

