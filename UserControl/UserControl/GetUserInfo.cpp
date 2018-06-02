
#include "stdafx.h"
#include "LoadDll.h"
#include "ExternSymbols.h"
#include "GetUserInfo.h"

LSA_HANDLE GetPolicyHandle()
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    // Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    // Get a handle to the Policy object.
    ntsResult = LsaOpenPolicyPtr(
        NULL,    //Name of the target system.
        &ObjectAttributes, //Object attributes.
        POLICY_ALL_ACCESS | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, //Desired access permissions.
        &lsahPolicyHandle  //Receives the policy handle.
    );

    if (ntsResult != STATUS_SUCCESS)
    {
        // An error occurred. Display it as a win32 error code.
        wprintf(L"OpenPolicy returned %lu\n", LsaNtStatusToWinErrorPtr(ntsResult));
        return NULL;
    }
    return lsahPolicyHandle;
}

void Enumerate_Privileges(LPTSTR _user_name)
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

    if (!LookupAccountNamePtr(NULL, (LPWSTR)_user_name, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"can't LookupAccountName\n");
        return;
    }

    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"err\n");
        return;
    }

    LsaEnumerateAccountRightsPtr(policy_handle, userSID, &pp_user_rights, &count_of_rights);
    wprintf(L"\t Privileges:\n");
    for (size_t i = 0; i < count_of_rights; i++)
    {
        wprintf(L"\t\t %s\n", pp_user_rights[i].Buffer);
    }
}

void Get_User_Sid(LPTSTR _user_name)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    if (!LookupAccountNamePtr(NULL, (LPWSTR)_user_name, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"can't LookupAccountName\n");
    }

    ConvertSidToStringSidPtr(userSID, &chSID);
    wprintf(L"\t SID:\n\t\t%s\n", chSID);
    LocalFree((HLOCAL)chSID);
}

void Enumerate_Users(LPTSTR _server_name)
{
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    NET_API_STATUS nStatus;
    LPTSTR pszServerName = _server_name;

    do // begin do
    {
        nStatus = NetUserEnumPtr((LPCWSTR)pszServerName,
            dwLevel,
            FILTER_NORMAL_ACCOUNT, // global users
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle);
        // If the call succeeds,
        //
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {
                //
                // Loop through the entries.
                //
                for (i = 0; (i < dwEntriesRead); i++)
                {
                    assert(pTmpBuf != NULL);

                    if (pTmpBuf == NULL)
                    {
                        fprintf(stderr, "An access violation has occurred\n");
                        break;
                    }
                    //
                    //  Print the name of the user account.
                    //
                    wprintf(L"\nUser name: %s\n", pTmpBuf->usri0_name);
                    Get_User_Sid(pTmpBuf->usri0_name);
                    Enumerate_Groups(pTmpBuf->usri0_name);
                    Enumerate_Privileges(pTmpBuf->usri0_name);
                    //
                    //  Print the user groups.
                    //

                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }
        // Otherwise, print the system error.
        //
        else
        {
            fprintf(stderr, "A system error has occurred: %d\n", nStatus);
        }

        if (pBuf != NULL)
        {
            NetApiBufferFreePtr(pBuf);
            pBuf = NULL;
        }
    }
    // Continue to call NetUserEnum while 
    // there are more entries. 
    // 
    while (nStatus == ERROR_MORE_DATA); // end do
                                        // Check again for allocated memory.
    if (pBuf != NULL)
    {
        NetApiBufferFreePtr(pBuf);
    }
}

void Enumerate_Groups(LPWSTR _user_name)
{
    LPBYTE buffer;
    DWORD entries;
    DWORD total_entries;
    LOCALGROUP_USERS_INFO_0 *groups;

    printf("\t local groups: \n");
    NetUserGetLocalGroupsPtr(NULL, _user_name, 0, LG_INCLUDE_INDIRECT, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    groups = (LOCALGROUP_USERS_INFO_0*)buffer;
    for (int i = 0; i < entries; i++)
    {
        printf("\t\t%S\n", groups[i].lgrui0_name);
    }
    NetApiBufferFreePtr(buffer);
    printf("\t global groups: \n");
    NetUserGetGroupsPtr(NULL, _user_name, 0, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    GROUP_USERS_INFO_0 *ggroups = (GROUP_USERS_INFO_0*)buffer;
    for (int i = 0; i < entries; i++)
    {
        printf("\t\t%S\n", ggroups[i].grui0_name);
    }
    NetApiBufferFreePtr(buffer);
}
