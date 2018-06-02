#include "stdafx.h"
#include "LoadDll.h"


HINSTANCE hNetapi32Dll = NULL;
HINSTANCE hAdvapi32Dll = NULL;

_NetUserEnumT                NetUserEnumPtr;
_NetApiBufferFreeT           NetApiBufferFreePtr;
_NetUserGetLocalGroupsT      NetUserGetLocalGroupsPtr;
_NetUserGetGroupsT           NetUserGetGroupsPtr;
_NetUserAddT                 NetUserAddPtr;
_NetUserDelT                 NetUserDelPtr;
_NetLocalGroupAddMembersT    NetLocalGroupAddMembersPtr;
_NetLocalGroupDelMembersT    NetLocalGroupDelMembersPtr;
_NetLocalGroupAddT           NetLocalGroupAddPtr;
_NetLocalGroupDelT           NetLocalGroupDelPtr;

_ConvertSidToStringSidT      ConvertSidToStringSidPtr;
_LookupAccountNameT          LookupAccountNamePtr;
_AdjustTokenPrivilegesT      AdjustTokenPrivilegesPtr;
_LsaAddAccountRightsT        LsaAddAccountRightsPtr;
_LsaRemoveAccountRightsT     LsaRemoveAccountRightsPtr;
_LsaNtStatusToWinErrorT      LsaNtStatusToWinErrorPtr;
_LsaOpenPolicyT              LsaOpenPolicyPtr;
_LsaEnumerateAccountRightsT  LsaEnumerateAccountRightsPtr;

void Load_Dll(void)
{
    hNetapi32Dll = LoadLibrary(TEXT("netapi32.dll"));                                                                           assert(hNetapi32Dll);
    NetUserEnumPtr = (_NetUserEnumT)GetProcAddress(hNetapi32Dll, "NetUserEnum");                                                assert(NetUserEnumPtr);
    NetApiBufferFreePtr = (_NetApiBufferFreeT)GetProcAddress(hNetapi32Dll, "NetApiBufferFree");                                 assert(NetApiBufferFreePtr);
    NetUserGetLocalGroupsPtr = (_NetUserGetLocalGroupsT)GetProcAddress(hNetapi32Dll, "NetUserGetLocalGroups");                  assert(NetUserGetLocalGroupsPtr);
    NetUserGetGroupsPtr = (_NetUserGetGroupsT)GetProcAddress(hNetapi32Dll, "NetUserGetGroups");                                 assert(NetUserGetGroupsPtr);
    NetUserAddPtr = (_NetUserAddT)GetProcAddress(hNetapi32Dll, "NetUserAdd");                                                   assert(NetUserAddPtr);
    NetUserDelPtr = (_NetUserDelT)GetProcAddress(hNetapi32Dll, "NetUserDel");                                                   assert(NetUserDelPtr);
    NetLocalGroupAddMembersPtr = (_NetLocalGroupAddMembersT)GetProcAddress(hNetapi32Dll, "NetLocalGroupAddMembers");            assert(NetLocalGroupAddMembersPtr);
    NetLocalGroupDelMembersPtr = (_NetLocalGroupDelMembersT)GetProcAddress(hNetapi32Dll, "NetLocalGroupDelMembers");            assert(NetLocalGroupDelMembersPtr);
    NetLocalGroupAddPtr = (_NetLocalGroupAddT)GetProcAddress(hNetapi32Dll, "NetLocalGroupAdd");                                 assert(NetLocalGroupAddPtr);
    NetLocalGroupDelPtr = (_NetLocalGroupDelT)GetProcAddress(hNetapi32Dll, "NetLocalGroupDel");                                 assert(NetLocalGroupDelPtr);

    hAdvapi32Dll = LoadLibrary(TEXT("Advapi32.dll"));                                                                           assert(hAdvapi32Dll);
    ConvertSidToStringSidPtr = (_ConvertSidToStringSidT)GetProcAddress(hAdvapi32Dll, "ConvertSidToStringSidW");                 assert(ConvertSidToStringSidPtr);
    LookupAccountNamePtr = (_LookupAccountNameT)GetProcAddress(hAdvapi32Dll, "LookupAccountNameW");                             assert(LookupAccountNamePtr);
    AdjustTokenPrivilegesPtr = (_AdjustTokenPrivilegesT)GetProcAddress(hAdvapi32Dll, "AdjustTokenPrivileges");                  assert(AdjustTokenPrivilegesPtr);
    LsaAddAccountRightsPtr = (_LsaAddAccountRightsT)GetProcAddress(hAdvapi32Dll, "LsaAddAccountRights");                        assert(LsaAddAccountRightsPtr);
    LsaRemoveAccountRightsPtr = (_LsaRemoveAccountRightsT)GetProcAddress(hAdvapi32Dll, "LsaRemoveAccountRights");               assert(LsaRemoveAccountRightsPtr);
    LsaNtStatusToWinErrorPtr = (_LsaNtStatusToWinErrorT)GetProcAddress(hAdvapi32Dll, "LsaNtStatusToWinError");                  assert(LsaNtStatusToWinErrorPtr);
    LsaOpenPolicyPtr = (_LsaOpenPolicyT)GetProcAddress(hAdvapi32Dll, "LsaOpenPolicy");                                          assert(LsaOpenPolicyPtr);
    LsaEnumerateAccountRightsPtr = (_LsaEnumerateAccountRightsT)GetProcAddress(hAdvapi32Dll, "LsaEnumerateAccountRights");      assert(LsaEnumerateAccountRightsPtr);
}

void Unload_Dll(void)
{
    FreeLibrary(hNetapi32Dll);
    FreeLibrary(hAdvapi32Dll);
}