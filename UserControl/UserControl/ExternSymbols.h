#pragma once

#include "LoadDll.h"

extern HINSTANCE hNetapi32Dll;
extern HINSTANCE hAdvapi32Dll;

extern _NetUserEnumT                NetUserEnumPtr;
extern _NetApiBufferFreeT           NetApiBufferFreePtr;
extern _NetUserGetLocalGroupsT      NetUserGetLocalGroupsPtr;
extern _NetUserGetGroupsT           NetUserGetGroupsPtr;
extern _NetUserAddT                 NetUserAddPtr;
extern _NetUserDelT                 NetUserDelPtr;
extern _NetLocalGroupAddMembersT    NetLocalGroupAddMembersPtr;
extern _NetLocalGroupDelMembersT    NetLocalGroupDelMembersPtr;
extern _NetLocalGroupAddT           NetLocalGroupAddPtr;
extern _NetLocalGroupDelT           NetLocalGroupDelPtr;

extern _ConvertSidToStringSidT      ConvertSidToStringSidPtr;
extern _LookupAccountNameT          LookupAccountNamePtr;
extern _AdjustTokenPrivilegesT      AdjustTokenPrivilegesPtr;
extern _LsaAddAccountRightsT        LsaAddAccountRightsPtr;
extern _LsaRemoveAccountRightsT     LsaRemoveAccountRightsPtr;
extern _LsaNtStatusToWinErrorT      LsaNtStatusToWinErrorPtr;
extern _LsaOpenPolicyT              LsaOpenPolicyPtr;
extern _LsaEnumerateAccountRightsT  LsaEnumerateAccountRightsPtr;