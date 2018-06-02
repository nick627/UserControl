#pragma once

LSA_HANDLE GetPolicyHandle();
void Enumerate_Privileges(LPTSTR _user_name);
void Get_User_Sid(LPTSTR _user_name);
void Enumerate_Users(LPTSTR _server_name);
void Enumerate_Groups(LPWSTR _user_name);