#pragma once

int Add_User(LPWSTR lpszUser, LPWSTR lpszPassword);
int Delete_User(LPWSTR lpszUser);

int Set_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index);
int Clear_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index);
int Clear_All_User_Privileges(LPWSTR lpszUser);

int Assign_User_To_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup);
int Exclude_User_From_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup);

int Add_Group(LPWSTR lpszLocalGroup);
int Delete_Group(LPWSTR lpszLocalGroup);

void list_Privileges(void);
