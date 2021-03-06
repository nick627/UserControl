#ifndef UNICODE
#define UNICODE
#endif

#include "stdafx.h"
#include "LoadDll.h"
#include "GetUserInfo.h"
#include "SetUserInfo.h"
#include "CLI.hpp"

using namespace std;

// au, ru, ag, rg, eu, ap, cp, jg, lg

LPWSTR help_str = (LPWSTR)L"Usage:\n"
                           "\t /au - Add user\n"
                           "\t /ru - Remove user\n"
                           "\t /ag - Add group\n"
                           "\t /rg - Remove group\n"
                           "\t /eu - Enumerate users\n"
                           "\t /ap - Add privilege to user\n"
                           "\t /rp - Remove user privilege\n"
                           "\t /rap - Remove all user privileges\n"
                           "\t /jg - Join group\n"
                           "\t /lg - Leave group\n"
                           "\n";

int wmain(int argc, wchar_t *argv[])
{
    setlocale(LC_ALL, "Russian");
    Load_Dll();
    TCHAR user_name[1024] = { 0 };
    TCHAR group_name[1024] = { 0 };
    TCHAR user_password[1024] = { 0 };
    DWORD privilege_index = 0;

    if (argc == 1)
    {
        wprintf(help_str);
        return 0;
    }
    else if (argc == 2)
    {
        if(wcscmp(argv[1], L"/au") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            wcout << "enter password\n";
            wcin >> user_password;
            Add_User((LPWSTR)user_name, (LPWSTR)user_password);
            
            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/ru") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            Delete_User((LPWSTR)user_name);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/ag") == 0)
        {
            wcout << "enter group name\n";
            wcin >> group_name;
            Add_Group((LPWSTR)group_name);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/rg") == 0)
        {
            wcout << "enter group name\n";
            wcin >> group_name;
            Delete_Group((LPWSTR)group_name);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/eu") == 0)
        {
            Enumerate_Users(NULL);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/ap") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            list_Privileges();
            wcout << "enter privilege index\n";
            wcin >> privilege_index;
            Set_User_Privileges((LPWSTR)user_name, privilege_index);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/rp") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            list_Privileges();
            wcout << "enter privilege index\n";
            wcin >> privilege_index;
            Clear_User_Privileges((LPWSTR)user_name, privilege_index);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/rap") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            Clear_All_User_Privileges((LPWSTR)user_name);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/jg") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            wcout << "enter group name\n";
            wcin >> group_name;
            Assign_User_To_Group((LPWSTR)user_name, (LPWSTR)group_name);

            Unload_Dll();
            return 0;
        }
        if (wcscmp(argv[1], L"/lg") == 0)
        {
            wcout << "enter username\n";
            wcin >> user_name;
            wcout << "enter group name\n";
            wcin >> group_name;
            Exclude_User_From_Group((LPWSTR)user_name, (LPWSTR)group_name);
            
            Unload_Dll();
            return 0;
        }

    }

    Unload_Dll();
    return 0;
}

