#pragma once
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "netapi32.lib")

#include <windows.h>
#include <lm.h>
#include <iostream>
#include <iomanip>
#include <lsalookup.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <winbase.h>
#include <string>

using namespace std;

#define MAX_STRING_LENGTH 128
#define MAX_PRIVILEGE_INDEX 36

class UsersAndGroups
{
private:

	DWORD MAX_USERS_GROUPS = 100;

	DWORD usersNumber;
	DWORD groupsNumber;

	USER_INFO_1* usersArray;
	LOCALGROUP_INFO_0* groupsArray;

	PSID* usersSID;
	PSID* groupsSID;

private:

	LSA_HANDLE GetPolicyHandle();
	bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString);

	void Create();
	void Update();
	void Clean();

	void PrintListOfUsers();
	void PrintListOfGroups();

	void AddUser();
	void DeleteUser();
	void AddUserPrivilege();
	void RemoveUserPrivilege();

	PSID GetUserSID(LPCTSTR userName);
	void GetUserPrivileges(int userIndex);
	void GetUserGroups(LPCTSTR userName);
	void GetUserLevel(DWORD userPrivelege);

	void AddGroup();
	void DeleteGroup();
	void AddGroupPrivilege();
	void DeleteGroupPrivilege();
	void GetGroupPrivileges(int groupIndex);

	void AddUserToGroup();
	void DeleteUserFromGroup();

public:

	UsersAndGroups();
	~UsersAndGroups();

	void Menu();
};
