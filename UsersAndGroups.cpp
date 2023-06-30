#include "UsersAndGroups.h"

const wchar_t* g_PrivilegeArray[] =
{
	TEXT("SeAssignPrimaryTokenPrivilege"),
	TEXT("SeAuditPrivilege"),
	TEXT("SeBackupPrivilege"),
	TEXT("SeChangeNotifyPrivilege"),
	TEXT("SeCreateGlobalPrivilege"),
	TEXT("SeCreatePagefilePrivilege"),
	TEXT("SeCreatePermanentPrivilege"),
	TEXT("SeCreateSymbolicLinkPrivilege"),
	TEXT("SeCreateTokenPrivilege"),
	TEXT("SeDebugPrivilege"),
	TEXT("SeEnableDelegationPrivilege"),
	TEXT("SeImpersonatePrivilege"),
	TEXT("SeIncreaseBasePriorityPrivilege"),
	TEXT("SeIncreaseQuotaPrivilege"),
	TEXT("SeIncreaseWorkingSetPrivilege"),
	TEXT("SeLoadDriverPrivilege"),
	TEXT("SeLockMemoryPrivilege"),
	TEXT("SeMachineAccountPrivilege"),
	TEXT("SeManageVolumePrivilege"),
	TEXT("SeProfileSingleProcessPrivilege"),
	TEXT("SeRelabelPrivilege"),
	TEXT("SeRemoteShutdownPrivilege"),
	TEXT("SeRestorePrivilege"),
	TEXT("SeSecurityPrivilege"),
	TEXT("SeShutdownPrivilege"),
	TEXT("SeSyncAgentPrivilege"),
	TEXT("SeSystemEnvironmentPrivilege"),
	TEXT("SeSystemProfilePrivilege"),
	TEXT("SeSystemtimePrivilege"),
	TEXT("SeTakeOwnershipPrivilege"),
	TEXT("SeTcbPrivilege"),
	TEXT("SeTimeZonePrivilege"),
	TEXT("SeTrustedCredManAccessPrivilege"),
	TEXT("SeUnsolicitedInputPrivilege"),
	TEXT("SeUndockPrivilege"),
	TEXT("SeInteractiveLogonRight"),
	TEXT("SeNetworkLogonRight")
};


bool UsersAndGroups::InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)
			return FALSE;
	}

	pLsaString->Buffer = (WCHAR*)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}


UsersAndGroups::UsersAndGroups()
{
	this->Create();
}


UsersAndGroups::~UsersAndGroups()
{
	NetApiBufferFree(this->usersArray);
	NetApiBufferFree(this->groupsArray);
	this->Clean();
}


void UsersAndGroups::Create()
{
	if (this->usersArray != NULL)
		this->usersArray = NULL;

	this->usersArray = new USER_INFO_1[this->MAX_USERS_GROUPS];

	DWORD dwprefmaxlen = MAX_PREFERRED_LENGTH;
	DWORD dwtotalentries;
	DWORD dwfilter = 0;

	NetUserEnum(NULL, 1, dwfilter, (LPBYTE*)&(this->usersArray), dwprefmaxlen, &(this->usersNumber), &dwtotalentries, NULL);
	NetLocalGroupEnum(NULL, 0, (LPBYTE*)&(this->groupsArray), dwprefmaxlen, &(this->groupsNumber), &dwtotalentries, NULL);

	this->usersSID = new PSID[this->MAX_USERS_GROUPS];
	this->groupsSID = new PSID[this->MAX_USERS_GROUPS];

	for (int i = 0; i < this->usersNumber; i++)
		this->usersSID[i] = this->GetUserSID(this->usersArray[i].usri1_name);

	for (int i = 0; i < this->groupsNumber; i++)
		this->groupsSID[i] = this->GetUserSID(this->groupsArray[i].lgrpi0_name);
}


void UsersAndGroups::Update()
{
	this->Clean();
	this->Create();
}


void UsersAndGroups::Clean()
{
	free(this->usersSID);
	free(this->groupsSID);
}


LSA_HANDLE UsersAndGroups::GetPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE lsahPolicyHandle;

	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);

	return lsahPolicyHandle;
}


void UsersAndGroups::Menu() {

	int choice = 0;

	while (choice != 20)
	{
		system("cls");

		cout << "1 - Show users list" << endl
			<< "2 - Show group list" << endl
			<< "3 - Add user" << endl
			<< "4 - Delete user" << endl
			<< "5 - Add privileges to user" << endl
			<< "6 - Delete privileges to user" << endl
			<< "7 - Add group" << endl
			<< "8 - Delete group" << endl
			<< "9 - Add privileges to group " << endl
			<< "10 - Delete privileges to group" << endl
			<< "11 - Add user to group" << endl
			<< "12 - Delete user from group" << endl
			<< "\n0 - Exit" << endl;

		cout << endl << "Choose option: ";
		cin >> choice;

		switch (choice)
		{
		case 1:
			this->PrintListOfUsers();
			break;
		case 2:
			this->PrintListOfGroups();
			break;
		case 3:
			this->AddUser();
			break;
		case 4:
			this->DeleteUser();
			break;
		case 5:
			this->AddUserPrivilege();
			break;
		case 6:
			this->RemoveUserPrivilege();
			break;
		case 7:
			this->AddGroup();
			break;
		case 8:
			this->DeleteGroup();
			break;
		case 9:
			this->AddGroupPrivilege();
			break;
		case 10:
			this->DeleteGroupPrivilege();
			break;
		case 11:
			this->AddUserToGroup();
			break;
		case 12:
			this->DeleteUserFromGroup();
			break;
		case 0:
			return;
		default:
			cout << "Error: incorrect command" << endl;
			break;
		}
		system("pause");
	}
}


void UsersAndGroups::PrintListOfUsers()
{
	LPWSTR stringSID;

	for (int i = 0; i < this->usersNumber; i++)
	{
		cout << endl;
		cout << "-" << i << endl;
		cout << setw(30) << left << "Username:";
		wcout << this->usersArray[i].usri1_name << endl;
		cout << setw(30) << left << "User's SID:";
		ConvertSidToStringSidW(this->usersSID[i], &stringSID);
		wcout << stringSID << endl;
		cout << setw(30) << left << "User's privileges:";
		this->GetUserPrivileges(i);
		cout << setw(30) << left << "User's groups:";
		this->GetUserGroups(this->usersArray[i].usri1_name);
		cout << setw(30) << left << "User;s level:";
		this->GetUserLevel(this->usersArray[i].usri1_priv);
	}
}


PSID UsersAndGroups::GetUserSID(LPCTSTR userName)
{
	DWORD dwSidLength = 0, dwLengthOfDomainName = 0, dwRetCode = 0;
	SID_NAME_USE typeOfSid;
	PSID lpSid = NULL;
	LPTSTR lpDomainName = NULL;

	if (!LookupAccountName(NULL, userName, NULL, &dwSidLength, NULL, &dwLengthOfDomainName, &typeOfSid))
	{
		dwRetCode = GetLastError();
		if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
		{
			lpSid = (SID*) new char[dwSidLength];
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
		}
		else
		{
			cout << "Lookup account name failed: " << GetLastError() << endl;
			return NULL;
		}
	}

	if (!LookupAccountName(NULL, userName, lpSid, &dwSidLength, lpDomainName, &dwLengthOfDomainName, &typeOfSid))
	{

		cout << "Lookup account name failed: " << GetLastError() << endl;
		return NULL;
	}
	return lpSid;
}


void UsersAndGroups::GetUserLevel(DWORD userPrivelege)
{
	if (userPrivelege == USER_PRIV_GUEST)
		cout << "Guest";
	else
		if (userPrivelege == USER_PRIV_USER)
			cout << "User";
		else
			if (userPrivelege == USER_PRIV_ADMIN)
				cout << "Admin";
	cout << endl;
}


void UsersAndGroups::GetUserPrivileges(int userIndex)
{
	LPLOCALGROUP_USERS_INFO_0 pBuf2;
	LPUSER_INFO_4 pTmpBuf1;
	NET_API_STATUS nStatus;
	NET_API_STATUS nStatusLG;
	DWORD dwEntriesReadLG = 0;
	DWORD dwTotalEntriesLG = 0;
	DWORD i = MAX_COMPUTERNAME_LENGTH + 1;
	wchar_t pszServerName[MAX_COMPUTERNAME_LENGTH + 1];
	GetComputerNameW(pszServerName, &i);

	NetUserGetInfo((LPCWSTR)pszServerName, this->usersArray[userIndex].usri1_name, 4, (LPBYTE*)&pTmpBuf1);

	LPWSTR sid;
	ConvertSidToStringSidW(this->usersSID[userIndex], &sid);

	NTSTATUS ntsResult;
	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	LSA_HANDLE lsahPolicyHandle;
	ULONG count = 0;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
	PSID sid1 = this->usersSID[userIndex];
	ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_LOOKUP_NAMES, &lsahPolicyHandle);
	PLSA_UNICODE_STRING rights;
	ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, sid1, &rights, &count);
	LsaNtStatusToWinError(ntsResult);
	LPLOCALGROUP_INFO_0 lgroups = NULL;
	nStatusLG = NetUserGetLocalGroups((LPCWSTR)pszServerName, this->usersArray[userIndex].usri1_name, 0, LG_INCLUDE_INDIRECT,
		(LPBYTE*)&pBuf2, MAX_PREFERRED_LENGTH, &dwEntriesReadLG, &dwTotalEntriesLG);

	if (ntsResult == ERROR_SUCCESS)
	{
		if (count)
			for (int k = 0; k < count; k++)
			{
				if (k + 1 < count)
					wprintf(L"%s; ", rights->Buffer);
				else
					wprintf(L"%s; ", rights->Buffer);
				rights++;
			}
		else
			printf("No additional rights");
	}
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	PDWORD_PTR dwResumeHandle = 0;
	nStatus = NetLocalGroupEnum(pszServerName, 0, (LPBYTE*)&lgroups, MAX_PREFERRED_LENGTH,
		&dwEntriesRead, &dwTotalEntries, dwResumeHandle);

	if (dwEntriesReadLG != 0 && nStatus == NERR_Success && nStatusLG == NERR_Success)
	{
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf = pBuf2;
		for (int i = 0; i < dwEntriesRead; i++)
		{
			if (lstrcmpW(lgroups->lgrpi0_name, pTmpBuf->lgrui0_name) == 0)
			{
				LSA_HANDLE lsahPolicyHandle;
				LSA_OBJECT_ATTRIBUTES ObjAttributes;
				PSID sid1 = this->GetUserSID(lgroups->lgrpi0_name);
				ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
				ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
				PLSA_UNICODE_STRING rights;
				ULONG count = 0;
				ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, sid1, &rights, &count);
				if (ntsResult == ERROR_SUCCESS)
				{
					if (count)
						for (int k = 0; k < count; k++)
						{
							if (k + 1 < count)
								wprintf(L"%s; ", rights->Buffer);
							else
								wprintf(L"%s; ", rights->Buffer);
							rights++;
						}
					else
						printf("NO additional rights");
				}
			}
			lgroups++;
		}
	}
	cout << endl;
}


void UsersAndGroups::GetUserGroups(LPCTSTR userName)
{
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwEntriesRead, dwTotalEntries, dwTotalCount = 0, i;

	NET_API_STATUS nStatus = NetUserGetLocalGroups(NULL, userName, 0, LG_INCLUDE_INDIRECT,
		(LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries);

	if (nStatus == NERR_Success)
	{

		for (i = 0; i < dwEntriesRead; i++)
		{

			if (pBuf == NULL)
			{
				cout << "An access violation has occurred";
				break;
			}
			wcout << pBuf->lgrui0_name << " ";
			pBuf++;
			dwTotalCount++;
		}
	}
	else
		cout << "A system error has occurred";

	cout << endl;
}

void UsersAndGroups::AddUser()
{
	TCHAR userName[MAX_STRING_LENGTH] = { 0 };
	TCHAR userPassword[MAX_STRING_LENGTH] = { 0 };

	cout << "Enter new username: ";
	wcin >> userName;
	cout << "Enter new username password: ";
	wcin >> userPassword;

	USER_INFO_1 userInfo;
	NET_API_STATUS nStatus = NERR_Success;
	ZeroMemory(&userInfo, sizeof(USER_INFO_1));
	userInfo.usri1_name = userName;
	userInfo.usri1_password = userPassword;
	userInfo.usri1_priv = USER_PRIV_USER;
	userInfo.usri1_flags = UF_NORMAL_ACCOUNT | UF_SCRIPT;

	nStatus = NetUserAdd(NULL, 1, (PBYTE)&userInfo, NULL);

	if (nStatus == NERR_Success)
		cout << "Success" << endl;
	else
		cout << "Error: " << GetLastError() << endl;

	this->Update();
}


void UsersAndGroups::DeleteUser()
{
	unsigned int index;
	cout << "Enter users index you want to delete: ";
	cin >> index;

	NET_API_STATUS nStatus = NetUserDel(NULL, this->usersArray[index].usri1_name);

	if (nStatus == NERR_Success)
		cout << "Success" << endl;
	else
		cout << "Error: " << GetLastError() << endl;

	this->Update();
}


void UsersAndGroups::AddUserPrivilege()
{
	unsigned int index;
	cout << "Enter user's index: ";
	cin >> index;

	LSA_HANDLE lsahPolicyHandle;
	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

	NTSTATUS nStatus = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if (nStatus != NULL)
		cout << "Lsa open policy failed: %d\n" << GetLastError();

	cout << "Privileges list" << endl;
	for (int i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
		wcout << i << " - " << g_PrivilegeArray[i] << endl;

	DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;

	while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX)
	{
		cout << endl << "Enter privilege index: ";
		wcin >> privilegeIndex;
	}

	LSA_UNICODE_STRING lsaString;
	this->InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

	if (LsaAddAccountRights(lsahPolicyHandle, this->usersSID[index], &lsaString, 1))
		cout << "Error: " << GetLastError() << endl;
	else cout << "Success" << endl;
}


void UsersAndGroups::RemoveUserPrivilege()
{
	unsigned int userIndex;
	cout << "Enter user's index: ";
	cin >> userIndex;

	DWORD privilegesAmount = 0;
	PLSA_UNICODE_STRING privilegesArray;
	LSA_HANDLE Handle = this->GetPolicyHandle();
	LsaEnumerateAccountRights(Handle, this->usersSID[userIndex], &privilegesArray, &privilegesAmount);
	LsaClose(Handle);

	if (privilegesAmount > 0)
	{
		cout << "Priveleges list" << endl;
		for (int i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
			wcout << i << " - " << g_PrivilegeArray[i] << endl;

		DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
		while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX)
		{
			cout << endl << "Enter privelege index: ";
			wcin >> privilegeIndex;
		}

		LSA_UNICODE_STRING lsaString;
		this->InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

		LSA_HANDLE pHandle = this->GetPolicyHandle();
		NTSTATUS nStatus = LsaRemoveAccountRights(pHandle, this->usersSID[userIndex], FALSE, &lsaString, 1);
		LsaClose(pHandle);

		if (LsaNtStatusToWinError(nStatus) == ERROR_SUCCESS)
			cout << "Success" << endl;
		else
			cout << "Error: " << GetLastError() << endl;

	}
	else
		cout << "User dont have any priveleges" << endl;
}


void UsersAndGroups::PrintListOfGroups()
{
	LPWSTR stringSID;

	for (int i = 0; i < groupsNumber; i++)
	{
		cout << endl;
		cout << "-" << i << endl;
		cout << setw(30) << left << "Group name:";
		wcout << this->groupsArray[i].lgrpi0_name << endl;
		cout << setw(30) << left << "Group SID:";
		ConvertSidToStringSidW(this->groupsSID[i], &stringSID);
		wcout << stringSID << endl;
		cout << setw(30) << left << "Group privileges:";
		this->GetGroupPrivileges(i);
	}
}


void UsersAndGroups::GetGroupPrivileges(int groupIndex)
{
	DWORD rightsAmount;
	PLSA_UNICODE_STRING groupRights;
	LSA_HANDLE pHandle = this->GetPolicyHandle();

	LsaEnumerateAccountRights(pHandle, this->groupsSID[groupIndex], &groupRights, &rightsAmount);

	if (rightsAmount != 0)
	{
		for (int i = 0; i < rightsAmount; i++)
			wcout << groupRights[i].Buffer << "; ";
	}
	wcout << endl;

	LsaClose(pHandle);
	LsaFreeMemory(groupRights);
}


void UsersAndGroups::AddGroup()
{
	wchar_t groupName[MAX_STRING_LENGTH];
	cout << "Enter new group name: ";
	wcin >> groupName;

	LOCALGROUP_INFO_0 groupInfo;
	groupInfo.lgrpi0_name = groupName;

	NET_API_STATUS status = NetLocalGroupAdd(NULL, 0, (PBYTE)&groupInfo, NULL);
	if (status == NERR_Success)
		cout << "Success" << endl;
	else cout << "Error: " << GetLastError() << endl;

	this->Update();
}


void UsersAndGroups::DeleteGroup()
{
	wchar_t groupName[MAX_STRING_LENGTH] = { 0 };
	cout << "Enter group name to delete: ";
	wcin >> groupName;

	NET_API_STATUS status = NetLocalGroupDel(NULL, groupName);
	if (status == NERR_Success)
		cout << "Success" << endl;
	else cout << "Error: " << GetLastError() << endl;

	this->Update();
}


void UsersAndGroups::AddUserToGroup()
{
	int userIndex, groupIndex;
	cout << "Enter group index: ";
	cin >> groupIndex;
	cout << "Enter ures index: ";
	cin >> userIndex;

	if (NetLocalGroupAddMember(NULL, groupsArray[groupIndex].lgrpi0_name, usersSID[userIndex]) == NERR_Success)
		cout << "Success" << endl;
	else cout << "Error: " << GetLastError() << endl;
	this->Update();
}


void UsersAndGroups::DeleteUserFromGroup()
{
	int userIndex, groupIndex;
	cout << "Enter group index: ";
	cin >> groupIndex;
	cout << "Enter user's index to delete: ";
	cin >> userIndex;

	if (NetLocalGroupDelMember(NULL, this->groupsArray[groupIndex].lgrpi0_name, this->usersSID[userIndex]) == NERR_Success)
		cout << "Success" << endl;
	else cout << "Error: " << GetLastError() << endl;
	this->Update();
}


void UsersAndGroups::AddGroupPrivilege()
{
	int groupIndex;
	cout << "Enter group index: ";
	cin >> groupIndex;

	LSA_HANDLE lsahPolicyHandle;
	LSA_OBJECT_ATTRIBUTES ObjAttributes;
	ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

	NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
	if (ntsResult != NULL)
		cout << "Lsa open policy failed: " << GetLastError() << endl;

	for (size_t i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
		wcout << i << " - " << g_PrivilegeArray[i] << endl;

	DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
	while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX)
	{
		cout << "Enter privilege index: ";
		wcin >> privilegeIndex;
	}

	LSA_UNICODE_STRING lsaString;
	this->InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

	if (LsaAddAccountRights(lsahPolicyHandle, this->groupsSID[groupIndex], &lsaString, 1) != NULL)
		cout << "Error: " << GetLastError() << endl;
	else cout << "Success" << endl;
}


void UsersAndGroups::DeleteGroupPrivilege()
{
	int groupIndex;
	cout << "Enter group index: ";
	cin >> groupIndex;

	DWORD privilegeAmount = 0;
	PLSA_UNICODE_STRING privilegeArray;
	LSA_HANDLE Handle = this->GetPolicyHandle();

	LsaEnumerateAccountRights(Handle, this->groupsSID[groupIndex], &privilegeArray, &privilegeAmount);

	LsaClose(Handle);

	if (privilegeAmount > 0)
	{
		for (size_t i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
			wcout << i << " - " << g_PrivilegeArray[i] << endl;;

		DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
		while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX)
		{
			cout << "ВEnter privilege index: ";
			wcin >> privilegeIndex;
		}

		LSA_OBJECT_ATTRIBUTES ObjAttributes;
		LSA_HANDLE lsahPolicyHandle;
		ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

		NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
		if (ntsResult != NULL)
			cout << "Lsa open policy failed: " << GetLastError() << endl;

		LSA_UNICODE_STRING lsaString;
		this->InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

		if (LsaRemoveAccountRights(lsahPolicyHandle, this->groupsSID[groupIndex], 0, &lsaString, 1) != NULL)
			cout << "Error: " << GetLastError() << endl;
		else cout << "Success" << endl;
	}
	else
		cout << "Group don't have any privileges" << endl;
}
