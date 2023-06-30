#include <iostream>
#include <locale.h>
#include "UsersAndGroups.h"

using namespace std;

int main()
{
	setlocale(LC_ALL, "Rus");
	UsersAndGroups winSecApp = UsersAndGroups();
	winSecApp.Menu();
}
