#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void login(){
	int passcode1;
	int passcode2;
	
	printf("\n[PWN] passcode1's address is %p\n", &passcode1);
	printf("[PWN] passcode2's address is %p\n\n", &passcode2);
	
	printf("[PWN] passcode1's value is %d\n", passcode1);
	printf("[PWN] passcode2's value is %d\n\n", passcode2);

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
		setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("[PWN] Stack's address is %p\n\n", name);
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.1 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}

