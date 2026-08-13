#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <linux/seccomp.h>
#include <sys/stat.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>

int urandom;
int total_allocated_pages = 0;

int64_t generate_signature(uint64_t ptr)
{  
    int64_t signature;
    read(urandom, &signature, sizeof signature);
    return signature & 0xffffff;
}

void *extract_ptr(void *ptr)
{ 
    return (void*)(((uint64_t)ptr & 0x7fffffffffff));
}

void *sign_ptr(void *ptr)
{ 
    uint64_t tmp_ptr=(uint64_t)ptr & 0x7fffffffffff;
    uint64_t signature = generate_signature(tmp_ptr);
    uint64_t generated_ptr = signature<<47 | tmp_ptr;

    return (void*) generated_ptr;
}

static int install_protections()
{
    struct sock_filter filter[] = {
        /* validate arch */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
        /* Grab the system call number. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),
        /* List allowed syscalls. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 3), 
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[0]))), 
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 3, 1, 0), 
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        exit(-1);
    }
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        exit(-1);
    }
    
    return 0;
}

void hello_world()
{
    puts("Hello world!");
}

void palindrome()
{
    char str[]="Was it a car or a cat I saw?";
    int l = 0;
    int h = strlen(str) - 1;
    while (l < h) {
        while (!isalnum(str[l]) && l < h) l++;
        while (!isalnum(str[h]) && l < h) h--;
        if (tolower(str[l++]) != tolower(str[h--])) {
            printf("%s is not a palindrome\n", str);
            return;
        }
    }
    
    printf("%s is a palindrome\n", str);
}

void primality_test()
{
    puts("3 is prime!");
}

void *init()
{
    setvbuf(stdin,(char *)0x0,2,0);
    setvbuf(stdout,(char *)0x0,2,0);
    setvbuf(stderr,(char *)0x0,2,0);

    void *flagPtr;
    urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0) {
        puts("Could not open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    read(urandom, &flagPtr, sizeof(flagPtr));
    return flagPtr;
}

void execute_test_function()
{
    void *ptr;
    char ptrstr[18];

    printf("Function pointer: ");
    read(STDIN_FILENO, ptrstr, 36);
    ptr = (void*)strtol(ptrstr+2, NULL, 16);
    ptr = extract_ptr(ptr);

    if (ptr == NULL)
        return;
    
    ((void (*)())ptr)();
}

void get_test_functions_list()
{
    void *hello_world_ptr = sign_ptr(hello_world);
    void *palindrome_ptr = sign_ptr(palindrome);
    void *primality_test_ptr = sign_ptr(primality_test);

    printf("Hello world function: %p\n", hello_world_ptr);
    printf("Palindrome function: %p\n", palindrome_ptr);
    printf("Primality test function: %p\n", primality_test_ptr);
}

void allocate_memory()
{
    if (total_allocated_pages >= 10) {
        puts("Sorry cannot allocate any more memory for you.");
        return;
    }
    
    void *newMem = mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (newMem == 0) {
        puts("Could not allocate any more memory.");
        exit(EXIT_FAILURE);
    }
    
    total_allocated_pages += 1;
    printf("Your allocated memory is at %p\n", sign_ptr(newMem));
}

void write_memory()
{
    void *ptr;
    printf("Memory pointer: ");
    scanf("%p", &ptr);
    getchar();
    ptr = extract_ptr(ptr);
    printf("Text: ");
    read(STDIN_FILENO, ptr, 16);
}

void read_memory()
{
    void *ptr;
    printf("Function pointer: ");
    scanf("%p", &ptr);
    getchar();
    ptr = extract_ptr(ptr);
    write(STDOUT_FILENO, ptr, 16);
}

void mainMenu()
{
    puts("This is PoC for 2PAC, a novel technology providing safe pointers!");
    puts("This technology allows you to reduce memory usage by leaving the burden of saving pointers to your users!");

    while(1) {
        puts("Main menu:");
        puts("1. Allocate new memory");
        puts("2. Write to memory");
        puts("3. Read from memory");
        puts("4. Execute test function");
        puts("5. Get test functions list");
        puts("6. Exit");
        printf("> ");
        int choice = -1;
        scanf("%d", &choice);
        getchar();
        switch (choice){
            case 1:
                allocate_memory();
                break;
            case 2:
                write_memory();
                break;
            case 3:
                read_memory();
                break;
            case 4:
                execute_test_function();
                break;
            case 5:
                get_test_functions_list();
                break;
            case 6:
                puts("Thank you for flying with us!");
                exit(0);
                break;
            default:
                puts("Unknown option");
        }
    }
}

int main()
{
    void *flagPtr = init();
    
    void *addr = (void *)(((uint64_t)flagPtr & 0xfff000) | 0x7ffff7000000);
    flagPtr = mmap(addr, getpagesize(), PROT_WRITE, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);

    FILE *flagFile;
    flagFile = fopen("flag.txt", "r");
    if (!flagFile) {
        puts("Could not load flag.txt");
        exit(EXIT_FAILURE);
    }
    
    fgets(flagPtr, 100, flagFile);
    fclose(flagFile);
    flagFile = NULL;

    mprotect(flagPtr, getpagesize(), PROT_NONE);
    flagPtr = 0;  
    install_protections();
    mainMenu();

    return 0;
}
