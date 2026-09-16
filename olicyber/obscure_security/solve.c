#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static
char warr[] = {
    0xbe, 0xc0, 0xc9, 0x76, 0xf5, 0xab, 0xf6, 0x09, 0x56, 0x19,
    0x85, 0xfd, 0xe1, 0x4d, 0x0e, 0x83, 0xe3, 0x46, 0xa8, 0xa6,
    0x5b, 0xcb, 0x7c, 0x8b, 0xbe, 0x33, 0x1c, 0x24, 0x74, 0x51,
    0xb3, 0x1b, 0xcb, 0xca, 0x8f, 0xec, 0x98, 0xbf, 0x78, 0x5b
};

static
char trgt[] = {
    0xe7, 0x8e, 0x9a, 0x5c, 0xba, 0xe0, 0xb5, 0x4e, 0x73, 0x5d,
    0xca, 0xdf, 0xdd, 0x75, 0x3d, 0xb6, 0xfe, 0x07, 0x9f, 0x92,
    0x6f, 0xf4, 0x6b, 0xb0, 0x89, 0x0f, 0x28, 0x0d, 0x65, 0x64,
    0x98, 0x33, 0xe3, 0xf9, 0x84, 0xc3, 0xb3, 0x8f, 0x50, 0x46
};

static inline
void invert_rotation()
{
    long len;
    int v3, i, j;
    char *ptr;
    
    len = strlen(trgt);
    ptr = calloc(1, len + 1);
    
    v3 = 16 % strlen(trgt);
    
    for (i = 0; i < 16 % strlen(trgt); i++)
        ptr[v3++] = trgt[i];

    for (j = 16 % strlen(trgt); j < strlen(trgt); j++)
        ptr[v3++ % strlen(trgt)] = trgt[j];
    
    ptr[strlen(trgt)] = 0;
    strcpy(trgt, ptr);
    free(ptr);
}

static inline
void replace_char(char c, char replacement)
{
    for (int i = 0; i < 40; i++)
        if (trgt[i] == c)
            trgt[i] = replacement;
}

static inline
void rotate_first_n_chars()
{
    long v2;
    int v3, i, j;
    char *ptr;

    v2 = strlen(trgt);
    ptr = calloc(1u, v2 + 1);
    v3 = 0;
    
    for (i = 16 % strlen(trgt); i < strlen(trgt); i++)
        ptr[v3++] = trgt[i];
    
    for (j = 0; j < 16; j++)
        ptr[v3++] = trgt[j];
    
    ptr[strlen(trgt)] = 0;
    strcpy(trgt, ptr);
    free(ptr);
}

static inline
void sum_idx()
{
    for (int i = 0; i < 40 ; i++)
        trgt[i] += i;
}

static inline
void swap()
{
    for (int i = 0; i < 40; i += 2) {
        char tmp = trgt[i];
        trgt[i] = trgt[i + 1];
        trgt[i + 1] = tmp;
    }
}

static inline
void to_lowercase()
{
    for (int i = 0; i < 40; i++)
        trgt[i] = tolower(trgt[i]);
}

static inline
void xor()
{
    for (int i = 0; i < 40; i++)
        trgt[i] ^= warr[i];
}

static inline
void print_trgt()
{
    printf("HEX: ");
    
    for (int i = 0; i < 40; i++)
        printf("%x ", trgt[i]);
    
    printf("\nTEXT: %s\n", trgt);
}

__attribute__((constructor))
void init()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    for (int i = 0; i < 40; i += 2) {
        char tmp = warr[i];
        warr[i] = warr[i + 1];
        warr[i + 1] = tmp;
    }    
}

int main()
{
    swap();
    replace_char('@', 'z');
    
    xor(); 
    swap();
    
    sum_idx();
    to_lowercase();
    
    rotate_first_n_chars();
    
    replace_char('s', '$');
    replace_char('a', '4');
    replace_char('e', '3');
    replace_char('o', '0');
    replace_char('t', '7');
    replace_char('i', '!');
    replace_char('-', '_');

    invert_rotation();

    print_trgt();
    return 0;
}
