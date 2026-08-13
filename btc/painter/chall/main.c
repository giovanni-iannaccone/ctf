#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define COL 64
#define ROW 64

static char canvas1[ROW * COL];
static char canvas2[ROW * COL];
static char canvas3[ROW * COL];
static char canvas4[ROW * COL];

static char *gallery[4] = {canvas1, canvas2, canvas3, canvas4};

void download()
{
    int idx;
    char name[100];
    
    printf("Idx of canvas: ");
    scanf("%d", &idx);
    
    printf("File name: ");
    scanf("%99s[^\n]", name);

    FILE *fd = fopen(name, "w");

    if (fd == NULL) {
        perror("Could not download: ");
        exit(EXIT_FAILURE);
    }
    
    for (int i = 0; i < ROW; i++) {
        fwrite(gallery[idx] + i, 1, ROW, fd);
        fwrite("\n", 1, 1, fd);
    }
}

void fast_paint()
{
    int idx;
    int offset;
    
    puts("Yeah paint as fast as Lightning McQueen KACHOW");
    
    printf("Idx of canvas: ");
    scanf("%d", &idx);
    
    printf("Offset of the pixel you want to set: ");
    scanf("%d", &offset);
    
    printf("Values: ");
    read(0, gallery[idx] + offset, sizeof(void *));
}

void init()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void menu()
{
    puts("\n1. Set a pixel");
    puts("2. Fast paint");
    puts("3. Look at your masterpiece");
    puts("4. Download your art");
    puts("99. Exit");
    printf("> ");
}

void paint()
{
    int idx;
    int offset;
    
    printf("Idx of canvas: ");
    scanf("%d", &idx);
    
    printf("Offset of the pixel you want to set: ");
    scanf("%d", &offset);

    getchar();
    
    printf("Value to set pixel to: ");
    gallery[idx][offset] = getchar();
}

void show()
{
    int idx;
    
    printf("Idx of canvas: ");
    scanf("%d", &idx);
    
    for (int i = 0; i < ROW; i++) {
        for (int j = 0; j < COL; j++)
            putchar(gallery[idx][i * ROW + j]);

        putchar('\n');
    }

    puts("Painting is definetly not for you, maybe pwn is ?");
}

void painter_3000(int option)
{
    switch (option) {
    case 1:
        paint();
        break;
        
    case 2:
        fast_paint();
        break;
        
    case 3:
        show();
        break;

    case 4:
        download();
        break;
    }
}

void win()
{
    system("/bin/sh");
}

int main()
{
    int option;
    
    init();
    puts("*** Painter 3000 ***");
    
    do {
        menu();
        scanf("%d", &option);

        if (option > 4 && option != 99) {
            printf("Invalid option\n");
            continue;
        }
        
        painter_3000(option);

    } while (option != 99);
    
    exit(0);
}
