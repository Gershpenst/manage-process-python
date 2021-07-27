#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    printf("Début du programme %s\n", argv[0]);

    while(1) {
        printf("Hello from %s !\n", argv[0]);
        sleep(1);
    }
    
    return 0;
} 