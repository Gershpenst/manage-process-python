#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    printf("Début du programme %s\n", argv[0]);

    int pid = fork();

    if (pid == 0) {
        while(1) {
            printf("Hello from Child!\n");
            sleep(1);
        }
    } else {
        while(1) {
            printf("Hello from Parent!\n");
            sleep(1);
        }
    }
    
    return 0;
} 