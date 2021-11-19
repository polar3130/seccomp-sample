#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

int main()
{
        int fd = open("foo.txt", O_WRONLY|O_TRUNC|O_CREAT);
        const char *val = "hello.";

        printf("Setting seccomp strict mode...\n");
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

        printf("Trying to write to an opened file...\n");
        write(fd, val, strlen(val)+1);

        printf("Trying to rename a file...\n");
        rename("foo.txt", "bar.txt");

        printf("Done.\n");
}
