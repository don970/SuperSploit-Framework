#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    const char *home = getenv("HOME");
    if (home == NULL) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return 1;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/.SuperSploit/start.sh", home);

    // Using execl replaces the current process with bash, preventing shell injection vulnerabilities
    // compared to using system().
    execl("/bin/bash", "bash", path, (char *)NULL);

    // If execl returns, an error occurred
    perror("execl failed");
    return 1;
}