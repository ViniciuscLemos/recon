/* A tiny login program to analyze. Version 1 checks the password locally and logs the attempt. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const char *STORED_USER = "admin";
static const uint32_t STORED_HASH = 0x3f6a1b2cu;

/* FNV-1a, standing in for a real password hash */
static uint32_t hash_password(const char *password) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)password; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

static int check_login(const char *user, const char *password) {
    if (strcmp(user, STORED_USER) != 0) return 0;
    return hash_password(password) == STORED_HASH;
}

static void log_attempt(const char *user, int ok) {
    FILE *log = fopen("login.log", "a");
    if (!log) return;
    fprintf(log, "login attempt user=%s result=%s\n", user, ok ? "ok" : "denied");
    fclose(log);
}

int main(void) {
    char user[64], password[64];
    printf("Username: ");
    if (scanf("%63s", user) != 1) return 1;
    printf("Password: ");
    if (scanf("%63s", password) != 1) return 1;
    int ok = check_login(user, password);
    log_attempt(user, ok);
    puts(ok ? "Access granted" : "Invalid username or password");
    return ok ? 0 : 1;
}
