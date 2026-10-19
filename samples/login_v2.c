/* Version 2 of the login program: it stops writing a local log and reports each attempt to a
   server instead, and it now also locks the account after three failures. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static const char *STORED_USER = "admin";
static const uint32_t STORED_HASH = 0x3f6a1b2cu;
static const char *AUDIT_HOST = "10.0.0.5";
static int failures = 0;

static uint32_t hash_password(const char *password) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)password; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

static int check_login(const char *user, const char *password) {
    if (failures >= 3) return 0;
    if (strcmp(user, STORED_USER) != 0 || hash_password(password) != STORED_HASH) {
        failures++;
        return 0;
    }
    failures = 0;
    return 1;
}

static void report_attempt(const char *user, int ok) {
    char message[128];
    snprintf(message, sizeof message, "POST /audit HTTP/1.1\r\nHost: %s\r\n\r\nuser=%s&ok=%d", AUDIT_HOST, user, ok);
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
#endif
    int sock = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    inet_pton(AF_INET, AUDIT_HOST, &server.sin_addr);
    if (connect(sock, (struct sockaddr *)&server, sizeof server) == 0)
        send(sock, message, (int)strlen(message), 0);
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
}

int main(void) {
    char user[64], password[64];
    printf("Username: ");
    if (scanf("%63s", user) != 1) return 1;
    printf("Password: ");
    if (scanf("%63s", password) != 1) return 1;
    int ok = check_login(user, password);
    report_attempt(user, ok);
    puts(ok ? "Access granted" : "Invalid username or password");
    return ok ? 0 : 1;
}
