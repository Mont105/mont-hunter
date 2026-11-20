/* Harmless fixture for MontHunter's Windows sandbox test.
 * Mimics typical behaviours without doing anything harmful:
 * Run-key persistence, dropped executable, child process, outbound connection, DNS lookup.
 * Build: x86_64-w64-mingw32-gcc -O1 -o winprobe.exe winprobe.c -lws2_32 -ladvapi32 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("hello from winprobe\n");

    HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0,
                        KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
        const char *v = "C:\\Users\\Public\\mhprobe.exe";
        RegSetValueExA(k, "MHProbe", 0, REG_SZ, (const BYTE *)v, (DWORD)strlen(v) + 1);
        RegCloseKey(k);
    }

    CreateDirectoryA("C:\\Users\\Public", NULL);
    HANDLE f = CreateFileA("C:\\Users\\Public\\mhprobe.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD n;
        WriteFile(f, "MZ-not-really-an-exe", 20, &n, NULL);
        CloseHandle(f);
    }

    system("cmd /c echo spawned-child");

    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    gethostbyname("c2.evil.invalid");
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(4444);
    a.sin_addr.s_addr = inet_addr("203.0.113.7");
    connect(s, (struct sockaddr *)&a, sizeof a);
    closesocket(s);
    WSACleanup();
    return 0;
}
