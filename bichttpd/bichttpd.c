// Compile:  gcc -O2 -Wall -Wextra -pedantic -std=c11 bichttpd.c -o bichttpd
// Install :  install -D -m 0755 ./bichttpd ~/opt/bichttpd/usr/sbin/bichttpd
// Run    :  ~/opt/bichttpd/usr/sbin/bichttpd --port 42204 [--debug|-d] [--fork] [--secure|-s]
 
#define _POSIX_C_SOURCE 200809L
#include <toml.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
 
#define BACKLOG       64
#define REQ_MAX       8192
#define PATH_MAX_LEN  1024
 
static int g_debug  = 0;
static int g_fork   = 0;
static int g_secure = 0;   // SECURE OPTION: just a flag for now
 
/* ------------------------------ utils ---------------------------------- */
static void dprintf_dbg(const char *fmt, ...) {
    if (!g_debug) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
 
static void http_date(char *buf, size_t n) {
    time_t now = time(NULL);
    struct tm g;
#if defined(_WIN32) || defined(_WIN64)
    if (gmtime_s(&g, &now) != 0) memset(&g, 0, sizeof g);
#else
    if (!gmtime_r(&now, &g)) memset(&g, 0, sizeof g);
#endif
    strftime(buf, n, "%a, %d %b %Y %H:%M:%S GMT", &g);
}
 
static ssize_t full_send(int fd, const void *p, size_t n) {
    const char *b = (const char*)p;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, 0);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return (ssize_t)off;
}
 
static void sendf(int fd, const char *fmt, ...) {
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (len > 0) full_send(fd, buf, (size_t)len);
}
 
static void respond_simple(int fd, int code, const char *reason, const char *body) {
    char date[64]; http_date(date, sizeof date);
    size_t n = body ? strlen(body) : 0;
    sendf(fd,
        "HTTP/1.0 %d %s\r\n"
        "Date: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        code, reason, date, n, body ? body : "");
}
 
/* --- recognise strictly A..Z token to decide 400 vs 405 --- */
static int token_is_upper_alpha(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *p=(const unsigned char*)s; *p; ++p) {
        if (*p < 'A' || *p > 'Z') return 0;
    }
    return 1;
}
 
/* ------------------------- FS root attendu ------------------------------ */
static void get_root(char *out, size_t n) {
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(out, n, "%s/opt/bichttpd/srv/http", home);
}
 
/* Mappe l’URL vers ~/opt/bichttpd/srv/http (protège basiquement) */
static void build_fs_path(char out[PATH_MAX_LEN], const char *url_path) {
    char root[PATH_MAX_LEN]; get_root(root, sizeof root);
 
    if (!url_path || strstr(url_path, "..")) {
        snprintf(out, PATH_MAX_LEN, "%s/index.html", root);
        return;
    }
    if (url_path[0] == '\0' || (url_path[0] == '/' && url_path[1] == '\0')) {
        snprintf(out, PATH_MAX_LEN, "%s/index.html", root);
        return;
    }
 
    const char *p = (url_path[0] == '/') ? url_path + 1 : url_path;
    int w = snprintf(out, PATH_MAX_LEN, "%s/%s", root, p);
    if (w < 0 || w >= (int)PATH_MAX_LEN) {
        snprintf(out, PATH_MAX_LEN, "%s/index.html", root);
    }
}
 
/* ------------------------------ file serving --------------------------- */
static void respond_headers_only(int fd, int code, const char *reason) {
    char date[64]; http_date(date, sizeof date);
    sendf(fd,
        "HTTP/1.0 %d %s\r\n"
        "Date: %s\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n",
        code, reason, date);
}
 
static void send_file(int fd, const char *path, const char *method) {
    int f = open(path, O_RDONLY);
    if (f < 0) {
        if (strcmp(method, "HEAD") == 0) respond_headers_only(fd, 404, "Not Found");
        else respond_simple(fd, 404, "Not Found", "Not Found\n");
        return;
    }
 
    struct stat st;
    if (fstat(f, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(f);
        if (strcmp(method, "HEAD") == 0) respond_headers_only(fd, 404, "Not Found");
        else respond_simple(fd, 404, "Not Found", "Not Found\n");
        return;
    }
 
    char date[64]; http_date(date, sizeof date);
    sendf(fd,
        "HTTP/1.0 200 OK\r\n"
        "Date: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        date, (size_t)st.st_size);
 
    if (strcmp(method, "HEAD") != 0) {
        char buf[4096]; ssize_t r;
        while ((r = read(f, buf, sizeof buf)) > 0) {
            if (full_send(fd, buf, (size_t)r) < 0) break;
        }
    }
    close(f);
}
 
/* ------------------------------ HTTP ----------------------------------- */
static void handle_client(int cfd) {
    char req[REQ_MAX+1]; memset(req, 0, sizeof req);
    ssize_t r = recv(cfd, req, REQ_MAX, 0);
    if (r <= 0) { close(cfd); return; }
    req[r] = '\0';
 
    if (g_debug) dprintf_dbg("=== Request ===\n%.*s\n==============\n", (int)r, req);
 
    /* Tolérer CRLF ou LF seul */
    char *line_end = strstr(req, "\r\n");
    if (!line_end) line_end = strchr(req, '\n');
    if (!line_end) { respond_simple(cfd, 400, "Bad Request", "Bad Request\n"); close(cfd); return; }
    *line_end = '\0';
 
    char method[16], path[PATH_MAX_LEN], version[16];
    if (sscanf(req, "%15s %1023s %15s", method, path, version) != 3) {
        respond_simple(cfd, 400, "Bad Request", "Bad Request\n"); close(cfd); return;
    }
 
    if (!token_is_upper_alpha(method)) {
        respond_simple(cfd, 400, "Bad Request", "Bad Request\n");
        close(cfd);
        return;
    }
 
    /* HTTP/1.0 uniquement (RFC 1945). */
    if (strcmp(version, "HTTP/1.0") != 0) {
        respond_simple(cfd, 505, "HTTP Version Not Supported", "Only HTTP/1.0 is supported\n");
        close(cfd); return;
    }
 
    /* Méthodes autorisées */
    if (strcmp(method, "GET") && strcmp(method, "HEAD") && strcmp(method, "POST")) {
        respond_simple(cfd, 405, "Method Not Allowed", "Allowed: GET, HEAD, POST\n");
        close(cfd); return;
    }
 
    if (!strcmp(method, "POST")) {
        respond_simple(cfd, 200, "OK", "POST received\n");
        close(cfd); return;
    }
 
    /* GET/HEAD -> servir depuis ~/opt/bichttpd/srv/http */
    char fs_path[PATH_MAX_LEN];
    build_fs_path(fs_path, path);
 
    if (g_debug) dprintf_dbg("[REQ] %s %s %s\n", method, path, version);
 
    send_file(cfd, fs_path, method);
    close(cfd);
}
 
/* ------------------------------ CLI ------------------------------------ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --port N [--debug|-d] [--fork] [--secure|-s]\n"
        "  --port N   Port d'ecoute (1..65535)\n"
        "  --debug,-d Trace des requetes sur stderr\n"
        "  --fork     Un processus par connexion\n"
        "  --secure,-s  Active l'option de mode securise (TLS a venir)\n",
        prog);
}
 
static int parse_port_strict(const char *s, unsigned short *out) {
    errno = 0; char *end = NULL; long v = strtol(s, &end, 10);
    if (errno != 0 || s == end || *end != '\0') return -1;
    if (v < 1 || v > 65535) return -2;
    *out = (unsigned short)v; return 0;
}
 
/* reap workers */
static void reap_children(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) { /* loop */ }
}
 
/* ------------------------------ main ----------------------------------- */
int main(int argc, char **argv) {
    int port = -1;
 
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--port=", 7) == 0) {
            unsigned short p; int rc = parse_port_strict(argv[i] + 7, &p);
            if (rc != 0) { fprintf(stderr, "Invalid argument\n"); return EXIT_FAILURE; }
            port = (int)p; continue;
        }
        if (!strcmp(argv[i], "--port")) {
            if (i + 1 >= argc) { fprintf(stderr, "Invalid argument\n"); return EXIT_FAILURE; }
            unsigned short p; int rc = parse_port_strict(argv[++i], &p);
            if (rc != 0) { fprintf(stderr, "Invalid argument\n"); return EXIT_FAILURE; }
            port = (int)p; continue;
        }
        if (!strcmp(argv[i], "-p")) {
            if (i + 1 >= argc) { fprintf(stderr, "Invalid argument\n"); return EXIT_FAILURE; }
            unsigned short p; int rc = parse_port_strict(argv[++i], &p);
            if (rc != 0) { fprintf(stderr, "Invalid argument\n"); return EXIT_FAILURE; }
            port = (int)p; continue;
        }
        if (!strcmp(argv[i], "--debug") || !strcmp(argv[i], "-d")) { g_debug = 1; continue; }
        if (!strcmp(argv[i], "--fork"))  { g_fork  = 1; continue; }
        if (!strcmp(argv[i], "--secure") || !strcmp(argv[i], "-s")) { g_secure = 1; continue; } // SECURE OPTION
        usage(argv[0]); return EXIT_FAILURE;
    }
 
    if (port < 0) { usage(argv[0]); return EXIT_FAILURE; }
 
    /* DEBUG: pas de buffering + messages CdC */
    if (g_debug) {
        setvbuf(stderr, NULL, _IONBF, 0);
        fprintf(stderr, "[BOOT] debug=ON\n");
    }
    if (g_secure && g_debug) {
        fprintf(stderr, "[BOOT] secure=ON\n");
        fprintf(stderr, "[bichttpd] TLS connection enabled\n");
 
 /* demandé en Étape 3. */
    }
 
    if (g_fork) {
        struct sigaction sa; memset(&sa, 0, sizeof sa);
        sa.sa_handler = reap_children;
        sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, NULL);
    }
 
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return EXIT_FAILURE; }
 
    int yes = 1; setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
 
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
 
    if (g_debug) {
        char ip[32]; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof ip);
        fprintf(stderr, "[bichttpd] Trying to bind to %s:%d\n", ip, (int)ntohs(addr.sin_port));
    }
    if (bind(sfd, (struct sockaddr*)&addr, sizeof addr) < 0) { perror("bind"); close(sfd); return EXIT_FAILURE; }
 
    if (g_debug) {
        char ip[32]; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof ip);
        fprintf(stderr, "[bichttpd] Socket successfully bound to %s:%d\n", ip, (int)ntohs(addr.sin_port));
    }
    if (listen(sfd, BACKLOG) < 0) { perror("listen"); close(sfd); return EXIT_FAILURE; }
 
    if (g_debug) fprintf(stderr, "[bichttpd] Listening on socket %d\n", sfd);
 
    fprintf(stderr, "Listening on 0.0.0.0:%d (HTTP/1.0)%s%s%s\n",
            port,
            g_debug?" [debug]":"",
            g_fork ? " [fork]":"",
            g_secure ? " [secure]":""   // visible mais pas requis
    );
 
    if (g_debug) fprintf(stderr, "[bichttpd] Ready to accept connection\n");
 
    for (;;) {
        struct sockaddr_in cli; socklen_t clilen = sizeof cli;
        int cfd = accept(sfd, (struct sockaddr*)&cli, &clilen);
        if (cfd < 0) { if (errno==EINTR) continue; perror("accept"); break; }
 
        if (g_debug) {
            char cip[32]; inet_ntop(AF_INET, &cli.sin_addr, cip, sizeof cip);
            fprintf(stderr, "[bichttpd] Connection accepted from %s:%d\n",
                    cip, (int)ntohs(cli.sin_port));
        }
 
        if (g_fork) {
            pid_t pid = fork();
            if (pid == 0) {
                if (g_debug) {
                    fprintf(stderr, "[WORKER] pid=%d ppid=%d\n", (int)getpid(), (int)getppid());
                    fprintf(stderr, "[bichttpd] Subprocess %d handling request\n", (int)getpid());
                }
                close(sfd);
                handle_client(cfd);
                _exit(0);
            }
            if (pid > 0) { close(cfd); }
        } else {
            handle_client(cfd);
            close(cfd);
        }
    }
 
    close(sfd);
    return 0;
}