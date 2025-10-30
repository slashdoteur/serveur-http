#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>
#include <pwd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int server_socket = -1;
static const char *log_file = NULL;
static int debug_mode = 0;
static int secure_mode = 0;
static SSL_CTX *ssl_ctx = NULL;
static const char *cert_file = "/opt/bichttpd/usr/sbin/server.crt";
static const char *key_file = "/opt/bichttpd/usr/sbin/server.key";

void handle_sigint(int sig) {
    if (server_socket != -1) {
        close(server_socket);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    exit(EXIT_SUCCESS);
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [-p PORT] [-d] [-s] [-l LOGFILE] [-c CONFFILE]\n", program_name);
    fprintf(stderr, "  -p PORT  Spécifier le port d'écoute (défaut: 42124)\n");
    fprintf(stderr, "  -d       Activer le mode debug\n");
    fprintf(stderr, "  -s       Activer le mode sécurisé (TLS)\n");
    fprintf(stderr, "  -l FILE  Spécifier le fichier de log\n");
    fprintf(stderr, "  -c FILE  Spécifier le fichier de configuration\n");
}

static unsigned short parse_port(const char *s){
    char *e = NULL;
    errno = 0;
    long v = strtol(s, &e, 10);
    if(errno != 0 || e == s || *e != '\0' || v < 1 || v > 65535){
        fprintf(stderr, "Invalid argument: port '%s' is invalid (must be 1-65535)\n", s);
        exit(EXIT_FAILURE);
    }
    return (unsigned short)v;
}

int parse_config(const char *filename, unsigned short *port) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open config file '%s'\n", filename);
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, " =");
        char *value = strtok(NULL, " =\n\r");
        if (key && value) {
            if (strcmp(key, "port") == 0) {
                *port = atoi(value);
            } else if (strcmp(key, "secure_mode") == 0) {
                secure_mode = atoi(value);
            } else if (strcmp(key, "debug_mode") == 0) {
                debug_mode = atoi(value);
            } else if (strcmp(key, "log_file") == 0) {
                log_file = strdup(value);
            }
        }
    }
    fclose(file);
    return 1;
}

void log_request(const char *method, const char *path, int status) {
    if (log_file) {
        FILE *log = fopen(log_file, "a");
        if (log) {
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char time_buffer[64];
            strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
            fprintf(log, "[%s] \"%s %s HTTP/1.0\" %d\n", time_buffer, method, path, status);
            fclose(log);
        }
    }
}

void get_current_date(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now); // Use GMT for HTTP dates
    strftime(buffer, size, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
}

void send_http_response(int client, int status, const char *body, const char *method, const char *path) {
    char response[4096];
    char date_header[128];
    const char *status_text;

    switch(status) {
        case 200: status_text = "200 OK"; break;
        case 400: status_text = "400 Bad Request"; break;
        case 404: status_text = "404 Not Found"; break;
        default: status_text = "500 Internal Server Error"; break;
    }

    get_current_date(date_header, sizeof(date_header));

    size_t body_length = (strcmp(method, "HEAD") == 0) ? 0 : strlen(body);
    snprintf(response, sizeof(response),
        "HTTP/1.0 %s\r\n"
        "Date: %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n", status_text, date_header, body_length);

    // For HEAD requests, don't send body
    if (strcmp(method, "HEAD") != 0) {
        strncat(response, body, sizeof(response) - strlen(response) - 1);
    }

    send(client, response, strlen(response), 0);
    log_request(method, path, status);
}

void send_ssl_response(SSL *ssl, int status, const char *body, const char *method, const char *path) {
    char response[4096];
    char date_header[128];
    const char *status_text;

    switch(status) {
        case 200: status_text = "200 OK"; break;
        case 400: status_text = "400 Bad Request"; break;
        case 404: status_text = "404 Not Found"; break;
        default: status_text = "500 Internal Server Error"; break;
    }

    get_current_date(date_header, sizeof(date_header));

    size_t body_length = (strcmp(method, "HEAD") == 0) ? 0 : strlen(body);
    snprintf(response, sizeof(response),
        "HTTP/1.0 %s\r\n"
        "Date: %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n", status_text, date_header, body_length);

    // For HEAD requests, don't send body
    if (strcmp(method, "HEAD") != 0) {
        strncat(response, body, sizeof(response) - strlen(response) - 1);
    }

    SSL_write(ssl, response, strlen(response));
    log_request(method, path, status);
}

const char* get_current_username() {
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_name : "tc243969";
}

int serve_file(int client, const char *path, const char *method) {
    char full_path[1024];
    const char *username = get_current_username();

    if (strcmp(path, "/") == 0) {
        snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/index.html", username);
        if (access(full_path, F_OK) == -1) {
            snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/root/index.html", username);
        }
    } else {
        const char *clean_path = (path[0] == '/') ? path + 1 : path;

        snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/%s", username, clean_path);
        if (access(full_path, F_OK) == -1) {
            snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/root/%s", username, clean_path);
        }
    }

    if (debug_mode) {
        fprintf(stderr, "[bichttpd] Looking for file: %s\n", full_path);
    }

    if (access(full_path, F_OK) == -1) {
        if (debug_mode) {
            fprintf(stderr, "[bichttpd] File not found: %s\n", full_path);
        }
        return 0;
    }

    struct stat st;
    if (stat(full_path, &st) == -1 || !S_ISREG(st.st_mode)) {
        return 0;
    }

    FILE *file = fopen(full_path, "r");
    if (!file) {
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(file);
        return 0;
    }

    char *file_content = malloc(file_size + 1);
    if (!file_content) {
        fclose(file);
        return 0;
    }

    size_t bytes_read = fread(file_content, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(file_content);
        return 0;
    }
    file_content[bytes_read] = '\0';

    char response[8192];
    char date_header[128];
    get_current_date(date_header, sizeof(date_header));

    // For HEAD requests, don't include body
    if (strcmp(method, "HEAD") == 0) {
        snprintf(response, sizeof(response),
            "HTTP/1.0 200 OK\r\n"
            "Date: %s\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n", date_header, file_size);
    } else {
        snprintf(response, sizeof(response),
            "HTTP/1.0 200 OK\r\n"
            "Date: %s\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s", date_header, file_size, file_content);
    }

    int send_result = send(client, response, strlen(response), 0);
    log_request(method, path, 200);
    free(file_content);

    return send_result != -1;
}

int serve_ssl_file(SSL *ssl, const char *path, const char *method) {
    char full_path[1024];
    const char *username = get_current_username();

    if (strcmp(path, "/") == 0) {
        snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/index.html", username);
        if (access(full_path, F_OK) == -1) {
            snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/root/index.html", username);
        }
    } else {
        const char *clean_path = (path[0] == '/') ? path + 1 : path;

        snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/%s", username, clean_path);
        if (access(full_path, F_OK) == -1) {
            snprintf(full_path, sizeof(full_path), "/home/2025/a2-bic/%s/opt/bichttpd/srv/http/root/%s", username, clean_path);
        }
    }

    if (debug_mode) {
        fprintf(stderr, "[bichttpd] Looking for file: %s\n", full_path);
    }

    if (access(full_path, F_OK) == -1) {
        if (debug_mode) {
            fprintf(stderr, "[bichttpd] File not found: %s\n", full_path);
        }
        return 0;
    }

    struct stat st;
    if (stat(full_path, &st) == -1 || !S_ISREG(st.st_mode)) {
        return 0;
    }

    FILE *file = fopen(full_path, "r");
    if (!file) {
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(file);
        return 0;
    }

    char *file_content = malloc(file_size + 1);
    if (!file_content) {
        fclose(file);
        return 0;
    }

    size_t bytes_read = fread(file_content, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(file_content);
        return 0;
    }
    file_content[bytes_read] = '\0';

    char response[8192];
    char date_header[128];
    get_current_date(date_header, sizeof(date_header));

    // For HEAD requests, don't include body
    if (strcmp(method, "HEAD") == 0) {
        snprintf(response, sizeof(response),
            "HTTP/1.0 200 OK\r\n"
            "Date: %s\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n", date_header, file_size);
    } else {
        snprintf(response, sizeof(response),
            "HTTP/1.0 200 OK\r\n"
            "Date: %s\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s", date_header, file_size, file_content);
    }

    int ssl_result = SSL_write(ssl, response, strlen(response));
    log_request(method, path, 200);
    free(file_content);

    return ssl_result > 0;
}

void handle_client_request(int client) {
    char buf[4096];
    ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);

    if (n <= 0) {
        close(client);
        return;
    }

    buf[n] = '\0';

    char *first_line = strtok(buf, "\r\n");

    if (!first_line) {
        send_http_response(client, 400, "<html><body><h1>400 Bad Request</h1></body></html>", "UNKNOWN", "unknown");
        close(client);
        return;
    }

    char method[16], path[256], version[16];
    int parsed = sscanf(first_line, "%15s %255s %15s", method, path, version);

    if (debug_mode) {
        fprintf(stderr, "[bichttpd] Received: %s %s %s\n", method, path, version);
    }

    if (parsed != 3) {
        send_http_response(client, 400, "<html><body><h1>400 Bad Request - Invalid request line</h1></body></html>", "UNKNOWN", "unknown");
        close(client);
        return;
    }

    if (strcmp(version, "HTTP/1.0") != 0) {
        send_http_response(client, 400, "<html><body><h1>400 Bad Request - Invalid HTTP version</h1></body></html>", method, path);
        close(client);
        return;
    }

    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0 && strcmp(method, "POST") != 0) {
        send_http_response(client, 400, "<html><body><h1>400 Bad Request - Invalid method</h1></body></html>", method, path);
        close(client);
        return;
    }

    if (!serve_file(client, path, method)) {
        if (strcmp(method, "POST") == 0) {
            send_http_response(client, 200, "<html><body><h1>POST Received</h1></body></html>", method, path);
        } else {
            send_http_response(client, 404, "<html><body><h1>404 Not Found</h1></body></html>", method, path);
        }
    }

    close(client);
}

void handle_ssl_client_request(SSL *ssl, int client) {
    char buf[4096];
    ssize_t n = SSL_read(ssl, buf, sizeof(buf) - 1);

    if (n <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    buf[n] = '\0';

    char *first_line = strtok(buf, "\r\n");

    if (!first_line) {
        send_ssl_response(ssl, 400, "<html><body><h1>400 Bad Request</h1></body></html>", "UNKNOWN", "unknown");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    char method[16], path[256], version[16];
    int parsed = sscanf(first_line, "%15s %255s %15s", method, path, version);

    if (debug_mode) {
        fprintf(stderr, "[bichttpd] Received TLS: %s %s %s\n", method, path, version);
    }

    if (parsed != 3) {
        send_ssl_response(ssl, 400, "<html><body><h1>400 Bad Request - Invalid request line</h1></body></html>", "UNKNOWN", "unknown");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    if (strcmp(version, "HTTP/1.0") != 0) {
        send_ssl_response(ssl, 400, "<html><body><h1>400 Bad Request - Invalid HTTP version</h1></body></html>", method, path);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0 && strcmp(method, "POST") != 0) {
        send_ssl_response(ssl, 400, "<html><body><h1>400 Bad Request - Invalid method</h1></body></html>", method, path);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        return;
    }

    if (!serve_ssl_file(ssl, path, method)) {
        if (strcmp(method, "POST") == 0) {
            send_ssl_response(ssl, 200, "<html><body><h1>POST Received</h1></body></html>", method, path);
        } else {
            send_ssl_response(ssl, 404, "<html><body><h1>404 Not Found</h1></body></html>", method, path);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
}

SSL_CTX* create_ssl_context() {
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

int configure_ssl_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    unsigned short port = 42124; // Fixed default port
    int opt;

    while((opt = getopt(argc, argv, "p:dsl:c:")) != -1) {
        switch(opt) {
            case 'p': port = parse_port(optarg); break;
            case 'd': debug_mode = 1; fprintf(stderr, "[bichttpd] Debug mode enabled\n"); break;
            case 's': secure_mode = 1; fprintf(stderr, "[bichttpd] TLS connection enabled\n"); break;
            case 'l': log_file = optarg; break;
            case 'c': if (!parse_config(optarg, &port)) return EXIT_FAILURE; break;
            default: print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if(optind < argc) {
        fprintf(stderr, "Error: Unexpected argument '%s'\n", argv[optind]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (secure_mode) {
        ssl_ctx = create_ssl_context();
        if (!ssl_ctx || !configure_ssl_context(ssl_ctx)) {
            fprintf(stderr, "Error: Failed to initialize SSL context\n");
            return EXIT_FAILURE;
        }
    }

    if (debug_mode) {
        fprintf(stderr, "[bichttpd] Trying to bind to port %d\n", port);
        fprintf(stderr, "[bichttpd] Current username: %s\n", get_current_username());
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, handle_sigint);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket error");
        return EXIT_FAILURE;
    }

    int yes = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt");
        close(server_socket);
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
    addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind error");
        close(server_socket);
        return EXIT_FAILURE;
    }

    if (listen(server_socket, 16) == -1) {
        perror("listen error");
        close(server_socket);
        return EXIT_FAILURE;
    }

    printf("HTTP server listening on port %d\n", port);
    if (secure_mode) {
        printf("TLS server enabled on port %d\n", port);
    }

    while (1) {
        int client = accept(server_socket, NULL, NULL);
        if (client == -1) {
            if (errno == EINTR) continue;
            perror("accept error");
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork error");
            close(client);
            continue;
        }

        if (pid == 0) {
            close(server_socket);

            if (secure_mode) {
                SSL *ssl = SSL_new(ssl_ctx);
                SSL_set_fd(ssl, client);

                if (SSL_accept(ssl) <= 0) {
                    if (debug_mode) {
                        fprintf(stderr, "[bichttpd] TLS handshake failed\n");
                    }
                    SSL_free(ssl);
                    close(client);
                    exit(EXIT_SUCCESS);
                }

                if (debug_mode) {
                    fprintf(stderr, "[bichttpd] TLS connection established\n");
                }

                handle_ssl_client_request(ssl, client);
            } else {
                handle_client_request(client);
            }

            exit(EXIT_SUCCESS);
        } else {
            close(client);
        }
    }

    close(server_socket);
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    return EXIT_SUCCESS;
}