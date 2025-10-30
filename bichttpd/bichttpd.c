#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <tls.h>

#define BUFFER_SIZE 4096
#define ROOT_DIR "/home/tc243969/opt/bichttpd/srv/http"
#define DEFAULT_PORT 42124
#define LOG_FILE "/home/tc243969/opt/bichttpd/var/log/access.log"

// Chemins des certificats
#define CA_FILE "/home/tc243969/opt/bichttpd/etc/certs/root-ca.pem"
#define CERT_FILE "/home/tc243969/opt/bichttpd/etc/certs/cert.pem"
#define KEY_FILE "/home/tc243969/opt/bichttpd/etc/certs/key.pem"

// Variables globales
int secure_mode = 0;
int debug_mode = 0;
FILE *log_fp = NULL;

// Fonction pour obtenir la date au format HTTP (RFC 1123)
void get_http_date(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(buf, size, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
}

// Fonction de logging
void write_log(const char *client_ip, const char *method, const char *path, int status) {
    if (!log_fp) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%d/%b/%Y:%H:%M:%S %z", tm_info);
    
    fprintf(log_fp, "%s - - [%s] \"%s %s HTTP/1.0\" %d -\n",
            client_ip, timestamp, method, path, status);
    fflush(log_fp);
}

// Envoi de la réponse HTTP
void send_response(int client_fd, struct tls *tls_conn, const char *status, 
                   const char *content_type, const char *body) {
    char header[BUFFER_SIZE];
    char date_buf[128];
    int length = body ? strlen(body) : 0;
    
    get_http_date(date_buf, sizeof(date_buf));
    
    snprintf(header, sizeof(header),
             "HTTP/1.0 %s\r\n"
             "Date: %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n"
             "\r\n",
             status, date_buf, content_type, length);
    
    if (secure_mode && tls_conn) {
        tls_write(tls_conn, header, strlen(header));
        if (body) tls_write(tls_conn, body, length);
    } else {
        write(client_fd, header, strlen(header));
        if (body) write(client_fd, body, length);
    }
}

// Gestion d'un client
void handle_client(int client_fd, struct tls *tls_ctx, const char *client_ip) {
    struct tls *tls_conn = NULL;
    char buffer[BUFFER_SIZE];
    ssize_t bytes;
    
    if (secure_mode && tls_ctx) {
        if (tls_accept_socket(tls_ctx, &tls_conn, client_fd) < 0) {
            fprintf(stderr, "TLS accept error: %s\n", tls_error(tls_ctx));
            close(client_fd);
            exit(1);
        }
        
        bytes = tls_read(tls_conn, buffer, sizeof(buffer) - 1);
        if (bytes < 0) {
            fprintf(stderr, "TLS read error: %s\n", tls_error(tls_conn));
            tls_close(tls_conn);
            tls_free(tls_conn);
            close(client_fd);
            exit(1);
        }
    } else {
        bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    }
    
    if (bytes <= 0) {
        if (tls_conn) {
            tls_close(tls_conn);
            tls_free(tls_conn);
        }
        close(client_fd);
        exit(0);
    }
    buffer[bytes] = '\0';

    if (debug_mode) {
        printf("🔍 Requête reçue : %s\n", buffer);
    }

    // Parser la méthode et le chemin
    char method[16] = "UNKNOWN";
    char path[256] = "/";
    sscanf(buffer, "%15s %255s", method, path);

    if (strncmp(buffer, "GET", 3) == 0) {
        const char *body = "<html><body><h1>200 OK</h1></body></html>\n";
        send_response(client_fd, tls_conn, "200 OK", "text/html", body);
        write_log(client_ip, method, path, 200);
    } else {
        const char *body = "<html><body><h1>400 Bad Request</h1></body></html>\n";
        send_response(client_fd, tls_conn, "400 Bad Request", "text/html", body);
        write_log(client_ip, method, path, 400);
    }

    if (tls_conn) {
        tls_close(tls_conn);
        tls_free(tls_conn);
    }
    close(client_fd);
    exit(0);
}

// Initialisation du contexte TLS
struct tls *init_tls_server() {
    struct tls_config *tls_cfg = NULL;
    struct tls *tls_ctx = NULL;
    
    if (tls_init() < 0) {
        fprintf(stderr, "TLS initialization failed\n");
        return NULL;
    }
    
    tls_ctx = tls_server();
    if (!tls_ctx) {
        fprintf(stderr, "tls_server() failed\n");
        return NULL;
    }
    
    tls_cfg = tls_config_new();
    if (!tls_cfg) {
        fprintf(stderr, "tls_config_new() failed\n");
        tls_free(tls_ctx);
        return NULL;
    }
    
    if (tls_config_set_ca_file(tls_cfg, CA_FILE) < 0) {
        fprintf(stderr, "Failed to load CA file: %s\n", CA_FILE);
        tls_config_free(tls_cfg);
        tls_free(tls_ctx);
        return NULL;
    }
    
    if (tls_config_set_cert_file(tls_cfg, CERT_FILE) < 0) {
        fprintf(stderr, "Failed to load cert file: %s\n", CERT_FILE);
        tls_config_free(tls_cfg);
        tls_free(tls_ctx);
        return NULL;
    }
    
    if (tls_config_set_key_file(tls_cfg, KEY_FILE) < 0) {
        fprintf(stderr, "Failed to load key file: %s\n", KEY_FILE);
        tls_config_free(tls_cfg);
        tls_free(tls_ctx);
        return NULL;
    }
    
    if (tls_configure(tls_ctx, tls_cfg) < 0) {
        fprintf(stderr, "tls_configure() failed: %s\n", tls_error(tls_ctx));
        tls_config_free(tls_cfg);
        tls_free(tls_ctx);
        return NULL;
    }
    
    tls_config_free(tls_cfg);
    
    if (debug_mode) {
        fprintf(stderr, "[ bichttpd ] TLS connection enabled\n");
    }
    
    return tls_ctx;
}

// Lecture du fichier de configuration
void read_config_file(const char *config_file, int *port, int *secure) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        if (debug_mode) {
            fprintf(stderr, "Impossible d'ouvrir le fichier de configuration: %s\n", config_file);
        }
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // Enlever les espaces et les commentaires
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        
        // Parser les options
        if (strstr(line, "port")) {
            char *equals = strchr(line, '=');
            if (equals) {
                *port = atoi(equals + 1);
            }
        } else if (strstr(line, "secure")) {
            char *equals = strchr(line, '=');
            if (equals) {
                char value[32];
                sscanf(equals + 1, " %31s", value);
                if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
                    *secure = 1;
                }
            }
        }
    }
    
    fclose(fp);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    int opt;
    char *config_file = NULL;

    // Parser les options de ligne de commande
    while ((opt = getopt(argc, argv, "p:sdc:")) != -1) {
        switch (opt) {
            case 'p': {
                char *endptr;
                long val = strtol(optarg, &endptr, 10);

                if (*endptr != '\0') {
                    fprintf(stderr, "Invalid argument\n");
                    return 1;
                }

                if (val <= 0 || val > 65535) {
                    fprintf(stderr, "Invalid argument\n");
                    return 1;
                }
               
                port = (int)val;
                break;
            }
            case 's':
                secure_mode = 1;
                break;
            case 'd':
                debug_mode = 1;
                break;
            case 'c':
                config_file = optarg;
                break;
            default:
                fprintf(stderr, "Invalid argument\n");
                return 1;
        }
    }

    // Lire le fichier de configuration si spécifié
    if (config_file) {
        read_config_file(config_file, &port, &secure_mode);
    }

    // Initialiser TLS si nécessaire
    struct tls *tls_ctx = NULL;
    if (secure_mode) {
        tls_ctx = init_tls_server();
        if (!tls_ctx) {
            fprintf(stderr, "Erreur lors de l'initialisation TLS\n");
            return 1;
        }
        if (debug_mode) {
            printf("🔒 Mode sécurisé activé (TLS)\n");
        }
    }

    // Créer le socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int reuse_opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_opt, sizeof(reuse_opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(sockfd, 10) < 0) {
        perror("listen");
        return 1;
    }

    if (debug_mode) {
        printf("✅ Serveur en écoute sur le port %d...\n", port);
    }
    
    signal(SIGCHLD, SIG_IGN);

    // Boucle principale
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        pid_t pid = fork();
        if (pid == 0) {
            close(sockfd);
            handle_client(client_fd, tls_ctx, client_ip);
        } else {
            close(client_fd);
        }
    }

    if (tls_ctx) tls_free(tls_ctx);
    if (log_fp) fclose(log_fp);
    close(sockfd);
    return 0;
}