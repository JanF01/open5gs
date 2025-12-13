#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h> // For mkdir
#include <errno.h>
#include <pthread.h>

#define SERVER_IP "10.45.0.1"
#define SERVER_PORT 9500
// Increased backlog for high load
#define BACKLOG 512 
#define BUFFER_SIZE 4096

// Pre-calculate response length to avoid calling strlen() every time
const char *HTTP_RESPONSE = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 0\r\n" 
    "Connection: close\r\n" 
    "\r\n";
const size_t HTTP_RESPONSE_LEN = 88; // Length of the string above

// Structure to pass client info to the thread
typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} client_data_t;

void ensure_directory(const char *path) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    }
    if (mkdir(tmp, S_IRWXU) < 0 && errno != EEXIST) {
        perror("Failed to create directory");
        exit(EXIT_FAILURE);
    }
}

// --- Function to generate RSA Keys (Private & Public) ---
void generate_rsa_keys() {
    const char *dir_path = "./install/etc/open5gs/ssl";
    const char *priv_key_path = "./install/etc/open5gs/ssl/server_rsa_priv.pem";
    const char *pub_key_path  = "./install/etc/open5gs/ssl/server_rsa_pub.pem";
    
    // 1. Create directory
    ensure_directory(dir_path);

    // 2. Generate Private Key
    if (access(priv_key_path, F_OK) != 0) {
        printf("Generating RSA Private Key...\n");
        // 'genpkey' creates the private key
        int status = system("openssl genpkey -algorithm RSA "
                            "-out ./install/etc/open5gs/ssl/server_rsa_priv.pem "
                            "-pkeyopt rsa_keygen_bits:2048 2> /dev/null");
        if (status != 0) {
            fprintf(stderr, "Error: Failed to generate Private Key.\n");
            exit(EXIT_FAILURE);
        }
        printf("Created: %s\n", priv_key_path);
    }

    // 3. Generate Public Key
    if (access(pub_key_path, F_OK) != 0) {
        printf("Extracting RSA Public Key...\n");
        // 'rsa -pubout' derives the public key from the private key
        int status = system("openssl rsa "
                            "-in ./install/etc/open5gs/ssl/server_rsa_priv.pem "
                            "-pubout "
                            "-out ./install/etc/open5gs/ssl/server_rsa_pub.pem 2> /dev/null");
        if (status != 0) {
            fprintf(stderr, "Error: Failed to generate Public Key.\n");
            exit(EXIT_FAILURE);
        }
        printf("Created: %s\n", pub_key_path);
    }
}

void *handle_client(void *arg) {
    client_data_t *data = (client_data_t *)arg;
    int newfd = data->client_fd;
    char buffer[BUFFER_SIZE];

    // Read request (consumes data but ignores content for speed)
    int n = read(newfd, buffer, BUFFER_SIZE - 1);
    
    if (n >= 0) {
        send(newfd, HTTP_RESPONSE, HTTP_RESPONSE_LEN, MSG_NOSIGNAL);
    }

    close(newfd);
    free(data);
    return NULL;
}

int main()
{
    // --- STEP 0: Generate Keys before starting server ---
    generate_rsa_keys();
    int sockfd, newfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int opt = 1;

    // 1. Create TCP socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Set socket options
    // SO_REUSEADDR allows restart without waiting.
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 3. Listen with high backlog
    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("High-Performance Server running on %s:%d\n", SERVER_IP, SERVER_PORT);

    while (1) {
        // 4. Accept connection
        if ((newfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
            perror("accept failed");
            continue;
        }

        // Allocate memory for client data to pass to thread
        client_data_t *data = malloc(sizeof(client_data_t));
        if (!data) {
            perror("malloc failed");
            close(newfd);
            continue;
        }
        data->client_fd = newfd;
        data->client_addr = client_addr;

        // 5. Create a detached thread to handle the client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)data) != 0) {
            perror("pthread_create failed");
            close(newfd);
            free(data);
        } else {
            // Detach thread so resources are freed automatically when it finishes
            pthread_detach(thread_id);
        }
    }

    close(sockfd);
    return 0;
}