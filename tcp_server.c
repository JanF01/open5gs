#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h> // Include pthread library

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

// Thread function to handle the client
void *handle_client(void *arg) {
    client_data_t *data = (client_data_t *)arg;
    int newfd = data->client_fd;
    char buffer[BUFFER_SIZE];

    // Optional: Only enable detailed logging for debugging, otherwise it slows down fast I/O
    // char client_ip[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &data->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    // Read client request (Blocking, but only blocks THIS thread, not the server)
    int n = read(newfd, buffer, BUFFER_SIZE - 1);
    
    // Check if read was successful (we don't strictly need to parse the content for this dummy server)
    if (n >= 0) {
        // Send HTTP 200 OK response
        // Using MSG_NOSIGNAL prevents crash if client disconnects prematurely
        send(newfd, HTTP_RESPONSE, HTTP_RESPONSE_LEN, MSG_NOSIGNAL);
    }

    // Clean up
    close(newfd);
    free(data); // Free the memory allocated in main loop
    return NULL;
}

int main()
{
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