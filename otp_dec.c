/*
Erin Rosenbaum
cs_344 winter_2017
March 17, 2017
otp_enc.c

Usage: otp_enc <plaintext> <key> <port>

*/

#include <arpa/inet.h>
#include <fcntl.h>     
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>     
#include <stdlib.h>    
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <unistd.h>

// large enough to hold largest plaintext file
#define BUFFER_SIZE 80000

int main(int argc, char *argv[]){

    int client_socket;
    int port_num;
    struct sockaddr_in server_address;
    struct hostent *server_host_info;
    char ct_buffer[BUFFER_SIZE];
    char key_buffer[BUFFER_SIZE];
    char code_buffer[16];
    char read_buffer[1024];
    int ct_fd;
    int key_fd;
    int i;
    int key_file_size;
    int bytes_received;
    int bytes_sent;
    int ct_file_size;
    char* code = "?";
    char* terminator = "##";

    // Verify Number of Arguments
    if (argc != 4){
        perror("USAGE: otp_enc <plaintext file> <key file> <port>\n");
        exit(1);
    }

    port_num = atoi(argv[3]);

    // open plaintext file and validate contents
    ct_fd = open(argv[1], O_RDONLY);

    if (ct_fd < 0){
        perror("CLIENT ERROR: cannot open plaintext file\n");
        exit(1);
    }

    memset(ct_buffer, '\0', sizeof(ct_buffer));

    ct_file_size  = lseek(ct_fd, 0, SEEK_END);
    //printf("ct_file_size: %d\n", ct_file_size);

    // reset file pointers to beginning of files
    lseek(ct_fd, 0, SEEK_SET);

    read(ct_fd, ct_buffer, BUFFER_SIZE);

    // validate that plaintext file only contains legal characters
    for (i = 0; i < ct_file_size - 1; i++){
        if ((ct_buffer[i] > 90 || ct_buffer[i] < 65 && ct_buffer[i] != 32)){
            perror("CLIENT ERROR: invalid characters in plaintext file\n");
            //printf("\nN: %d \n", i);
            exit(1);
        }
    }


    close(ct_fd);

    // open key file, validate contents, and get length
    memset(key_buffer, '\0', sizeof(key_buffer));
    key_fd = open(argv[2], O_RDONLY);
    key_file_size = lseek(key_fd, 0, SEEK_END);
    
    //printf("key_file_size: %d\n", key_file_size);
    
    lseek(key_fd, 0, SEEK_SET);
    
    if (key_fd < 0){
        perror("CLIENT ERROR: cannot open key file\n");
        exit(1);
    }

    // Get contents of file
    bytes_received = read(key_fd, key_buffer, BUFFER_SIZE);

    close(key_fd);

    // verify key file is not shorter than plaintext file
    if (key_file_size < ct_file_size){
        perror("CLIENT ERROR: key file is not long enough\n");
        exit(1);
    }

    // Create client socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0){
        perror("CLIENT ERROR: could not create socket\n");
        exit(2);
    }

    server_host_info = gethostbyname("localhost");
    if (server_host_info == NULL){
        perror("CLIENT ERROR: could not get host info\n");
        exit(2);
    }    
  
    // Set up the address struct for client
    memset(&server_address, '\0', sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(port_num);

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0){
        fprintf(stderr, "\nCLIENT ERROR: unable to connect to server on port %d\n", port_num);
        exit(2);
    }

    // code to identify client to server
    memset(code_buffer, '\0', sizeof(code_buffer));
    strncpy(code_buffer, code, 2);

    // send code to server
    bytes_sent = write(client_socket, code_buffer, 1);
    if (bytes_sent < 0){
        perror("CLIENT ERROR: could not send identification code\n");
        exit(1);
    }

    // send length of plaintext file to server
    // reference: http://stackoverflow.com/questions/9140409/transfer-integer-over-a-socket-in-c
    memset(code_buffer, '\0', sizeof(code_buffer));
    int tmp = htonl(ct_file_size);
    bytes_sent = write(client_socket, &tmp, sizeof(tmp));
    if (bytes_sent < 0){
        perror("CLIENT ERROR: could not send file size\n");
        exit(1);
    }

    /* send length of key file to server so that it knows how much 
    data to expect */
    memset(code_buffer, '\0', sizeof(code_buffer));
    tmp = htonl(key_file_size);
    bytes_sent = write(client_socket, &tmp, sizeof(tmp));
    if (bytes_sent < 0){
        perror("CLIENT ERROR: could not send file size\n");
        exit(1);
    }

    // replace newline character and add terminator to files
    ct_buffer[strcspn(ct_buffer, "\n")] = 0;
    strcat(ct_buffer, terminator);

    key_buffer[strcspn(key_buffer, "\n")] = 0;
    strcat(key_buffer, terminator);

    // write the input file
    bytes_sent = write(client_socket, ct_buffer, ct_file_size + 1);
    if (bytes_sent < ct_file_size - 1){
        perror("CLIENT ERROR: could not send all plaintext data\n");
    }

    // get acknowledgement from server
    memset(code_buffer, '\0', sizeof(code_buffer));
    bytes_received = read(client_socket, code_buffer, 1);
    if (bytes_received < 0){
       perror("CLIENT ERROR: unable to receive acknowledgement\n");
    }

    // write key to socket
    bytes_sent = write(client_socket, key_buffer, key_file_size + 2);
    if (bytes_sent < key_file_size - 1){
        perror("CLIENT ERROR: not all key data sent\n");
    }

    //printf("\n4. Client. here: bytes_sent: %d\n", bytes_sent);
    memset(ct_buffer, '\0', BUFFER_SIZE);

    bytes_received = read(client_socket, ct_buffer, ct_file_size - 1);
    //printf("\n5. Client. here: bytes_sent: %d\n", bytes_sent);
    if (bytes_received < 0){
       perror("CLIENT ERROR: reading encrypted text");
       exit(2);
    }

    // Print to console
    for (i = 0; i < ct_file_size - 1; i++){
        printf("%c", ct_buffer[i]);
    }
    printf("\n");

    // close socket
    close(client_socket);

    return 0;
}
/******** EOF **************************************************/