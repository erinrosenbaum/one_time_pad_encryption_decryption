/*
Erin Rosenbaum
cs_344 winter_2017
March 17, 2017
otp_enc.c

Usage: otp_enc_d <port> &

*/

#include <fcntl.h>     
#include <netinet/in.h>
#include <stdio.h>     
#include <stdlib.h>    
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

// big enough to hold largest plaintext file
#define BUFFER_SIZE 80000
int num_children = 0;

// Signal handler to terminate child processes
static void wait_for_child(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
    num_children--;
}

int main(int argc, char *argv[]){

    struct sigaction sa;
    int listen_socket_fd;
    int newsockfd;
    int port_num;
    socklen_t client_addr_size; // unsigned opaque integral type of length of at least 32 bits
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    char ct_buffer[BUFFER_SIZE];
    char key_buffer[BUFFER_SIZE];
    char code_buffer[16];
    char read_buffer[1024];
    int i;
    int key_file_length;
    int ct_file_length;
    int pid;
    int bytes_sent;
    int bytes_read;
    int encrypted_value;
    int key_value;
    int decrypted_value;
    int code_byte;
  
    // Validate number of arguments 
    if (argc != 2){
        perror("USAGE: otp_dec_d <port> &\n");
        exit(1);
    }

    port_num = atoi(argv[1]);

    // Set up the address struct for server
    memset(&server_address, '\0', sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(port_num);

    // Create listening socket
    if ((listen_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("SERVER ERROR: creating server socket\n");
        exit(1);
    }

    // Enable the socket to begin listening
    if (bind(listen_socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0){
        perror("SERVER ERROR: binding socket\n");
        exit(1);
    }

    // Flip the socket on - it can now receive up to 5 connections
    if (listen(listen_socket_fd, 5) < 0){
        perror("SERVER ERROR upon listen\n");
        exit(1);
    }

    client_addr_size = sizeof(client_address);

    // Set up the signal handler to terminate finished child processes
    sa.sa_handler = wait_for_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("SERVER ERROR: sigaction failed\n");
        return 1;
    }

    // Infinite loop to listen for connections
    while (1){

        if(num_children < 5){
/***********************/

                newsockfd = accept(listen_socket_fd, (struct sockaddr *)&client_address, &client_addr_size);
                if (newsockfd < 0){
                    perror("SERVER ERROR upon accept\n");
                    continue;
                }

                // create child process to do the work
                pid = fork();

                if (pid < 0){
                    perror("SERVER ERROR while forking\n");
                }

                // in child process
                if (pid == 0){
                    // close child process listening socket
                    close(listen_socket_fd);

                    memset(code_buffer, '\0', sizeof(code_buffer));

                    /* recieve a verification code from client. Character 63, '?', was chosen.
                    If a different code is received, the program terminates */
                    code_byte = recv(newsockfd, code_buffer, 1, 0);
                    if (code_byte < 0){
                        perror("SERVER ERROR: Unable to verify sender\n");
                        continue;
                    }

                    if (code_buffer[0] != 63){
                        perror("SERVER ERROR: Terminated due to attempted unauthorized access\n");
                        exit(1);
                    }

                    int temp;
                    bytes_read = read(newsockfd, &temp, sizeof(temp));
                    if (bytes_read < 0){
                        perror("SERVER ERROR reading plaintext file\n");
                        continue;
                    }

                    ct_file_length = ntohl(temp);

                    bytes_read = read(newsockfd, &temp, sizeof(temp));
                    if (bytes_read < 0){
                        perror("SERVER ERROR reading plaintext file\n");
                        continue;
                    }

                    key_file_length = ntohl(temp);

                    while(strstr(ct_buffer, "##") == NULL){
                        memset(read_buffer, '\0', sizeof(read_buffer));
                        bytes_read = read(newsockfd, read_buffer, sizeof(read_buffer - 1)); // Get the next chunk
                        strcat(ct_buffer, read_buffer); // Add that chunk to what we have so far

                        if (bytes_read < 0){
                            perror("SERVER ERROR reading plaintext file\n");
                            continue;
                        }
                    }

                    //send single character acknowledgement to client
                    bytes_sent = write(newsockfd, "!", 1);
                    if (bytes_sent < 0){
                        perror("SERVER ERROR sending acknowledgement\n");
                        continue;
                    }
                    
                    memset(key_buffer, 0, BUFFER_SIZE);

                    while(strstr(key_buffer, "##") == NULL){
                        memset(read_buffer, '\0', sizeof(read_buffer));
                        bytes_read = read(newsockfd, read_buffer, sizeof(read_buffer - 1)); // Get the next chunk
                        strcat(key_buffer, read_buffer); // Add that chunk to what we have so far
                        //printf("PARENT: Message received from child: \"%s\", total: \"%s\"\n", read_buffer, key_buffer);
                        if (bytes_read < 0){
                            perror("SERVER ERROR reading plaintext file\n");
                            continue;
                        }
                    }

                    // Check plaintext file for invalid characters
                    for (i = 0; i < ct_file_length - 1 ; i++){
                        if (ct_buffer[i] > 90 || (ct_buffer[i] < 65 && ct_buffer[i] != 32)){
                            perror("SERVER ERROR: invalid characters in plaintext file\n");
                            exit(1);
                        }
                    }

                    // verify key file is not shorter than plaintext file
                    if (key_file_length < ct_file_length ){ 
                        perror("SERVER ERROR: key is too short\n");
                        exit(1);
                    }

                    // do the decryption by subtracting the strings
                    for(i = 0; i < ct_file_length; i++){
                        if(ct_buffer[i] == ' '){
                            encrypted_value = 0;
                        } else {
                            encrypted_value = ct_buffer[i] - 64;
                        }
                        if(key_buffer[i] == ' '){
                            key_value = 0;
                        } else {
                            key_value = key_buffer[i] - 64;
                        }
                        decrypted_value = encrypted_value - key_value;
                        if(decrypted_value < 0){
                            decrypted_value = decrypted_value + 27;
                        }
                        if(decrypted_value == 0){
                            ct_buffer[i] = ' ';
                        } else {
                            ct_buffer[i] = 64 + decrypted_value;
                        }
                    }

                    // write encrytped text 
                    bytes_sent = write(newsockfd, ct_buffer, ct_file_length);
                    if (bytes_sent < ct_file_length ){
                        perror("SERVER ERROR writing ciphertext to socket\n");
                        exit(2);
                    }

                    close(newsockfd);

                    exit(0);
                }
                // parent process continues to listen in loop
                else close(newsockfd);
            } 


/***********************/
        }


    return 0;
}
/********** EOF *************************************************/