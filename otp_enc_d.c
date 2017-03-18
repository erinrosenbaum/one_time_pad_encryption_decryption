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

/**********************************************/
int main(int argc, char *argv[]){

    struct sigaction sa;
    int listen_socket_fd;
    int newsockfd;
    int port_num;
    socklen_t client_addr_size; // unsigned opaque integral type of length of at least 32 bits printf
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    char pt_buffer[BUFFER_SIZE];
    char key_buffer[BUFFER_SIZE];
    char code_buffer[16];
    char read_buffer[1024];
    int i;
    int key_file_length;
    int pt_file_length;
    int pid;
    int bytes_sent;
    int bytes_read;
    int pre_encrypt;
    int key_value;
    int encrypted_sum;
    int code_byte;
  
    // Validate number of arguments 
    if (argc != 2){
        perror("USAGE: otp_enc_d <port> &\n");
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

    /* Set socket option to reuse socket addresses 
    allows bind to reuse local addresses*/
    int optval = 1;
    setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));


    // Flip the socket on - it can now receive up to 5 connections
    if (listen(listen_socket_fd, 5) < 0){
        perror("SERVER ERROR upon listen\n");
        exit(1);
    }

    client_addr_size = sizeof(client_address);

/**********************************************/
    // Set up the signal handler to terminate finished child processes
    sa.sa_handler = wait_for_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("SERVER ERROR: sigaction failed\n");
        return 1;
    }
/**********************************************/
    // Infinite loop to listen for connections
    while (1){

        if(num_children < 5){


/***************************************/

            newsockfd = accept(listen_socket_fd, (struct sockaddr *)&client_address, &client_addr_size);
            if (newsockfd < 0){
                perror("SERVER ERROR upon accept\n");
                continue;
            }

            // create child process to do the work
            num_children++;
            pid = fork();

            if (pid < 0){
                perror("SERVER ERROR while forking\n");
            }

            // in child process
            if (pid == 0){
                // close child process listening socket
                close(listen_socket_fd);

                memset(code_buffer, '\0', sizeof(code_buffer));

                /* recieve a verification code from client. Character 64, '@', was chosen.
                If a different code is received, the program terminates */
                code_byte = recv(newsockfd, code_buffer, 1, 0);
                if (code_byte < 0){
                    perror("SERVER ERROR: Unable to verify sender\n");
                    continue;
                }

                if (code_buffer[0] != 64){
                    perror("SERVER ERROR: Terminated due to attempted unauthorized access\n");
                    exit(1);
                }

                int temp;
                bytes_read = read(newsockfd, &temp, sizeof(temp));
                if (bytes_read < 0){
                    perror("SERVER ERROR reading plaintext file\n");
                    continue;
                }

                pt_file_length = ntohl(temp);

                bytes_read = read(newsockfd, &temp, sizeof(temp));
                if (bytes_read < 0){
                    perror("SERVER ERROR reading plaintext file\n");
                    continue;
                }

                key_file_length = ntohl(temp);

                while(strstr(pt_buffer, "##") == NULL){
                    memset(read_buffer, '\0', sizeof(read_buffer));
                    bytes_read = read(newsockfd, read_buffer, sizeof(read_buffer - 1)); // Get the next chunk
                    strcat(pt_buffer, read_buffer); // Add that chunk to what we have so far

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
    /************************************/
                //printf("\nSERVER 1. here\n");
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
                //printf("\nSERVER 2. here\n");
    /************************************/

                // Check plaintext file for invalid characters
                for (i = 0; i < pt_file_length - 1 ; i++){
                    if (pt_buffer[i] > 90 || (pt_buffer[i] < 65 && pt_buffer[i] != 32)){
                        perror("SERVER ERROR: invalid characters in plaintext file\n");
                        exit(1);
                    }
                }

                // verify key file is not shorter than plaintext file
                if (key_file_length < pt_file_length ){ 
                    perror("SERVER ERROR: key is too short\n");
                    exit(1);
                }

                // do the encryption by adding the strings together
                for(i = 0; i < pt_file_length; i++){
                    if(pt_buffer[i] == ' '){
                        pre_encrypt = 0;
                    } else {
                        pre_encrypt = pt_buffer[i] - 64;
                    }
                    if(key_buffer[i] == ' '){
                        key_value = 0;
                    } else {
                        key_value = key_buffer[i] - 64;
                    }
                    encrypted_sum = (pre_encrypt + key_value) % 27;
                    if(encrypted_sum == 0){
                        pt_buffer[i] = ' ';
                    } else {
                        pt_buffer[i] = 64 + encrypted_sum;
                    }
                }

                // write encrytped text 
                bytes_sent = write(newsockfd, pt_buffer, pt_file_length);
                if (bytes_sent < pt_file_length ){
                    perror("SERVER ERROR writing ciphertext to socket\n");
                    exit(2);
                }

                close(newsockfd);

                exit(0);
            }
            // parent process continues to listen in loop
            else{

                close(newsockfd);

            } 
        } 
/*****************************************/
        }

    return 0;

}


/********** EOF *************************************************/