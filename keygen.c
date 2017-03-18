/*
Erin Rosenbaum
cs_344 winter_2017
March 17, 2017
keygen.c

This program creates a key file of random characters of the specified length. 27 characters are allowed, the capital letters and spaces. Use rand(), and last character needs to be a new line character. Output errors to stderr. 

Desired ascii values are 32 (space), and 65-90.

Usage: keygen keylength
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char* argv[]){
  int i, keylength, rand_num;
  int ascii_values[27] = {32,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90};

  if(argc != 2){
    fprintf(stderr, "Usage: keygen keylength\n");
    exit(1);
  }
  keylength = atoi(argv[1]);

  srand(time(NULL));

  for(i = 0; i < keylength; i++){
    rand_num = rand()%27;
    printf("%c", ascii_values[rand_num]);
  }
 
  printf("\n");


}