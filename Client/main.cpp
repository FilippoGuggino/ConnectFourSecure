#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <vector>
#include "interface.h"

#define PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

int connect(int &sock){
     int ret = 0;

     sock = 0;
     int valread = 0;
     struct sockaddr_in serv_addr;


     if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
     {
          printf("\n Socket creation error \n");
          return -1;
     }

     serv_addr.sin_family = AF_INET;
     serv_addr.sin_port = htons(PORT);

     // Convert IPv4 and IPv6 addresses from text to binary form
     if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
     {
          printf("\nInvalid address/ Address not supported \n");
          return -1;
     }

     if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
     {
          printf("\nConnection Failed \n");
          return -1;
     }

     /*struct sockaddr_in my_addr;
     unsigned int len = sizeof(struct sockaddr_in);
     getsockname(sock, (struct sockaddr *) &my_addr, &len);
     cout<<"my port is: "<<ntohs(my_addr.sin_port)<<endl;*/

     return sock;
}

int main(int argc, char const *argv[])
{
     int sock;
     connect(sock);
     /*vector<string> prova;
     prova.push_back("giovanni");
     prova.push_back("francesco");
     prova.push_back("emilia");

     BaseInterface* aCurrentMenu = new FirstMenu(prova); // We have a pointer to our menu. We're using a pointer so we can change the menu seamlessly.
     bool isQuitOptionSelected = false;
     while (!isQuitOptionSelected) // We're saying that, as long as the quit option wasn't selected, we keep running
     {
     aCurrentMenu->printText(); // This will call the method of whichever MenuObject we're using, and print the text we want to display

     int choice = 0; // Always initialise variables, unless you're 100% sure you don't want to.
     cin >> choice;

     BaseInterface* aNewMenuPointer = aCurrentMenu->getNextMenu(choice, isQuitOptionSelected); // This will return a new object, of the type of the new menu we want. Also checks if quit was selected

     if (aNewMenuPointer && aNewMenuPointer != aCurrentMenu) // This is why we set the pointer to 0 when we were creating the new menu - if it's 0, we didn't create a new menu, so we will stick with the old one
     {
     delete aCurrentMenu; // We're doing this to clean up the old menu, and not leak memory.
     aCurrentMenu = aNewMenuPointer; // We're updating the 'current menu' with the new menu we just created
}
}*/


/*INTERRUPT DRIVEN CONNECTION
int io_handler(), on;
pid_t pgrp;

on=1;
signal(SIGIO, io_handler);

// Set the process receiving SIGIO/SIGURG signals to us

pgrp=getpid();
if (ioctl(s, SIOCSPGRP, &pgrp) < 0) {
perror("ioctl F_SETOWN");
exit(1);
}

// Allow receipt of asynchronous I/O signals

if (ioctl(s, FIOASYNC, &on) < 0) {
perror("ioctl F_SETFL, FASYNC");
exit(1);
}*/


/*Grid g;
g.printGrid();
cin.get();
g.setCell(1,2, blue);
g.printGrid();*/
/*
int ret = 0;

int sock = 0, valread;
struct sockaddr_in serv_addr;
char buffer[BUFFER_SIZE] = {0};
cin>>buffer;
int clear_size = strlen(buffer);
unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
memcpy(clear_buf, buffer, clear_size);

cout<<"clear text: " <<clear_buf<< endl;
cout<<"clear size: " <<clear_size<<endl;
if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
{
printf("\n Socket creation error \n");
return -1;
}

serv_addr.sin_family = AF_INET;
serv_addr.sin_port = htons(PORT);

// Convert IPv4 and IPv6 addresses from text to binary form
if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
{
printf("\nInvalid address/ Address not supported \n");
return -1;
}

if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
{
printf("\nConnection Failed \n");
return -1;
}


// declare some useful variables:
char buffer[BUFFER_SIZE] = {0};
cin>>buffer;
int clear_size = strlen(buffer);
unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
memcpy(clear_buf, buffer, clear_size);

const EVP_CIPHER* cipher = EVP_aes_128_cbc();
int iv_len = EVP_CIPHER_iv_length(cipher);
int block_size = EVP_CIPHER_block_size(cipher);

// Assume key is hard-coded (this is not a good thing, but it is not our focus right now)
unsigned char *key = (unsigned char *)"0123456789012345";
// Allocate memory for and randomly generate IV:
unsigned char* iv = (unsigned char*)malloc(iv_len);
// Seed OpenSSL PRNG
RAND_poll();
// Generate 16 bytes at random. That is my IV
RAND_bytes((unsigned char*)&iv[0],iv_len);

// check for possible integer overflow in (clear_size + block_size) --> PADDING!
// (possible if the plaintext is too big, assume non-negative clear_size and block_size):
if(clear_size > INT_MAX - block_size) { cerr <<"Error: integer overflow (file too big?)\n"; exit(1); }
// allocate a buffer for the ciphertext:
int enc_buffer_size = clear_size + block_size;
unsigned char* cphr_buf = (unsigned char*) malloc(enc_buffer_size);
if(!cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

//Create and initialise the context with used cipher, key and iv
EVP_CIPHER_CTX *ctx;
ctx = EVP_CIPHER_CTX_new();
if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
ret = EVP_EncryptInit(ctx, cipher, key, iv);
cout<<"iv: "<<iv<<endl;
if(ret != 1){
cerr <<"Error: Encrypt Init Failed\n";
exit(1);
}
int update_len = 0; // bytes encrypted at each chunk
int total_len = 0; // total encrypted bytes

// Encrypt Update: one call is enough because our file is small.
//TODO while
ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
if(ret != 1){
cerr <<"Error: EncryptUpdate Failed\n";
exit(1);
}
total_len += update_len;
cout<<"partial: "<<total_len<<endl;

//Encrypt Final. Finalize the encryption and adds the padding
ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
if(ret != 1){
cerr <<"Error: EncryptFinal Failed\n";
exit(1);
}
total_len += update_len;
int cphr_size = total_len;

// delete the context and the plaintext from memory:
EVP_CIPHER_CTX_free(ctx);
// Telling the compiler it MUST NOT optimize the following instruction.
// With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
free(clear_buf);

// write the IV and the ciphertext into a '.enc' file:

string cphr_file_name = "iv.enc";
FILE* cphr_file = fopen(cphr_file_name.c_str(), "wb");
if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }

ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
if(ret < EVP_CIPHER_iv_length(cipher)) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }

fclose(cphr_file);

send(sock , cphr_buf , cphr_size , 0 );
cout<<"crypted: " << cphr_buf<<endl;
cout<<"crypted size: "<< cphr_size<<endl;


// deallocate buffers:
free(cphr_buf);
free(iv);

cin.get();*/
cin.get();
close(sock);

return 0;
}
