#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "interface.h"
#define PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

int main(int argc, char const *argv[])
{
  Grid g;
  g.printGrid();
  cin.get();
  g.setCell(1,2, blue);
  g.printGrid();
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
	return 0;
}
