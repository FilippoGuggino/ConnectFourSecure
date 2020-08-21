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

// SERVER SESSION KEY GENERATION

static DH *get_dh2048_auto(void)
{
    static unsigned char dhp_2048[] = {
        0xF9, 0xEA, 0x2A, 0x73, 0x80, 0x26, 0x19, 0xE4, 0x9F, 0x4B,
        0x88, 0xCB, 0xBF, 0x49, 0x08, 0x60, 0xC5, 0xBE, 0x41, 0x42,
        0x59, 0xDB, 0xEC, 0xCA, 0x1A, 0xC9, 0x90, 0x9E, 0xCC, 0xF8,
        0x6A, 0x3B, 0x60, 0x5C, 0x14, 0x86, 0x19, 0x09, 0x36, 0x29,
        0x39, 0x36, 0x21, 0xF7, 0x55, 0x06, 0x1D, 0xA3, 0xED, 0x6A,
        0x16, 0xAB, 0xAA, 0x18, 0x2B, 0x29, 0xE9, 0x64, 0x48, 0x67,
        0x88, 0xB4, 0x80, 0x46, 0xFD, 0xBF, 0x47, 0x17, 0x91, 0x4A,
        0x9C, 0x06, 0x0A, 0x58, 0x23, 0x2B, 0x6D, 0xF9, 0xDD, 0x1D,
        0x93, 0x95, 0x8F, 0x76, 0x70, 0xC1, 0x80, 0x10, 0x4B, 0x3D,
        0xAC, 0x08, 0x33, 0x7D, 0xDE, 0x38, 0xAB, 0x48, 0x7F, 0x38,
        0xC4, 0xA6, 0xD3, 0x96, 0x4B, 0x5F, 0xF9, 0x4A, 0xD7, 0x4D,
        0xAE, 0x10, 0x2A, 0xD9, 0xD3, 0x4A, 0xF0, 0x85, 0x68, 0x6B,
        0xDE, 0x23, 0x9A, 0x64, 0x02, 0x2C, 0x3D, 0xBC, 0x2F, 0x09,
        0xB3, 0x9E, 0xF1, 0x39, 0xF6, 0xA0, 0x4D, 0x79, 0xCA, 0xBB,
        0x41, 0x81, 0x02, 0xDD, 0x30, 0x36, 0xE5, 0x3C, 0xB8, 0x64,
        0xEE, 0x46, 0x46, 0x5C, 0x87, 0x13, 0x89, 0x85, 0x7D, 0x98,
        0x0F, 0x3C, 0x62, 0x93, 0x83, 0xA0, 0x2F, 0x03, 0xA7, 0x07,
        0xF8, 0xD1, 0x2B, 0x12, 0x8A, 0xBF, 0xE3, 0x08, 0x12, 0x5F,
        0xF8, 0xAE, 0xF8, 0xCA, 0x0D, 0x52, 0xBC, 0x37, 0x97, 0xF0,
        0xF5, 0xA7, 0xC3, 0xBB, 0xC0, 0xE0, 0x54, 0x7E, 0x99, 0x6A,
        0x75, 0x69, 0x17, 0x2D, 0x89, 0x1E, 0x64, 0xE5, 0xB6, 0x99,
        0xCE, 0x84, 0x08, 0x1D, 0x89, 0xFE, 0xBC, 0x80, 0x1D, 0xA1,
        0x14, 0x1C, 0x66, 0x22, 0xDA, 0x35, 0x1D, 0x6D, 0x53, 0x98,
        0xA8, 0xDD, 0xD7, 0x5D, 0x99, 0x13, 0x19, 0x3F, 0x58, 0x8C,
        0x4F, 0x56, 0x5B, 0x16, 0xE8, 0x59, 0x79, 0x81, 0x90, 0x7D,
        0x7C, 0x75, 0x55, 0xB8, 0x50, 0x63
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

int handleErrorsDH(){
	printf("An error has occured during DH processing \n");
	//exit(1);
}


void serverSessionKeyGeneration(int &socket){

 //DH
  EVP_PKEY* dhparams;
  if(NULL == (dhparams = EVP_PKEY_new())) handleErrorsDH();
  DH* temp = get_dh2048_auto();
  if(1 != EVP_PKEY_set1_DH(dhparams,temp)) handleErrorsDH();
  DH_free(temp);


  EVP_PKEY_CTX* DHctx = EVP_PKEY_CTX_new(dhparams,NULL); //handle errors
  EVP_PKEY* dh_prv_key = NULL;
  EVP_PKEY_keygen_init(DHctx);
  EVP_PKEY_keygen(DHctx,&dh_prv_key);

  int dh_prv_key_size =  EVP_PKEY_size(dh_prv_key);
  cout<<dh_prv_key_size<<"<>"<<dh_prv_key<<"\n";

  cout << "Sending DH public key to client \n";

  BIO* mbio=BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(mbio,dh_prv_key);
  char* pubkey_buf = NULL;
  long pubkey_size = BIO_get_mem_data(mbio,&pubkey_buf);
  send(socket, &pubkey_size, sizeof(long) , 0 ); //dimensione messaggio
  send(socket, pubkey_buf,pubkey_size, 0);
  BIO_free(mbio);

  long peer_pubkey_size;

  //size of  message is received
  int valread;
  if ((valread = recv( socket , &peer_pubkey_size, sizeof(long),0)) == 0)
  {
    exit(1);
  }

  unsigned char* peer_pubkey_buf =(unsigned char*)malloc(peer_pubkey_size);

  cout<<peer_pubkey_size<<"\n";

  //message received
  if (valread = recv( socket , peer_pubkey_buf, peer_pubkey_size,MSG_WAITALL) == 0)
  {
    exit(1);
  }

  BIO* peer_mbio = BIO_new(BIO_s_mem());
  BIO_write(peer_mbio, peer_pubkey_buf, peer_pubkey_size);
  EVP_PKEY* peer_pubkey=PEM_read_bio_PUBKEY(peer_mbio,NULL,NULL,NULL);
  BIO_free(peer_mbio);




  cout<<peer_pubkey_size<<"<>"<<peer_pubkey<<"\n";

  printf("Starting DH process inside Client\n"); //debug


  EVP_PKEY_CTX *der_ctx;
  unsigned char *skey;
  size_t skeylen;
  der_ctx = EVP_PKEY_CTX_new(dh_prv_key,NULL);


  if (!der_ctx) handleErrorsDH();
  if (EVP_PKEY_derive_init(der_ctx) <= 0) handleErrorsDH();
  //Setting the peer with its pubkey
  if (EVP_PKEY_derive_set_peer(der_ctx, peer_pubkey) <= 0) handleErrorsDH();
  // Determine buffer length, by performing a derivation but writing the result nowhere
  EVP_PKEY_derive(der_ctx, NULL, &skeylen);
  //allocate buffer for the shared secret
  skey = (unsigned char*)(malloc(int(skeylen)));
  if (!skey) handleErrorsDH();
  //Perform again the derivation and store it in skey buffer
  if (EVP_PKEY_derive(der_ctx, skey, &skeylen) <= 0) handleErrorsDH();

  //debug
  printf("Here it is the shared secret: \n");
  BIO_dump_fp (stdout, (const char *)skey, skeylen);

  //ATTENZIONEEEEEEEEEEEEEEEEEEEEEEEE
  /*WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
   * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
   * IN NEXT LABORATORY LESSON WE ADDRESS HASHING!

  //FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
*/
  unsigned char* hashed_secret;
  unsigned int hashed_secret_len;
  EVP_MD_CTX *Hctx;
  Hctx = EVP_MD_CTX_new();
  //allocate memory
  hashed_secret = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
  //init, Update (only once) and finalize digest
  EVP_DigestInit(Hctx, EVP_sha256());
  EVP_DigestUpdate(Hctx, (unsigned char*)skey, skeylen);
  EVP_DigestFinal(Hctx, hashed_secret, &hashed_secret_len);


  //REMEMBER TO FREE CONTEXT!!!!!!
  EVP_MD_CTX_free(Hctx);
  EVP_PKEY_CTX_free(der_ctx);
  EVP_PKEY_free(peer_pubkey);
  EVP_PKEY_free(dh_prv_key);
  EVP_PKEY_CTX_free(DHctx);
  EVP_PKEY_free(dhparams);

}

int main(int argc, char const *argv[])
{
     int sock;
     connect(sock);
     serverSessionKeyGeneration(sock);
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
