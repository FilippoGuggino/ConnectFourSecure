#include <unistd.h>
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <vector>
#include <sys/ioctl.h>
#include <thread>

#define MAX_CLIENTS 30
#define PORT 8080

using namespace std;

//utility function that allows to get a fix-sized string from nonce
string toString(string s){

  for(int i=strlen(s.c_str());i<10;i++){  //10 is the max number of digits of nonce
    s='0'+s;
  }
  return s;
}
/*
void generateNonce(unsigned int* nonce){
// Allocate memory for a randomly generate NONCE:
nonce= (unsigned int*)malloc(sizeof(uint32_t));
// Seed OpenSSL PRNG
RAND_poll();
// Generate 4 bytes at random. That is my NONCE
RAND_bytes((unsigned char*)&nonce[0],sizeof(uint32_t));
}
*/
void send_digital_signature(int sock,unsigned char* clear_buf,unsigned int clear_size){
  int ret;

  // load my private key:
  string prvkey_file_name="Server/ConnectFourServer_prvkey.pem";
  FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
  if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; return; }
  EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
  fclose(prvkey_file);
  if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; exit(1); }

  // declare some useful variables:
  const EVP_MD* md = EVP_sha256();


  // create the signature context:
  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

  // allocate buffer for signature:
  unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
  if(!sgnt_buf) { cerr << "Error: malloc returned NULL (signature too big?)\n"; exit(1); }

  // sign the plaintext:
  // (perform a single update on the whole plaintext,
  // assuming that the plaintext is not huge)
  ret = EVP_SignInit(md_ctx, md);
  if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); }
  ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
  if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
  unsigned int sgnt_size;
  ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
  if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); }

  cout<<sgnt_size<<endl;
  send(sock , sgnt_buf , sgnt_size , 0 );


  // delete the digest and the private key from memory:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(prvkey);

  // deallocate buffers:
  // free(clear_buf);  --> not necessary since it hasn't been allocated in heap
  free(sgnt_buf);
}

bool verify_client_signature(string username,unsigned char* sgnt_buf,unsigned int sgnt_size,string client_nonce){

  int ret;

  // load the client's public key:
  string pubkey_file_name="Server/"+username+"_pubkey.pem";
  FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
  if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; return false; }
  EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
  fclose(pubkey_file);
  if(!pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; return false; }

  // declare some useful variables:
  const EVP_MD* md = EVP_sha256();

  //create the plaintext
  string s=username+client_nonce;
  unsigned char* clear_buf=(unsigned char*)s.c_str();
  unsigned int clear_size=strlen((const char*)clear_buf);

  // create the signature context:
  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return false; }

  // verify the plaintext:
  // (perform a single update on the whole plaintext)
  ret = EVP_VerifyInit(md_ctx, md);
  if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; return false; }
  ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
  if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; return false; }
  ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pubkey);
  if(ret != 1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
    cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
    exit(1);
  }

  // deallocate buffers:
  //   free(clear_buf);
  free(sgnt_buf);
  EVP_PKEY_free(pubkey);
  EVP_MD_CTX_free(md_ctx);
  return true;
}

int handleErrorsDH(){
	printf("An error has occured during DH processing \n");
	exit(1);
}

void sendCertificate(int sock){
  int ret;
  // open the certificate file:
  string cert_file_name="Server/ConnectFourServer_cert.pem";
  FILE* cert_file = fopen(cert_file_name.c_str(), "r");
  if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; return; }

  // get the certificate size:
  // (assuming no failures in fseek() and ftell())
  //TODO we can't assume any failure
  fseek(cert_file, 0, SEEK_END);
  long int cert_size = ftell(cert_file);
  fseek(cert_file, 0, SEEK_SET);

  //read the certificate
  unsigned char* cert_buf = (unsigned char*)malloc(cert_size);
  ret=fread(cert_buf, 1, cert_size, cert_file);
  if(ret < cert_size) { cerr << "Error while reading file '" << cert_file_name << "'\n"; exit(1); }
  fclose(cert_file);

  send(sock , (const char*)&cert_size , sizeof(uint32_t) , 0 );  //certificate size
  send(sock , cert_buf , cert_size , 0 );
}

bool handleAuthentication(int sd){
  int valread = 0;
  ///*AUTHENTICATION WITH CLIENT*///

  // Seed OpenSSL PRNG
  uint32_t* server_nonce = (uint32_t*)malloc(sizeof(uint32_t));
  RAND_poll();
  RAND_bytes((unsigned char*)&server_nonce[0],sizeof(uint32_t));
  cout<<"server_nonce: "<<*server_nonce<<endl;

  //nonce generated by the client is received
  unsigned int client_nonce;
  if ((valread = read( sd , &client_nonce, sizeof(uint32_t))) == 0)
  {
    cout<<"client disconnected"<<endl;
    return false;
  }
  else
  cout<<"client_nonce: "<<client_nonce<<endl;
  // generated nonce is sent to the server
  send(sd , server_nonce , sizeof(uint32_t) , 0 );

  //Digital signature + certificate must be sent to the client for authentication
  sendCertificate(sd);
  string s = toString(to_string(*server_nonce));
  unsigned char* clear_buf = (unsigned char*)s.c_str();
  int clear_size=strlen((const char*)clear_buf);
  send_digital_signature(sd, clear_buf, clear_size);
  //authenticate_to_client(sd,toString(to_string(*server_nonce))); //to_string() to get variable size string from int.toString() to get fixed size string from variable string.

  //digital signature from the client must be verified.

  //size of next message is received
  unsigned int client_sign_size;
  if ((valread = read( sd , &client_sign_size, sizeof(uint32_t))) == 0)
  {
    cout<<"client disconnected"<<endl;
    return false;
  }
  //digital signature of the client is received.
  unsigned char* client_sign= (unsigned char*)malloc(client_sign_size);
  if ((valread = read( sd , client_sign, client_sign_size)) == 0)
  {
    cout<<"client disconnected"<<endl;
    return false;
  }

  //size of next message is received
  unsigned int size;
  if ((valread = read( sd , &size, sizeof(uint32_t))) == 0)
  {
    cout<<"client disconnected"<<endl;
    return false;
  }


  //username of the client is received
  unsigned char* username= (unsigned char*)malloc(size);
  if ((valread = read( sd , username, size)) == 0)
  {
    cout<<"client disconnected"<<endl;
    return false;
  }

  unsigned char* uc;
  string str( reinterpret_cast<char const*>(username), valread ) ;
  if(verify_client_signature(str,client_sign,client_sign_size,toString(to_string(client_nonce)))==false)
    return false;
  cout<<"Client authentication completed!"<<endl;

  // create the plaintext to be signed

  s="EndAuthentication"+toString(to_string(*server_nonce));
  cout<<"plaintext da segnare:"<<s<<endl;
  clear_buf=(unsigned char*)s.c_str();
  clear_size=strlen((const char*)clear_buf);

  send_digital_signature(sd,clear_buf,clear_size);

  cout<<"Authentication completed!"<<endl;
  return true;
}

void serverSessionKeyGeneration(int &socket){


  printf("DH: param phase \n"); //debug
 //DH

  EVP_PKEY* dhparams;
  if(NULL == (dhparams = EVP_PKEY_new())) handleErrorsDH();
  DH* temp = get_dh2048_auto();
  if(1 != EVP_PKEY_set1_DH(dhparams,temp)) handleErrorsDH();
  DH_free(temp);

  printf("DH: param 2 phase \n"); //debug

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
  send(socket, pubkey_buf,pubkey_size,0);
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

  printf("Starting DH process inside the server \n"); //debug


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


void handleClient(int sd){
  if(handleAuthentication(sd) == false)
    cout<<"Authentication Error, abort connection"<<endl;

}

int main(int argc, char const *argv[])
{
  int opt = 1;
  int master_socket , addrlen , new_socket;
  int max_sd;
  struct sockaddr_in address;

  //set of socket descriptors
  fd_set readfds;

  //create a master socket
  if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)
  {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  //set master socket to allow multiple connections ,
  //this is just a good habit, it will work without this
  if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
  sizeof(opt)) < 0 )
  {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  //type of socket created
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons( PORT );

  //bind the socket to localhost port 8888
  if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }
  printf("Listener on port %d \n", PORT);

  //try to specify maximum of 3 pending connections for the master socket
  if (listen(master_socket, 3) < 0)
  {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  //accept the incoming connection
  addrlen = sizeof(address);
  puts("Waiting for connections ...");

  while(true){

    if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0){
      perror("accept");
      exit(EXIT_FAILURE);
    }


    //inform user of socket number - used in send and receive commands
    printf("New connection , socket fd is %d , ip is : %s , port : %d\n" ,
    new_socket ,
    inet_ntoa(address.sin_addr) ,
    ntohs(address.sin_port));

    puts("Welcome message sent successfully");

    thread (handleClient, new_socket).detach();

}

//else its some IO operation on some other socket
/*for (i = 0; i < MAX_CLIENTS; i++)
{
sd = client_socket[i];

if (FD_ISSET( sd , &readfds))
{
//Check if it was for closing , and also read the
//incoming message
if ((valread = read( sd , buffer, 1024)) == 0)
{

//Somebody disconnected , get his details and print
getpeername(sd , (struct sockaddr*)&address ,
(socklen_t*)&addrlen);
printf("Host disconnected , ip %s , port %d \n" ,
inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
cout<<"socket disconnesso: "<<sd<<endl;

//Close the socket and mark as 0 in list for reuse
close( sd );
client_socket[i] = 0;
}

//Echo back the message that came in
else
{
     int opt = 1;
     int master_socket , addrlen , new_socket , client_socket[30] ,
     max_clients = 30 , activity, i , valread , sd;
     int max_sd;
     struct sockaddr_in address;
     struct sockaddr_in connected_users[30] = {NULL};

     char buffer[1024] = {0};  //data buffer of 1K

     //set of socket descriptors
     fd_set readfds;

     //initialise all client_socket[] to 0 so not checked
     for (i = 0; i < max_clients; i++)
     {
          client_socket[i] = 0;
     }

     //create a master socket
     if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)
     {
          perror("socket failed");
          exit(EXIT_FAILURE);
     }

     //set master socket to allow multiple connections ,
     //this is just a good habit, it will work without this
     if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
     sizeof(opt)) < 0 )
     {
          perror("setsockopt");
          exit(EXIT_FAILURE);
     }

     //type of socket created
     address.sin_family = AF_INET;
     address.sin_addr.s_addr = INADDR_ANY;
     address.sin_port = htons( PORT );

     //bind the socket to localhost port 8888
     if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)
     {
          perror("bind failed");
          exit(EXIT_FAILURE);
     }
     printf("Listener on port %d \n", PORT);

     //try to specify maximum of 3 pending connections for the master socket
     if (listen(master_socket, 3) < 0)
     {
          perror("listen");
          exit(EXIT_FAILURE);
     }

     //accept the incoming connection
     addrlen = sizeof(address);
     puts("Waiting for connections ...");

     while(true){
          //clear the socket set
          FD_ZERO(&readfds);

          //add master socket to set
          FD_SET(master_socket, &readfds);
          max_sd = master_socket;

          //add child sockets to set
          for ( i = 0 ; i < max_clients ; i++)
          {
               //socket descriptor
               sd = client_socket[i];

               //if valid socket descriptor then add to read list
               if(sd > 0)
               FD_SET( sd , &readfds);

               //highest file descriptor number, need it for the select function
               if(sd > max_sd)
               max_sd = sd;
          }

          //wait for an activity on one of the sockets , timeout is NULL ,
          //so wait indefinitely
          activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);

          if ((activity < 0) && (errno!=EINTR))
          {
               printf("select error");
          }

          //If something happened on the master socket ,
          //then its an incoming connection
          if (FD_ISSET(master_socket, &readfds))
          {
               if ((new_socket = accept(master_socket,
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
                    {
                         perror("accept");
                         exit(EXIT_FAILURE);
                    }

                    //inform user of socket number - used in send and receive commands
                    printf("New connection , socket fd is %d , ip is : %s , port : %d\n" ,
                    new_socket ,
                    inet_ntoa(address.sin_addr) ,
                    ntohs(address.sin_port));

                    serverSessionKeyGeneration(new_socket);

                    //send new connection greeting message
                    /*if( send(new_socket, message, strlen(message), 0) != strlen(message) )
                    {
                    perror("send");
               }*/

               puts("Welcome message sent successfully");

               //add new socket to array of sockets
               for (i = 0; i < max_clients; i++)
               {
                    //if position is empty
                    if( client_socket[i] == 0 )
                    {
                         client_socket[i] = new_socket;
                         connected_users[i] = address;

                         for(int i = 0 ; i < 30; i++){
                              cout<<inet_ntoa(connected_users[i].sin_addr) <<"     "<<ntohs(connected_users[i].sin_port)<<endl;
                         }

                         printf("Adding to list of sockets as %d\n" , i);

                         break;
                    }
               }
          }

          //else its some IO operation on some other socket
          for (i = 0; i < max_clients; i++)
          {
               sd = client_socket[i];

               if (FD_ISSET( sd , &readfds))
               {
                    cout<<"vuole disconnettersi"<<endl;
                    //Check if it was for closing , and also read the
                    //incoming message
                    if ((valread = read( sd , buffer, 1024)) == 0)
                    {
                         //Somebody disconnected , get his details and print
                         getpeername(sd , (struct sockaddr*)&address ,
                         (socklen_t*)&addrlen);
                         printf("Host disconnected , ip %s , port %d \n" ,
                         inet_ntoa(address.sin_addr) , ntohs(address.sin_port));

                         //Close the socket and mark as 0 in list for reuse
                         close( sd );
                         client_socket[i] = 0;
                    }

                    //Echo back the message that came in
                    else
                    {
                         //set the string terminating NULL byte on the end
                         //of the data read
                         buffer[valread] = '\0';
                         send(sd , buffer , strlen(buffer) , 0 );
                    }
               }
          }
     }
     //authentication by Public Key

     //send certificate to client

     cin.get();
     cin.get();


     return 0;
}

/**
BACKUP

int ret; // used for return values
unsigned char *key = (unsigned char *)"0123456789012345";

int server_fd, new_socket, valread;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);
char buffer[1024] = {0};
const char* hello = "Hello from server";

// Creating socket file descriptor
if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
{
perror("socket failed");
exit(EXIT_FAILURE);
}

// Forcefully attaching socket to the port 8080
if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
&opt, sizeof(opt)))
{
perror("setsockopt");
exit(EXIT_FAILURE);
}
address.sin_family = AF_INET;
address.sin_addr.s_addr = INADDR_ANY;
address.sin_port = htons( PORT );

// Forcefully attaching socket to the port 8080
if (bind(server_fd, (struct sockaddr *)&address,
sizeof(address))<0)
{
perror("bind failed");
exit(EXIT_FAILURE);
}
if (listen(server_fd, 3) < 0)
{
perror("listen");
exit(EXIT_FAILURE);
}
if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
(socklen_t*)&addrlen))<0)
{
perror("accept");
exit(EXIT_FAILURE);
}

valread = read( new_socket , buffer, 1024);
cout<<"received crypted message: "<<buffer<<endl;
cout<<"size: "<<valread<<endl;



// declare some useful variables:
const EVP_CIPHER* cipher = EVP_aes_128_cbc();
int iv_len = EVP_CIPHER_iv_length(cipher);

// Allocate buffer for IV, ciphertext, plaintext
unsigned char* iv = (unsigned char*)malloc(iv_len);
int cphr_size = valread;
char* cphr_buf = (char*)malloc(cphr_size);
memcpy(cphr_buf, buffer, cphr_size);

char* clear_buf = (char*)malloc(cphr_size);
if(!iv || !cphr_buf || !clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }


// open the file to decrypt:
FILE* cphr_file = fopen("iv.enc", "rb");
if(!cphr_file) { cerr << "Error: cannot open file '" ; exit(1); }

// read the IV and the ciphertext from file:
ret = fread(iv, 1, iv_len, cphr_file);
if(ret < iv_len) { cerr << "Error while reading file '"; exit(1); }

fclose(cphr_file);

//Create and initialise the context
EVP_CIPHER_CTX *ctx;
ctx = EVP_CIPHER_CTX_new();
if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
ret = EVP_DecryptInit(ctx, cipher, key, iv);
if(ret != 1){
cerr <<"Error: DecryptInit Failed\n";
exit(1);
}

int update_len = 0; // bytes decrypted at each chunk
int total_len = 0; // total decrypted bytes

// Decrypt Update: one call is enough because our ciphertext is small.
ret = EVP_DecryptUpdate(ctx, (unsigned char*)clear_buf, &update_len, (unsigned char*)cphr_buf, cphr_size);
if(ret != 1){
cerr <<"Error: DecryptUpdate Failed\n";
exit(1);
}
total_len += update_len;
cout<<"total_len: "<<total_len<<endl;

//Decrypt Final. Finalize the Decryption and adds the padding
ret = EVP_DecryptFinal(ctx, (unsigned char*)clear_buf + total_len, &update_len);
if(ret != 1){
cerr <<"Error: DecryptFinal Failed\n";
cout<<"iv: "<<iv<<endl;
cout<<"clear: " << (unsigned char*)clear_buf<<endl;
cout<<"tutto: "<< clear_buf + total_len;
cin.get();
exit(1);
}
total_len += update_len;
int clear_size = total_len;

// delete the context from memory:
EVP_CIPHER_CTX_free(ctx);

/*
// write the plaintext into a '.dec' file:
string clear_file_name = cphr_file_name + ".dec";
FILE* clear_file = fopen(clear_file_name.c_str(), "wb");
if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (no permissions?)\n"; exit(1); }
ret = fwrite(clear_buf, 1, clear_size, clear_file);
if(ret < clear_size) { cerr << "Error while writing the file '" << clear_file_name << "'\n"; exit(1); }
fclose(clear_file);*/
/*
// Just out of curiosity, print on stdout the used IV retrieved from file.
cout<<"Used IV:"<<endl;
BIO_dump_fp (stdout, (const char *)iv, iv_len);

cout<<clear_buf<<endl;

// delete the plaintext from memory:
// Telling the compiler it MUST NOT optimize the following instruction.
// With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
free(clear_buf);

//cout << "File '"<< cphr_file_name << "' decrypted into file '" << clear_file_name << "', clear size is " << clear_size << " bytes\n";

// deallocate buffers:
free(iv);
free(cphr_buf);

cin.get();
cin.get();
*/
