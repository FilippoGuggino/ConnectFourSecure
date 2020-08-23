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
     string prvkey_file_name="ConnectFourServer_prvkey.pem";
   FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
   if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; exit(1); }
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

void verify_client_signature(string username,unsigned char* sgnt_buf,unsigned int sgnt_size,string client_nonce){

   int ret;

  // load the client's public key:
   string pubkey_file_name=username+"_pubkey.pem";
   FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
   if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
   EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
   fclose(pubkey_file);
   if(!pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();

   //create the plaintext
   string s=username+client_nonce;
   unsigned char* clear_buf=(unsigned char*)s.c_str();
   unsigned int clear_size=strlen((const char*)clear_buf);

   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

   // verify the plaintext:
   // (perform a single update on the whole plaintext)
   ret = EVP_VerifyInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
   if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
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

}
/*
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
	exit(1);
}


void serverSessionKeyGeneration(){

 //DH
  EVP_PKEY* dhparams;
  if(NULL == (dhparams = EVP_PKEY_new())) handleErrorsDH();
  DH* temp = get_dh2048_auto();
  if(1 != EVP_PKEY_set1_DH(dhparams,temp)) handleErrorsDH();
  DH_free(temp);


  EVP_PKEY_CTX* DHctx = EVP_PKEY_CTX_new(dhparams,NULL) handleErrorsDH();
  EVP_PKEY* dh_prv_key = NULL;
  EVP_PKEY_keygen_init(DHctx) handleErrorsDH();
  EVP_PKEY_keygen(DHctx,&dh_prv_key) handleErrorsDH();

  string my_pubkey_file_name;

  //TODO sostituire con recupero automatico della chiave
  cout << "Please, type the PEM file that will contain your DH public key: ";
  getline(cin, my_pubkey_file_name);
  if(!cin) { cerr << "Error during input\n"; exit(1); }

  FILE* p1w = fopen(my_pubkey_file_name.c_str(), "w");
  if(!p1w){ cerr << "Error: cannot open file '"<< my_pubkey_file_name << "' (missing?)\n"; exit(1); }
  PEM_write_PUBKEY(p1w, dh_prv_key);
  fclose(p1w);

  string peer_pubkey_file_name;

  //TODO sostituire con recupero automatico del file
  cout << "Please, type the PEM file that contains the peer's DH public key: ";
  getline(cin, peer_pubkey_file_name);
  if(!cin) { cerr << "Error during input\n"; exit(1); }

  FILE* peer_file = fopen(peer_pubkey_file_name.c_str(), "r");
  if(!peer_file){ cerr << "Error: cannot open file '"<< peer_pubkey_file_name <<"' (missing?)\n"; exit(1); }
  EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);
  fclose(peer_file);
  if(!peer_pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

  printf("Starting DH process\n"); //debug


  EVP_PKEY_CTX *der_ctx;
  unsigned char *skey;
  size_t skeylen;
  derive_ctx = EVP_PKEY_CTX_new(dh_prv_key,NULL);
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

  unsigned char* digest;
  unsigned int digestlen;
  EVP_MD_CTX *Hctx;
  Hctx = EVP_MD_CTX_new();
  //allocate memory for digest
  digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
  //init, Update (only once) and finalize digest
  EVP_DigestInit(Hctx, EVP_sha256());
  EVP_DigestUpdate(Hctx, (unsigned char*)skey, skeylen);
  EVP_DigestFinal(Hctx, digest, &digestlen);


  //REMEMBER TO FREE CONTEXT!!!!!!
  EVP_MD_CTX_free(Hctx);
  EVP_PKEY_CTX_free(derive_ctx);
  EVP_PKEY_free(peer_pubkey);
  EVP_PKEY_free(dh_prv_key);
  EVP_PKEY_CTX_free(DHctx);
  EVP_PKEY_free(params);

}
*/


void authenticate_to_client(int sock, string server_nonce){
	int ret;

  // open the certificate file:
	string cert_file_name="ConnectFourServer_cert.pem";
	FILE* cert_file = fopen(cert_file_name.c_str(), "r");
	if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; return; }

	// get the certificate size:
	// (assuming no failures in fseek() and ftell())
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

  // create the plaintext to be signed
  string s="Hello!"+server_nonce;
	unsigned char* clear_buf=(unsigned char*)s.c_str();
	unsigned int clear_size=strlen((const char*)clear_buf);

	send_digital_signature(sock,clear_buf,clear_size);

}

int main(int argc, char const *argv[])
{
     int opt = 1;
     int master_socket , addrlen , new_socket , client_socket[MAX_CLIENTS] , activity, i , valread , sd;
     int max_sd;
     struct sockaddr_in address;

     char buffer[1024] = {0};  //data buffer of 1K

     //set of socket descriptors
     fd_set readfds;

     //initialise all client_socket[] to 0 so not checked
     for (i = 0; i < MAX_CLIENTS; i++)
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
          for ( i = 0 ; i < MAX_CLIENTS ; i++)
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

                    //send new connection greeting message
                    /*if( send(new_socket, message, strlen(message), 0) != strlen(message) )
                    {
                    perror("send");
               }*/

               puts("Welcome message sent successfully");

               //add new socket to array of sockets
               for (i = 0; i < MAX_CLIENTS; i++)
               {
                    //if position is empty
                    if( client_socket[i] == 0 )
                    {
                         client_socket[i] = new_socket;

                         printf("Adding to list of sockets as %d\n" , i);

                         break;
                    }
               }
          }

          //else its some IO operation on some other socket
          for (i = 0; i < MAX_CLIENTS; i++)
          {
               sd = client_socket[i];

               ///*AUTHENTICATION WITH CLIENT*///

               // uint32_t* server_nonce;
    		//  generateNonce(server_nonce);
    		
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
            		exit(1);
          		 }
          		 else
          		 	cout<<"client_nonce: "<<client_nonce<<endl;
          		 // generated nonce is sent to the server
          		 send(sd , server_nonce , sizeof(uint32_t) , 0 );

            	 //Digital signature + certificate must be sent to the client for authentication
          		 authenticate_to_client(sd,toString(to_string(*server_nonce))); //to_string() to get variable size string from int.toString() to get fixed size string from variable string.

          		 /*digital signature from the client must be verified.*/

          		 //size of next message is received
          		 unsigned int client_sign_size;
          		 if ((valread = read( sd , &client_sign_size, sizeof(uint32_t))) == 0)
          		 {
          			cout<<"client disconnected"<<endl;
          			exit(1);
          		 }
          		 //digital signature of the client is received.
          		 unsigned char* client_sign= (unsigned char*)malloc(client_sign_size);
          		 if ((valread = read( sd , client_sign, client_sign_size)) == 0)
               {
          		     cout<<"client disconnected"<<endl;
          		     exit(1);
          		 }

          		 //size of next message is received
          		 unsigned int size;
          		 if ((valread = read( sd , &size, sizeof(uint32_t))) == 0)
          		 {
          	      cout<<"client disconnected"<<endl;
          			  exit(1);
          		 }


          		 //username of the client is received
          		 unsigned char* username= (unsigned char*)malloc(size);
          		 if ((valread = read( sd , username, size)) == 0)
          		 {
          		     cout<<"client disconnected"<<endl;
          			   exit(1);
          		 }

          		 unsigned char* uc;
          		 std::string s( reinterpret_cast<char const*>(username), valread ) ;
          		 verify_client_signature(s,client_sign,client_sign_size,toString(to_string(client_nonce)));
          	   cout<<"Client authentication completed!"<<endl;

          		 // create the plaintext to be signed

          		 s="EndAuthentication"+toString(to_string(*server_nonce));
          	   cout<<"plaintext da segnare:"<<s<<endl;
          	   unsigned char* clear_buf=(unsigned char*)s.c_str();
          	   unsigned int clear_size=strlen((const char*)clear_buf);

            	 send_digital_signature(sd,clear_buf,clear_size);

            	 cout<<"Authentication completed!"<<endl;

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
                         //set the string terminating NULL byte on the end
                         //of the data read
                         buffer[valread] = '\0';
                         send(sd , buffer , strlen(buffer) , 0 );
                    }
               }
          }
     }



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
