#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
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
#include <algorithm> //for "find", search for a specific item inside vectors
#include <sys/ioctl.h>
#include <thread>
#include <mutex>
#include "Utility/serverlib.h"

#define MAX_CLIENTS 30
#define PORT 8080

using namespace std;

vector<struct UserInfo> connectedUsers;
mutex connectedUsersMutex;

//utility function that allows to get a fix-sized string from nonce (10 bytes for nonce exchange and 12 for iv generation)
string toString(uint32_t s,int i){

	ostringstream fixed_nonce;
	fixed_nonce << setw( i ) << setfill( '0' ) << to_string(s);

  return fixed_nonce.str();
}
int handleErrors(){
	printf("An error occourred.\n");
	exit(1);
}

int indexOf(vector<struct UserInfo> vect, string s){
  for (int i = 0; i < vect.size(); i++){
        if(strcmp((char*)vect[i].username.c_str(), s.c_str())==0)
          return i;
  }
  return -1;
}

//Symmetric encryption through session key
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        handleErrors();

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        handleErrors();
 /*      cout<<"iv:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)iv, 12);
 
  cout<<"chiave usata:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)key, 128);

  cout<<"messaggio cifrato:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
   cout<<"messaggio decifrato:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);
       */
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}
//Symmetric decryption through session key
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    

    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        handleErrors();
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();
	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        handleErrors();
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
    /*
    cout<<"iv:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)iv, 12);
 
  cout<<"chiave usata:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)key, 128);
   
  cout<<"messaggio cifrato:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
   cout<<"messaggio decifrato:"<<endl;	//debug
		 BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);
*/

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
    
    	   
        /* Verify failed */
        return -1;
    }
}

unsigned char* get_session_key(string username){
	int ret;

	// retrieve shared secret from file
  	  //TODO retrieve username of peer
	  string seskey_file_name = "Server/SessionKeys/"+username+"_seskey.txt";
	  FILE * seskey_file = fopen(seskey_file_name.c_str(), "r");
	  if (!seskey_file) {
	    cerr << "Error: cannot open file '" << seskey_file_name << "' (missing?)\n";
	    exit(1);
	  }
	  
	  // get the ss size:
	  // (assuming no failures in fseek() and ftell())
	  //TODO we can't assume any failure
	  fseek(seskey_file, 0, SEEK_END);
	  long int sskey_size = ftell(seskey_file);
	  fseek(seskey_file, 0, SEEK_SET);

	  //read the ss
	  unsigned char* sskey_buf = (unsigned char*)malloc(sskey_size);
	  ret=fread(sskey_buf, 1, sskey_size, seskey_file);
	  if(ret < sskey_size) { cerr << "Error while reading file '" << seskey_file_name << "'\n"; exit(1); }
	  fclose(seskey_file);
	 
	  return sskey_buf;
}

//This function allows send updated user list and forward challenge requests/responses
void send_message(int sock,string client_nonce,unsigned char* clear_buf,uint32_t clear_size,string username){
	  int ret;

  	  unsigned char* iv=(unsigned char*)malloc(12);
	  strncpy((char*)iv,client_nonce.c_str(),12);
	  unsigned char* cphr_buf=(unsigned char*)malloc(clear_size);
	  unsigned char* tag_buf=(unsigned char*)malloc(16);
  	  unsigned char* session_key=get_session_key(username);

	  gcm_encrypt(clear_buf,clear_size,iv,12,session_key,iv,12,cphr_buf, tag_buf);
	 	
	  send(sock , tag_buf , 16 , 0 );	//tag with fixed size
	  send(sock , (const char*)&clear_size , sizeof(uint32_t) , 0 );	//size of ciphertext  debug
	  send(sock , cphr_buf , clear_size , 0 );	//ciphertext	
	
}

bool removeFromConnectedUsers(string s){
  //lock_guard differently from mu.lock and mu.unlock release the lock when the object is destructed(aka at the end of the function)
  //with mu.lock/unlock if an exception raise between the twos the lock is not released
  lock_guard<mutex> guard(connectedUsersMutex);
  int index = indexOf(connectedUsers, s);
  if(index == -1){
    cout<<"User "<<s<<" doesn't exists."<<endl;
    return false;
  }
  connectedUsers.erase(connectedUsers.begin() + index);
  return true;
}

//synchronized function, only one thread at a time can enter this function
//update connectedUsers
bool addToConnectedUsers(int sd, string username,uint32_t nonce, struct sockaddr_in address){
  lock_guard<mutex> guard(connectedUsersMutex);
  if(indexOf(connectedUsers, username) == -1){
    struct UserInfo tmp;
    tmp.socket = sd;
    tmp.username = username;
    tmp.nonce = nonce; 
    tmp.address = address;
    connectedUsers.push_back(tmp);
    return true;
  }
  cout<<"User "<<username<<" already connected. Closing connection..."<<endl;
  return false;
}

void printConnectedUsers(){
  lock_guard<mutex> guard(connectedUsersMutex);
  cout<<endl<<"Online users:"<<endl;
  for(int i = 0; i < connectedUsers.size(); i++){
    cout<<connectedUsers[i].username<<endl;
  }
}

unsigned char* forgeUpdatePacket(){
  lock_guard<mutex> guard(connectedUsersMutex);
  unsigned char* clear_buf;

  //allocate dimension of the whole packet
  //+1, for ever "," used as divider
  //-1 at the end, because there are connectedUsers.size() - 1 commas

  int clear_size = 1;
  int user_size = 0;

    //plaintext to encrypt
  for(int i = 0; i < connectedUsers.size(); i++){
    clear_size += connectedUsers[i].username.size() + 1;
  }

  clear_buf = (unsigned char*) malloc(clear_size);
  clear_buf[0] = '5';

  int k = 1;
  for(int i = 0; i < connectedUsers.size(); i++ , k+=user_size+1){
    strcpy((char*)&clear_buf[k], connectedUsers[i].username.c_str());
    user_size = connectedUsers[i].username.size();
    clear_buf[k+user_size] = ',';
  }

  clear_buf[k-1] = '\0';

  //now send the packet to all connected clients
  cout<<endl<<"Updated user list is sent to following users:"<<endl; //debug
  for(int i = 0; i < connectedUsers.size(); i++){
    (connectedUsers[i].nonce)++; //nonce is incremented
    		cout<<"-----------------------"<<endl;
                cout<<"client username:"<<connectedUsers[i].username<<endl;//debug
    		cout<<"client nonce:"<<connectedUsers[i].nonce<<endl;//debug
        	cout<<"client socket:"<<connectedUsers[i].socket<<endl;//debug
    send_message(connectedUsers[i].socket, toString(connectedUsers[i].nonce,12), clear_buf, clear_size,connectedUsers[i].username);
  }
  cout<<"-----------------------"<<endl;

  return clear_buf;
}

void updateClientsWithConnectedUsersList(){
  unsigned char* packet;
  packet = forgeUpdatePacket();
  free(packet);
}

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
  string pubkey_file_name="Server/PubKeys/"+username+"_pubkey.pem";
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

// SERVER SESSION KEY GENERATION

  static DH *get_dh2048_auto(void){
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



//Message from the client must be decrypted,verified and then analyzed
bool handleClientMessage(int sd,unsigned char* cphr_buf,uint32_t cphr_len,unsigned char* tag_buf,string client_nonce,string username){
  int valread = 0;

  unsigned char* iv=(unsigned char*)malloc(12);
  strncpy((char*)iv,client_nonce.c_str(),12);
  unsigned char* session_key=get_session_key(username);
  unsigned char* clear_buf=(unsigned char*)malloc(cphr_len);
  valread=gcm_decrypt(cphr_buf, cphr_len, iv, 12, tag_buf, session_key, iv, 12, clear_buf);
  if(valread==-1)
  	return false;
  	
  unsigned char* type=&clear_buf[0];
 //type=2 --> challenge request message
 //type=3 --> challenge response message
 if(*type=='2'){
 	//retrieve username of the receiver of the challenge
 	char* opponent_username=(char*)malloc(cphr_len-1);
 	strncpy(opponent_username,(const char*)&clear_buf[1],cphr_len);
 	opponent_username[cphr_len-1]='\0';
 	
 	int opponent_socket;
 	uint32_t opponent_nonce;
 	for(int i=0;i<connectedUsers.size();i++){	 //retrieve socket+nonce of receiver of the challenge.
	    	if(connectedUsers[i].username==opponent_username){
	    		opponent_nonce=++(connectedUsers[i].nonce);
	    		opponent_socket=connectedUsers[i].socket;
	    		break;
	    	}
    	}
 	string sender_username=username; //sender of the request.
 	
 	//plaintext to encrypt
	string s='2'+sender_username;
	unsigned char*clear_buf=(unsigned char*)s.c_str();
	uint32_t clear_size=s.size();
	cout<<endl<<"Richiesta di sfida di "<<sender_username<<" da inoltrare a "<<opponent_username<<": "<<clear_buf<<endl;
 	send_message(opponent_socket,toString(opponent_nonce,12),clear_buf,clear_size,opponent_username);
 	
  }
  if(*type=='3'){
  	//Retrieve username of sender of challenge request
 	char* sender_username=(char*)malloc(cphr_len-1);
 	strncpy(sender_username,(const char*)&clear_buf[1],cphr_len-1);
 	sender_username[cphr_len-2]='\0';
 	
 	int sender_socket;
 	uint32_t sender_nonce;
 	for(int i=0;i<connectedUsers.size();i++){	 //retrieve socket+nonce of sender of the challenge.
	    	if(connectedUsers[i].username==sender_username){
	    		sender_nonce=++(connectedUsers[i].nonce);
	    		sender_socket=connectedUsers[i].socket;
	    		break;
	    	}
    	}
 	string opponent_username=username; //sender of the request.
 	
 	//plaintext to encrypt
 	char choice=clear_buf[cphr_len-1];
	string s='3'+opponent_username+choice;
	unsigned char*clear_buf=(unsigned char*)s.c_str();
	uint32_t clear_size=s.size()+1;
	cout<<endl<<"Risposta di sfida di "<<opponent_username<<" da inoltrare a "<<sender_username<<": "<<clear_buf<<endl;
 	send_message(sender_socket,toString(sender_nonce,12),clear_buf,clear_size,sender_username);	
  }

  return true;
}

  bool handleAuthentication(int sd, string& username,unsigned int* client_nonce){
    int valread = 0;
    ///*AUTHENTICATION WITH CLIENT*///

    // Seed OpenSSL PRNG
    uint32_t* server_nonce = (uint32_t*)malloc(sizeof(uint32_t));
    RAND_poll();
    RAND_bytes((unsigned char*)&server_nonce[0],sizeof(uint32_t));

    //nonce generated by the client is received
    if ((valread = read( sd , client_nonce, sizeof(uint32_t))) == 0)
    {
      cout<<"client disconnected"<<endl;
      return false;
    }
    // generated nonce is sent to the server
    send(sd , server_nonce , sizeof(uint32_t) , 0 );
	cout<<"server nonce:"<<*server_nonce<<endl;//debug
	cout<<"client nonce:"<<*client_nonce<<endl;//debug
    //Certificate + digital signature must be sent to the client for authentication
    sendCertificate(sd);
    string s = "Hello"+toString(*server_nonce,10);
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
    unsigned char* usernameTmp = (unsigned char*)malloc(size);
    if ((valread = read( sd , usernameTmp, size)) == 0)
    {
      cout<<"client disconnected"<<endl;
      return false;
    }

    string str( reinterpret_cast<char const*>(usernameTmp), valread ) ;
    username = str;

    if(verify_client_signature(str,client_sign,client_sign_size,toString(*client_nonce,10))==false)
    	return false;
    cout<<"Client authentication completed!"<<endl;

    // create the plaintext to be signed

    s="EndAuthentication"+toString(*server_nonce,10);
    cout<<"plaintext da segnare:"<<s<<endl;
    clear_buf=(unsigned char*)s.c_str();
    clear_size=strlen((const char*)clear_buf);

    send_digital_signature(sd,clear_buf,clear_size);

    cout<<"Authentication with "<<username<<" completed!"<<endl;
    return true;
  }

  void generate_session_key(int &socket,string username){
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

  // export shared secret in a file
  //TODO retrieve username of peer
  string seskey_file_name = "Server/SessionKeys/"+username+"_seskey.txt";
  FILE * seskey_file = fopen(seskey_file_name.c_str(), "wt");
  if (!seskey_file) {
    cerr << "Error: cannot open file '" << seskey_file_name << "' (missing?)\n";
    return;
  }
  int ret=fwrite(hashed_secret,1,hashed_secret_len,seskey_file);
  fclose(seskey_file);
  if (ret<hashed_secret_len) {
    cerr << "Error: fwrite returned NULL\n";
    return;
  }

  //REMEMBER TO FREE CONTEXT!!!!!!
  EVP_MD_CTX_free(Hctx);
  EVP_PKEY_CTX_free(der_ctx);
  EVP_PKEY_free(peer_pubkey);
  EVP_PKEY_free(dh_prv_key);
  EVP_PKEY_CTX_free(DHctx);
  EVP_PKEY_free(dhparams);

  }

  void handleClient(int sd, struct sockaddr_in address){
    string username;
    int valread;
    uint32_t client_nonce;
  
    if(handleAuthentication(sd,username,&client_nonce) == false){
      cout<<"Authentication Error, abort connection"<<endl;
          //TODO abort connection only with that client
      return;
    }
    /*SESSION KEY MUST BE ENSTABLISHED WITH CLIENT*/
    generate_session_key(sd,username);
    cout<<"Session key has been enstablished!"<<endl;
    cout<<username<<" is now online."<<endl;
    if(addToConnectedUsers(sd, username,client_nonce, address) == 0){
      return;
    }

    printConnectedUsers();

    //wait for the client to enable interrupt-driven socket connection
    //this pause only the thread, new connections can still occur during this time
    sleep(1);
    updateClientsWithConnectedUsersList();

  
  while(true){
    
    //Digest of message is received		
    unsigned char* tag_buf=(unsigned char*)malloc(16);
    if ((valread = read( sd , tag_buf, 16)) == 0)
       {
  	cout<<"client disconnected"<<endl;
  	removeFromConnectedUsers(username);
  	exit(1);
       }

    //size of next message is received		
    uint32_t cphr_len;
    if ((valread = read( sd , &cphr_len, sizeof(uint32_t))) == 0)
       {
  	cout<<"client disconnected"<<endl;
  	removeFromConnectedUsers(username);
  	exit(1);
       }
 
  //message from client is received
    unsigned char* cphr_buf=(unsigned char*)malloc(cphr_len);
    if ((valread = read( sd , cphr_buf, cphr_len)) == 0)
       {
  	cout<<"client disconnected"<<endl;
  	removeFromConnectedUsers(username);
  	exit(1);
       }

    for(int i=0;i<connectedUsers.size();i++){	//nonce is incremented at message reach.  
    	if(connectedUsers[i].username==username){
    		client_nonce=++(connectedUsers[i].nonce);
    		break;
    	}
    }
    //Decrpyt and analyze the message
    if(handleClientMessage(sd,cphr_buf,cphr_len,tag_buf,toString(client_nonce,12),username)==false){
	 cout<<"Invalid Message received."<<endl;
	// client_nonce--;	//nonce is restored.
	 exit(1);
	 }
  }	    
    
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
              cin.get();
        exit(EXIT_FAILURE);
      }


      //inform user of socket number - used in send and receive commands
      printf("New connection , socket fd is %d , ip is : %s , port : %d\n" ,
      new_socket ,
      inet_ntoa(address.sin_addr) ,
      ntohs(address.sin_port));

      thread (handleClient, new_socket, address).detach();
    }

    cin.get();
    cin.get();


    return 0;
  }
