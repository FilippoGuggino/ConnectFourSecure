#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h> // for error descriptions
#include <vector>
#include <sys/ioctl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <fcntl.h> //for asynchronous socket
#include <sstream>
#include <ios>
#include <limits>
#include <signal.h>
#include <thread>
#include "interface.h"

#define PORT 8080
#define CLIENT_PORT 3070
#define BUFFER_SIZE 1024

using namespace std;


int sock; //for client-server communication
int opponent_sock; //for client-client communication
vector<string> connectedUsers;
int id;
uint32_t * client_nonce;
uint32_t *session_nonce;
unsigned char* server_ses_key;
unsigned char* opponent_ses_key;
string myUsername;
char* opponent_username;
int opponent_username_length; //debug
bool myturn=true;
bool isMatchFinished=false;
int nextAction; //0--> default  1--> handle challenge request  2-->end match
cell color=red;
EVP_PKEY* dh_prv_key = NULL;
BaseInterface* aCurrentMenu = new FirstMenu(connectedUsers);

bool handleSessionMessage(unsigned char * cphr_buf, uint32_t cphr_len, unsigned char * tag_buf,string nonce,string username);


//utility function that allows to get a fix-sized string from nonce (10 bytes for nonce exchange and 12 for iv generation)
string toString(uint32_t s,int i){

	ostringstream fixed_nonce;
	fixed_nonce << setw( i ) << setfill( '0' ) << to_string(s);

	return fixed_nonce.str();
}


void validate_server_certificate(unsigned char* server_cert){
	int ret; // used for return values

	// load the CA's certificate:
	string cacert_file_name="Client/ca_cert.pem";
	FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
	if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; return;}
	X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
	fclose(cacert_file);
	if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return; }

	// load the CRL:
	string crl_file_name="Client/ca_crl.pem";
	FILE* crl_file = fopen(crl_file_name.c_str(), "r");
	if(!crl_file){ cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; return; }
	X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
	fclose(crl_file);
	if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; return; }

	// build a store with the CA's certificate and the CRL:
	X509_STORE* store = X509_STORE_new();
	if(!store) { cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }
	ret = X509_STORE_add_cert(store, cacert);
	if(ret != 1) { cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }
	ret = X509_STORE_add_crl(store, crl);
	if(ret != 1) { cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }
	ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
	if(ret != 1) { cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }

	// load the peer's certificate:
	BIO *bio;
	X509 *cert;

	bio = BIO_new(BIO_s_mem());
	BIO_puts(bio, (const char*)server_cert);
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return; }

	// verify the certificate:
	X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
	if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }
	ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
	if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }
	ret = X509_verify_cert(certvfy_ctx);
	if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; return; }

	// print the successful verification to screen:
	char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
	free(tmp);
	free(tmp2);

	// export server's pubkey in pem file
	string pubkey_file_name="Client/PubKeys/server_pubkey.pem";
	FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "wt");
	if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; return; }
	PEM_write_PUBKEY(pubkey_file,  X509_get_pubkey(cert));
	fclose(pubkey_file);


	// deallocate data:
	X509_free(cert);
	X509_STORE_free(store);
	//X509_free(cacert); // already deallocated by X509_STORE_free()
	//X509_CRL_free(crl); // already deallocated by X509_STORE_free()
	X509_STORE_CTX_free(certvfy_ctx);
}

void verify_digital_signature(unsigned char* sgnt_buf,unsigned int sgnt_size,unsigned char* clear_buf,unsigned int clear_size,string username){

	int ret;

	// load the peer's public key:
	string pubkey_file_name="Client/PubKeys/"+username+"_pubkey.pem";
	FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
	if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
	EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
	fclose(pubkey_file);
	if(!pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

	// declare some useful variables:
	const EVP_MD* md = EVP_sha256();

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

int connect(int &sock,int port,string ip){
	int ret = 0;

	sock = 0;
	int valread = 0;
	struct sockaddr_in addr;


	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, ip.c_str(), &addr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}
	//    addr.sin_addr.s_addr=INADDR_ANY; //debug

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}

	/*    struct sockaddr_in my_addr;
	unsigned int len = sizeof(struct sockaddr_in);
	getsockname(sock, (struct sockaddr *) &my_addr, &len);
	cout<<"my port is: "<<ntohs(my_addr.sin_port)<<endl;
	cout<<"dest ip is: "<<inet_ntoa(addr.sin_addr)<<endl;*/
	return sock;
}


int handleErrors() {
	printf("An error occourred.\n");
	exit(1);
}

//Symmetric decryption through session key
int gcm_decrypt(unsigned char * ciphertext, int ciphertext_len,
	unsigned char * aad, int aad_len,
	unsigned char * tag,
	unsigned char * key,
	unsigned char * iv, int iv_len,
	unsigned char * plaintext) {
		EVP_CIPHER_CTX * ctx;
		int len;
		int plaintext_len;
		int ret;
		/* Create and initialise the context */
		if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
		if (!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
		handleErrors();
		//Provide any AAD data.
		if (!EVP_DecryptUpdate(ctx, NULL, & len, aad, aad_len))
		handleErrors();
		//Provide the message to be decrypted, and obtain the plaintext output.
		if (!EVP_DecryptUpdate(ctx, plaintext, & len, ciphertext, ciphertext_len))
		handleErrors();
		plaintext_len = len;
		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
		handleErrors();
		/*
		* Finalise the decryption. A positive return value indicates success,
		* anything else is a failure - the plaintext is not trustworthy.
		*/
		ret = EVP_DecryptFinal(ctx, plaintext + len, & len);

		/* Clean up */
		EVP_CIPHER_CTX_cleanup(ctx);
/*
		cout<<"iv:"<<endl;	//debug
		BIO_dump_fp (stdout, (const char *)iv, 12);

		cout<<"chiave usata:"<<endl;	//debug
		BIO_dump_fp (stdout, (const char *)key, 32);

		cout<<"messaggio cifrato:"<<endl;	//debug
		BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
		cout<<"messaggio decifrato:"<<endl;	//debug
		BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);
*/
		if (ret > 0) {
			/* Success */
			plaintext_len += len;
			return plaintext_len;
		} else {

			/* Verify failed */
			return -1;
		}
	}
	//Symmetric encryption through session key
	int gcm_encrypt(unsigned char * plaintext, int plaintext_len,
		unsigned char * aad, int aad_len,
		unsigned char * key,
		unsigned char * iv, int iv_len,
		unsigned char * ciphertext,
		unsigned char * tag) {
			EVP_CIPHER_CTX * ctx;
			int len;
			int ciphertext_len;
			// Create and initialise the context
			if (!(ctx = EVP_CIPHER_CTX_new()))
			handleErrors();
			// Initialise the encryption operation.
			if (1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
			handleErrors();

			//Provide any AAD data. This can be called zero or more times as required
			if (1 != EVP_EncryptUpdate(ctx, NULL, & len, aad, aad_len))
			handleErrors();

			if (1 != EVP_EncryptUpdate(ctx, ciphertext, & len, plaintext, plaintext_len))
			handleErrors();
			ciphertext_len = len;
			//Finalize Encryption
			if (1 != EVP_EncryptFinal(ctx, ciphertext + len, & len))
			handleErrors();
			ciphertext_len += len;
			/* Get the tag */
			if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
			handleErrors();
/*
			cout<<"iv:"<<endl;	//debug
			BIO_dump_fp (stdout, (const char *)iv, 12);

			cout<<"chiave usata:"<<endl;	//debug
			BIO_dump_fp (stdout, (const char *)key, 32);

			cout<<"messaggio cifrato:"<<endl;	//debug
			BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
			cout<<"messaggio decifrato:"<<endl;	//debug
			BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);*/

			/* Clean up */
			EVP_CIPHER_CTX_free(ctx);
			return ciphertext_len;
		}



		//send message to the server/opponent using symmetric encription
		void send_message(int sock, string client_nonce, unsigned char * clear_buf, uint32_t clear_size,string peer_username) {

			//IV creation
			unsigned char* iv=(unsigned char*)malloc(12);
			strncpy((char*)iv,client_nonce.c_str(),12);


			unsigned char * cphr_buf = (unsigned char * ) malloc(clear_size+64);
			unsigned char * tag_buf = (unsigned char * ) malloc(16);
			unsigned char* session_key=(unsigned char * ) malloc(32); //aes key size...
			session_key=(peer_username=="server")?server_ses_key:opponent_ses_key;  //debug

			gcm_encrypt(clear_buf, clear_size, iv, 12, session_key, iv, 12, cphr_buf, tag_buf);

			cout<<"invio messaggio, lungh: "<<clear_size<<endl;	//debug
			cout<<send(sock, tag_buf, 16, 0)<<endl; //tag with fixed size
			cout<<send(sock, (const char * ) & clear_size, sizeof(uint32_t), 0)<<endl; //size of ciphertext
			cout<<send(sock, cphr_buf, clear_size, 0)<<endl;; //ciphertext

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

			void generateSessionKey(int &socket,string peer_username,unsigned char* peer_pubkey_buf,uint32_t peer_pubkey_size){


				BIO* peer_mbio = BIO_new(BIO_s_mem());
				BIO_write(peer_mbio, peer_pubkey_buf, peer_pubkey_size);
				EVP_PKEY* peer_pubkey=PEM_read_bio_PUBKEY(peer_mbio,NULL,NULL,NULL);
				BIO_free(peer_mbio);

				cout<<peer_pubkey_size<<"<>"<<peer_pubkey<<"\n"; //debug

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


				/* //debug
				printf("Here it is the shared secret: \n");
				BIO_dump_fp (stdout, (const char *)skey, skeylen);
				*/
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

			/*	// export shared secret in a file
				string seskey_file_name ="Client/SessionKeys/"+myUsername+"_"+peer_username+"_seskey.txt";  //debug

				FILE * seskey_file = fopen(seskey_file_name.c_str(), "wt");
				if (!seskey_file) {
					cerr << "Error: cannot open file '" << seskey_file_name << "' (missing?)\n";
					return;
				}
				int ret=fwrite(hashed_secret,1,hashed_secret_len,seskey_file);
				fclose(seskey_file);
				if (ret<hashed_secret_len) {
					cerr << "Error: PEM_write_PUBKEY returned NULL\n";
					return;
				}*/

				//REMEMBER TO FREE CONTEXT!!!!!!
				EVP_MD_CTX_free(Hctx);
				EVP_PKEY_CTX_free(der_ctx);
				EVP_PKEY_free(peer_pubkey);
				EVP_PKEY_free(dh_prv_key);
				
				if(peer_username=="server")
					server_ses_key=hashed_secret;
				else
					opponent_ses_key=hashed_secret;
				
			}

			void sendDigitalSignature(int socket,unsigned char* clear_buf,unsigned int clear_size){
				int ret;

				// load my private key:
				string prvkey_file_name="Client/PrvKeys/"+myUsername+"_prvkey.pem";
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
				// (perform a single update on the whole plaintext)
				ret = EVP_SignInit(md_ctx, md);
				if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); }
				ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
				if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
				unsigned int sgnt_size;
				ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
				if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); }

				send(socket , (const char*)&sgnt_size, sizeof(uint32_t) , 0 );	//client's sign size
				send(socket , sgnt_buf , sgnt_size , 0 ); 				//Digital sign


				// delete the digest and the private key from memory:
				EVP_MD_CTX_free(md_ctx);
				EVP_PKEY_free(prvkey);

				free(sgnt_buf);

			}
			uint32_t sendDhPubKey(int &socket,unsigned char* pubkey_buf,uint32_t nonce){

			  EVP_PKEY* dhparams;
			  if(NULL == (dhparams = EVP_PKEY_new())) handleErrorsDH();
			  DH* temp = get_dh2048_auto();
			  if(1 != EVP_PKEY_set1_DH(dhparams,temp)) handleErrorsDH();
			  DH_free(temp);
			  dh_prv_key=NULL;
			  EVP_PKEY_CTX* DHctx = EVP_PKEY_CTX_new(dhparams,NULL); //handle errors
			  EVP_PKEY_keygen_init(DHctx);
			  EVP_PKEY_keygen(DHctx,&dh_prv_key);

			  int dh_prv_key_size =  EVP_PKEY_size(dh_prv_key);
			  cout<<dh_prv_key_size<<"<>"<<dh_prv_key<<"\n";

			  cout << "Sending DH public key to server \n";

			  BIO* mbio=BIO_new(BIO_s_mem());	//serializing the key..
			  PEM_write_bio_PUBKEY(mbio,dh_prv_key);
			  pubkey_buf = NULL;
			  uint32_t pubkey_size = BIO_get_mem_data(mbio,&pubkey_buf);
			  cout<<pubkey_size<<endl; //debug
			  send(socket, &pubkey_size, sizeof(uint32_t) , 0 ); //dimensione messaggio
			  send(socket, pubkey_buf,pubkey_size,0);
			   
			  

			  //plaintext to be signed
			  unsigned char* clear_buf=(unsigned char*)malloc(pubkey_size+10); 
			  memcpy(clear_buf,pubkey_buf,pubkey_size);
			  memcpy(&clear_buf[pubkey_size],toString(nonce,10).c_str(),10);   
			  int clear_size=pubkey_size+10;
			  sendDigitalSignature(socket, clear_buf, clear_size);
			
			  BIO_free(mbio);
			  EVP_PKEY_CTX_free(DHctx);
			  EVP_PKEY_free(dhparams);

			  return pubkey_size;
		  }
			uint32_t * handleServerAuthentication(int sock,int id){

				int valread;
				uint32_t * client_nonce = (uint32_t * ) malloc(sizeof(uint32_t));
				RAND_poll();
				RAND_bytes((unsigned char * ) & client_nonce[0], sizeof(uint32_t));
				cout << "client_nonce: " << * client_nonce << endl;
				// generated nonce is sent to the server
				send(sock, client_nonce, sizeof(uint32_t), 0);
				uint32_t server_nonce;
				//nonce generated by the server is received
				if ((valread = read(sock, & server_nonce, sizeof(uint32_t))) == 0) {
					cout << "server disconnected" << endl;
					exit(1);
				}

				cout<<"server nonce:"<<server_nonce<<endl;//debug
				cout<<"client nonce:"<<*client_nonce<<endl;//debug
				
				/*certificate from server must be validated through CA*/
				//size of next message is received
				unsigned int size;
				if ((valread = read(sock, & size, sizeof(uint32_t))) == 0) {
					cout << "client disconnected" << endl;
					exit(1);
				}
				if(size>5000 || size<0){
				     	cerr<<"Invalid message size"<<endl;
			     		exit(1);
				}
				//certificate from server is received
				unsigned char * server_cert = (unsigned char * ) malloc(size);
				if ((valread = read(sock, server_cert, size)) == 0) {
					cout << "server disconnected" << endl;
					exit(1);
				}

				validate_server_certificate(server_cert);
				
				//size of next message is received
				uint32_t peer_pubkey_size;
				if ((valread = read(sock, & peer_pubkey_size, sizeof(uint32_t))) == 0) {
					cout << "client disconnected" << endl;
					exit(1);
				}
				if(peer_pubkey_size>5000 || peer_pubkey_size<0){
					cerr<<"Invalid message size"<<endl;
			     		exit(1);
				}
				//DH public key from server is received
				unsigned char * peer_pubkey_buf = (unsigned char * ) malloc(peer_pubkey_size);
				if ((valread = read(sock, peer_pubkey_buf, peer_pubkey_size)) == 0) {
					cout << "server disconnected" << endl;
					exit(1);
				}

				/*digital signature from the server must be verified. */

				//digital signature from server is received
				unsigned char * server_sign = (unsigned char * ) malloc(256);
				if ((valread = read(sock, server_sign, 256)) == 0) {
					cout << "server disconnected" << endl;
					exit(1);
				}
				
				//create the plaintext for signature verification
				unsigned char* clear_buf=(unsigned char*)malloc(peer_pubkey_size+10); 
			 	memcpy(clear_buf,peer_pubkey_buf,peer_pubkey_size);
				memcpy(&clear_buf[peer_pubkey_size],toString(*client_nonce,10).c_str(),10);   
			        uint32_t clear_size=peer_pubkey_size+10;
				verify_digital_signature(server_sign,256, clear_buf, clear_size,"server");
		
				//username +username_size+ DH public key +digital signature must be sent to the server for authentication
		
				//digit the username to be sent to the server
				cout << "Please, type your username: ";
				cin>>myUsername;
				if(!cin) { cerr << "Error during input\n"; exit(1); }
				uint32_t user_size=myUsername.size();
				send(sock , (const char*)&user_size, sizeof(uint32_t) , 0 );	//username size
				send(sock , myUsername.c_str() , strlen(myUsername.c_str()) , 0 );	//username in clear

				unsigned char* pubkey_buf;

				uint32_t pubkey_size=sendDhPubKey(sock,pubkey_buf,server_nonce);

				cout << "Authentication completed!" << endl;
				/*SESSION KEY MUST BE ENSTABLISHED WITH SERVER*/
				generateSessionKey(sock,"server",peer_pubkey_buf,peer_pubkey_size);
				cout<<"Session key has been enstablished!"<<endl;
			       
				return client_nonce;
			}

			vector<string> split(const string &s, char delim) {
				stringstream ss(s);
				string item;
				vector<string> elems;
				while (getline(ss, item, delim)) {
					if(item.compare(myUsername) != 0)
					elems.push_back(item);
				}
				return elems;
			}

			void printConnectedUsers(){
				//cout<<"Utenti Connessi:"<<endl;
				for(int i = 0; i < connectedUsers.size(); i++){
					cout<<connectedUsers[i]<<endl;
				}
			}

			void updateConnectedUsers(unsigned char* clear_buf){
				/*	unsigned char tmp[500];
				int valread;
				//TODO needs to be decrypted
				if ((valread = read( sock , tmp, MSG_WAITALL)) == 0){
				cout<<"server disconnected"<<endl;
				exit(1);
			}*/
			string s(reinterpret_cast<char*>(clear_buf));
			connectedUsers = split(s, ',');
			aCurrentMenu->updateText(connectedUsers);
			aCurrentMenu->printText();
		}

		void reconnectToServer(){
			unsigned char* msg = (unsigned char*)"recon";
			uint32_t clear_size = 6;
			unsigned char * clear_buf=(unsigned char *)malloc(clear_size);
			clear_buf[0]='8';
			memcpy((char*)&clear_buf[1], msg, 5);
			(*client_nonce)++;
			send_message(sock, toString((* client_nonce),12), clear_buf, clear_size, "server");
		}

		void updateMenu(string choice,bool isQuitOptionSelected){
			BaseInterface* aNewMenuPointer = aCurrentMenu->getNextMenu(choice, isQuitOptionSelected); // This will return a new object, of the type of the new menu we want. Also checks if quit was selected

			if (aNewMenuPointer && aNewMenuPointer != aCurrentMenu) // This is why we set the pointer to 0 when we were creating the new menu - if it's 0, we didn't create a new menu, so we will stick with the old one
			{
				delete aCurrentMenu; // We're doing this to clean up the old menu, and not leak memory.
				aCurrentMenu = aNewMenuPointer; // We're updating the 'current menu' with the new menu we just created
			}
			if(isMatchFinished){ //if match is finished we go back to first menu
				delete aCurrentMenu;
				aCurrentMenu=new FirstMenu(connectedUsers);
				isMatchFinished=false;
				myturn=true;
				close(opponent_sock);
				nextAction=0;
				reconnectToServer();
			}
			aCurrentMenu->printText();
		}

		//Handle session message from opponent
		void handleOpponentMessage(){
			int valread;
			//Digest of message is received
			unsigned char * tag_buf = (unsigned char * ) malloc(16);
			if ((valread = read(opponent_sock, tag_buf, 16)) == 0) {
				cout << "client disconnected" << endl;
				exit(1);
			}

			//size of next message is received
			uint32_t cphr_len;
			if ((valread = read(opponent_sock, & cphr_len, sizeof(uint32_t))) == 0) {
				cout << "client disconnected" << endl;
				exit(1);
			}
			if(cphr_len>5000 || cphr_len<0){
				cerr<<"Invalid message size"<<endl;
			     	exit(1);
			}
			//message from client is received
			unsigned char * cphr_buf = (unsigned char * ) malloc(cphr_len);
			if ((valread = read(opponent_sock, cphr_buf, cphr_len)) == 0) {
				cout << valread << endl;
				cout << "client disconnected" << endl;
				exit(1);
			}
			( * session_nonce) ++; //nonce is incremented.
			//Decrpyt and analyze the message
			if (handleSessionMessage(cphr_buf, cphr_len, tag_buf,toString(*session_nonce,12),opponent_username) == false) {
				cout << "Invalid Message received." << endl;
				//(*client_nonce)--;	//nonce is restored.
				exit(1);
			}

		}

		void handleChallengeResponse(unsigned char * clear_buf, uint32_t clear_len){
			opponent_username = (char * ) malloc(clear_len - 2);
			strncpy(opponent_username, (const char * ) & clear_buf[1], clear_len-1);
			opponent_username[clear_len - 2] = '\0';
			char choice = clear_buf[clear_len-1];
			if (choice == '1') {

				cout << "User " << opponent_username << " accepted the challenge."<<endl;
				cout<<"Waiting for public key and ip address of opponent.."<<endl;

			} else
			cout << "User " << opponent_username << " refused the challenge...Select another user:"<<endl;
		}

		void handleChallengeRequest(unsigned char * clear_buf, uint32_t clear_len){
			opponent_username = (char * ) malloc(clear_len - 1);
			opponent_username_length=clear_len-1;
			strncpy(opponent_username, (const char * ) & clear_buf[1], clear_len);
			opponent_username[clear_len - 1] = '\0';
			cout << "User " << opponent_username << " sent you a challenge request. Do you want to play with him?[yes/no]"<<endl;
			nextAction=1;
			/*
			string choice;
			cin>>choice;

			if (!cin) {
			cerr << "Error during input\n";
			exit(1);
		}

		//plaintext to encrypt
		clear_buf[clear_len] = (choice == "yes") ? '1' : '0';
		clear_buf[0]='3';
		clear_len = clear_len + 1;
		(*client_nonce)++;  //we increase nonce
		send_message(sock, toString(*client_nonce,12), clear_buf, clear_len,"server");
		if(choice=="yes")
		cout<<"Waiting for public key and ip address of opponent.."<<endl;
		else
		cout<<"Challenge refused"<<endl;*/
	}

	//listen for a connection with the opponent
	void listenForClientConnection(struct sockaddr_in addr){
		int master_socket;
		if((master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)
		{
			perror("socket failed");
			exit(EXIT_FAILURE);
		}
		addr.sin_addr.s_addr = INADDR_ANY;
		int enable = 1;

		if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
			cout<<"setsockopt(SO_REUSEADDR) failed"<<endl;

		if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
			cout<<"setsockopt(SO_REUSEADDR) failed"<<endl;

		linger lin;
		lin.l_onoff = 0;
		lin.l_linger = 0;
		setsockopt(master_socket, SOL_SOCKET, SO_LINGER, (const char *)&lin, sizeof(int));

		//bind the socket to localhost port 3070
		if (bind(master_socket, (struct sockaddr *)&addr, sizeof(addr))<0)
		{
			perror("bind failed");
			exit(EXIT_FAILURE);
		}
		printf("Listener on port %d \n", CLIENT_PORT);

		//try to specify maximum of 3 pending connections for the master socket
		if (listen(master_socket, 1) < 0)
		{
			perror("listen");
			exit(EXIT_FAILURE);
		}

		//accept new connection
		struct sockaddr_in opponent_addr;
		int addrlen = sizeof(opponent_addr);
		if ((opponent_sock = accept(master_socket, (struct sockaddr *)&opponent_addr, (socklen_t*)&addrlen))<0){
			perror("accept");
			cin.get();
			exit(EXIT_FAILURE);
		}
		//inform user of socket number - used in send and receive commands
		printf("New connection , socket fd is %d , ip is : %s , port : %d\n" ,
		opponent_sock ,
		inet_ntoa(opponent_addr.sin_addr) ,
		ntohs(opponent_addr.sin_port));

		close(master_socket);
	}

	void checkACKServer(unsigned char * clear_buf, uint32_t cphr_len){

		string server_msg((const char*)&clear_buf[1],cphr_len-1);
		if (server_msg.compare("discACK") == 0){
			close(sock);
		}
		else {
			cout<<"Invalid disconnection ACK received";
			exit(1);
		}
	}

	void sendDisconnectionRequest(){
		unsigned char* msg = (unsigned char*)"disc";
		uint32_t clear_size = 5;
		unsigned char * clear_buf=(unsigned char *)malloc(clear_size);
		clear_buf[0]='7';
		memcpy((char*)&clear_buf[1], msg, 4);
		(*client_nonce)++;
		send_message(sock, toString((* client_nonce),12), clear_buf, clear_size, "server");
	}

	bool handleSessionMessage(unsigned char * cphr_buf, uint32_t cphr_len, unsigned char * tag_buf,string nonce,string peer_username) {
		int valread = 0;

		unsigned char* iv=(unsigned char*)malloc(12);
		strncpy((char*)iv,nonce.c_str(),12);
		unsigned char* session_key=(peer_username=="server")?server_ses_key:opponent_ses_key;  
		unsigned char * clear_buf = (unsigned char * ) malloc(cphr_len);

		valread = gcm_decrypt(cphr_buf, cphr_len, iv, 12, tag_buf, session_key, iv, 12, clear_buf);
		if (valread == -1)
		return false;
		unsigned char * type = & clear_buf[0];

		//type=2 --> challenge request message
		//type=3 --> challenge response message
		//type=4 --> opponent's ip address and public key
		//type=5 --> update connected users list
		//type=6 --> match move
		if ( * type == '2') {
			handleChallengeRequest(clear_buf,cphr_len);
			return true;
		}
		if ( * type == '3') {
			handleChallengeResponse(clear_buf,cphr_len);
			return true;
		}
		if(*type=='4'){
			cout<<endl<<"Public key and ip address of opponent received!"<<endl;
			char role=clear_buf[1];
			session_nonce=(uint32_t*)&clear_buf[2];
			uint32_t* ip_addr=(uint32_t*)&clear_buf[6];

			struct sockaddr_in addr;	//debug
			addr.sin_family = AF_INET;
			addr.sin_port = htons(CLIENT_PORT);
			addr.sin_addr.s_addr=*ip_addr;


			BIO* mbio=BIO_new(BIO_s_mem());  //deserializing the public key
			uint32_t pubkey_size=cphr_len-10; //public key size is computed by subtracting other fields size from total size
			BIO_write(mbio,&clear_buf[10],pubkey_size);
			EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);

			// export opponent's pubkey in pem file
			string s=opponent_username;
			string pubkey_file_name="Client/PubKeys/"+s+"_pubkey.pem";
			FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "wt");
			if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
			PEM_write_PUBKEY(pubkey_file,  pubkey);
			fclose(pubkey_file);

			if(role=='0'){		//if client is request's sender it must initiate the connection
				//Enstablish a connection with the opponent
				cout<<"mi sto connettendo"<<endl;
				connect(opponent_sock,CLIENT_PORT,inet_ntoa(addr.sin_addr));

				//DH public key +digital signature must be sent to the opponent for authentication
				unsigned char* pubkey_buf;
				uint32_t pubkey_size=sendDhPubKey(opponent_sock,pubkey_buf,*session_nonce);
 
 				
				/*digital signature from the opponent must be verified. */
				 uint32_t peer_pubkey_size;

  				//size of  message is received
  				if ((valread = recv( opponent_sock , &peer_pubkey_size, sizeof(uint32_t),0)) == 0)
				  {
				  	cout<<"client disconnected"<<endl;
					  	close(opponent_sock);
				  }
				  if(peer_pubkey_size>5000 || peer_pubkey_size<0){
				     	close(opponent_sock);
				  }
				  unsigned char* peer_pubkey_buf =(unsigned char*)malloc(peer_pubkey_size);

				  //message received
				  if (valread = recv( opponent_sock , peer_pubkey_buf, peer_pubkey_size,MSG_WAITALL) == 0)
				  {
				    cout<<"client disconnected"<<endl;
					  	close(opponent_sock);
				  }
				    //size of next message is received
				    unsigned int sgnt_size;
				    if ((valread = read( opponent_sock , &sgnt_size, sizeof(uint32_t))) == 0)
				    {
				      cout<<"client disconnected"<<endl;
					  close(opponent_sock);
				    }
				    if(sgnt_size>5000 || sgnt_size<0){
				     	close(opponent_sock);
				     }
				     
				    //digital signature of the client is received.
				    unsigned char* sgnt_buf= (unsigned char*)malloc(sgnt_size);
				    if ((valread = read( opponent_sock , sgnt_buf, sgnt_size)) == 0)
				    {
				      cout<<"client disconnected"<<endl;
					  	close(opponent_sock);
				    }

				    //create the plaintext for signature verification
				    unsigned char*clear_buf=(unsigned char*)malloc(peer_pubkey_size+10); 
				    memcpy(clear_buf,peer_pubkey_buf,peer_pubkey_size);
				    memcpy(&clear_buf[peer_pubkey_size],toString(*session_nonce,10).c_str(),10);   
				    uint32_t clear_size=peer_pubkey_size+10;

				verify_digital_signature(sgnt_buf,sgnt_size, clear_buf, clear_size,opponent_username);

				cout<<" peer pubkey:"<<endl;	//debug
		BIO_dump_fp (stdout, (const char *)peer_pubkey_buf, peer_pubkey_size);
		

				cout << "Authentication completed!" << endl<<endl;
				generateSessionKey(opponent_sock,opponent_username,peer_pubkey_buf,peer_pubkey_size);
				cout<<"Session key generated!"<<endl<<endl;


				myturn=false;
				/*Game interface is now visible on console*/
				aCurrentMenu=new GameInterface();
				aCurrentMenu->printText();
				myturn=true; //the sender has the first move
			}

			else{

			listenForClientConnection(addr);

			//DH public key +digital signature must be sent to the opponent for authentication
				unsigned char* pubkey_buf;
				uint32_t pubkey_size=sendDhPubKey(opponent_sock,pubkey_buf,*session_nonce);
 
				/*digital signature from the opponent must be verified. */
				 uint32_t peer_pubkey_size;

  				//size of  message is received
  				if ((valread = recv( opponent_sock , &peer_pubkey_size, sizeof(uint32_t),0)) == 0)
				  {
				  	cout<<"client disconnected"<<endl;
					  	close(opponent_sock);
				  }
				  if(peer_pubkey_size>5000 || peer_pubkey_size<0){
				     	close(opponent_sock);
				  }
				  unsigned char* peer_pubkey_buf =(unsigned char*)malloc(peer_pubkey_size);

				  //message received
				  if (valread = recv( opponent_sock , peer_pubkey_buf, peer_pubkey_size,MSG_WAITALL) == 0)
				  {
				    cout<<"client disconnected"<<endl;
					  	close(opponent_sock);
				  }
				    //size of next message is received
				    unsigned int sgnt_size;
				    if ((valread = read( opponent_sock , &sgnt_size, sizeof(uint32_t))) == 0)
				    {
				      cout<<"client disconnected"<<endl;
					  close(opponent_sock);
				    }
				    if(sgnt_size>5000 || sgnt_size<0){
				     	close(opponent_sock);
				     }
				     
				    //digital signature of the client is received.
				    unsigned char* sgnt_buf= (unsigned char*)malloc(sgnt_size);
				    if ((valread = read( opponent_sock , sgnt_buf, sgnt_size)) == 0)
				    {
				      cout<<"client disconnected"<<endl;
					  	close(opponent_sock);
				    }

				    //create the plaintext for signature verification
				    unsigned char*clear_buf=(unsigned char*)malloc(peer_pubkey_size+10); 
				    memcpy(clear_buf,peer_pubkey_buf,peer_pubkey_size);
				    memcpy(&clear_buf[peer_pubkey_size],toString(*session_nonce,10).c_str(),10);   
				    uint32_t clear_size=peer_pubkey_size+10;

				verify_digital_signature(sgnt_buf,sgnt_size, clear_buf, clear_size,opponent_username);


		cout<<" peer pubkey:"<<endl;	//debug
		BIO_dump_fp (stdout, (const char *)peer_pubkey_buf, peer_pubkey_size);
		
			cout << "Authentication completed!" << endl<<endl;
			generateSessionKey(opponent_sock,opponent_username,peer_pubkey_buf,peer_pubkey_size);
			cout<<"Session key generated!"<<endl;

			/*Game interface is now visible on console*/
			aCurrentMenu=new GameInterface();
			aCurrentMenu->printText();
			myturn=false; //the receiver has the second move
			handleOpponentMessage();
		}

		BIO_free(mbio);
	}

	if ( * type == '5') {
		updateConnectedUsers(&clear_buf[1]);
	}

	if ( * type == '6') {

		bool isQuitOptionSelected = false;
		string choice;
		choice+=clear_buf[1];
		updateMenu(choice,isQuitOptionSelected);
		myturn=true;
	}

	if ( * type == '7'){
		checkACKServer(clear_buf,cphr_len);
		cout<<"You correctly logged off"<<endl;
		exit(1);
	}
	//TODO FREE CLEAR_BUF



	return true;
}


//reception of session message from server
void packetReceiver(int sock){
	while(1){
		int valread;
		//Digest of message is received
		unsigned char * tag_buf = (unsigned char * ) malloc(16);
		if ((valread = read(sock, tag_buf, 16)) == 0) {
			cout << "client disconnected" << endl;
			exit(1);
		}
		cout<<"dimensione tag: "<<valread<<endl;	//debug
		cout<<"Tag:"<<endl;
		BIO_dump_fp (stdout, (const char *)tag_buf, valread);

		//size of next message is received
		uint32_t cphr_len;
		if ((valread = read(sock, & cphr_len, sizeof(uint32_t))) == 0) {
			cout << "client disconnected" << endl;
			exit(1);
		}
		if(cphr_len>5000 || cphr_len<0){
		     	cerr<<"Invalid message size"<<endl;
			exit(1);
		 }
		/*       cout<<"dimensione di chpr_len: "<<valread<<endl;//debug
		cout<<"chpr_len: "<<cphr_len<<endl<<endl;
		*/
		//message from client is received
		unsigned char * cphr_buf = (unsigned char * ) malloc(cphr_len);
		if ((valread = read(sock, cphr_buf, cphr_len)) == 0) {
			cout << valread << endl;
			cout << "client disconnected" << endl;
			exit(1);
		}
		/*       cout<<endl<<"dimensione del messaggio: "<<valread<<endl;	//debug
		cout<<"messaggio:"<<endl;
		BIO_dump_fp (stdout, (const char *)cphr_buf, valread);
		*/
		( * client_nonce) ++; //nonce is incremented.
		//Decrpyt and analyze the message
		if (handleSessionMessage(cphr_buf, cphr_len, tag_buf,toString(*client_nonce,12),"server") == false) {
			cout << "Invalid Message received." << endl;
			//(*client_nonce)--;	//nonce is restored.
			exit(1);
		}
	}
}



int main(int argc, char const *argv[])
{

	int valread;
	connect(sock,PORT,"127.0.0.1");
	if(argc != 2){
		cout<<"use only one parameter"<<endl;
		//exit(1);
	}

	id = atoi(argv[1]);
	cout<<"id: "<<id<<endl;

	//*AUTHENTICATION WITH SERVER*//
	client_nonce=handleServerAuthentication(sock,id);


	//INTERRUPT DRIVEN CONNECTION

	/*int io_handler(), on;
	pid_t pgrp;

	on=1;
	signal(SIGIO, packetReceiver);


	// Set the process receiving SIGIO/SIGURG signals to us
	pgrp=getpid();
	if (ioctl(sock, SIOCSPGRP, &pgrp) < 0) {
	perror("ioctl F_SETOWN");
	exit(1);
}

// Allow receipt of asynchronous I/O signals
if (ioctl(sock, FIOASYNC, &on) < 0) {
perror("ioctl F_SETFL, FASYNC");
exit(1);
}*/

thread (packetReceiver, sock).detach();

bool isQuitOptionSelected = false;

while (!isQuitOptionSelected) // We're saying that, as long as the quit option wasn't selected, we keep running
{

	//*User inserts the id of the opponent if aCurrentMenu is first menu, or the move if it is the game interface*//
	string choice = "";
	cin>>choice;

	if(choice=="quit"){
		//isQuitOptionSelected=true; //debug
		sendDisconnectionRequest();
		cin>>choice;	//TODO debug
	}

	switch(nextAction){
		case 1:
		{
			//plaintext to encrypt
			uint32_t clear_len = opponent_username_length+ 2;
			unsigned char* clear_buf=(unsigned char*)malloc(clear_len);
			strncpy((char * ) & clear_buf[1],opponent_username, opponent_username_length);
			clear_buf[clear_len-1] = (choice == "yes") ? '1' : '0';
			clear_buf[0]='3';

			(*client_nonce)++;  //we increase nonce
			send_message(sock, toString(*client_nonce,12), clear_buf, clear_len,"server");
			if(choice=="yes")
			cout<<"Waiting for public key and ip address of opponent.."<<endl;
			else
			cout<<"Challenge refused"<<endl;
			nextAction=0;
			break;
		}
		default:{
			updateMenu(choice,isQuitOptionSelected);
			break;
		}
	}

	if(myturn==false) //it means that the match has started (aCurrentMenu is the game interface) and that i must receive the move of the opponent.
	handleOpponentMessage();
}
return 0;
}
