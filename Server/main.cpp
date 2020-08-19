#include <unistd.h>
#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions

#define PORT 8080

using namespace std;

void checkCertificate(){
  int ret; // used for return values

   // load the CA's certificate:
   string cacert_file_name;
   cout << "Please, type the PEM file containing a trusted CA's certificate: ";
   getline(cin, cacert_file_name);
   if(!cin) { cerr << "Error during input\n"; return;}
   FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
   if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; return;}
   X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
   fclose(cacert_file);
   if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return; }

   // load the CRL:
   string crl_file_name;
   cout << "Please, type the PEM file containing a trusted CRL: ";
   getline(cin, crl_file_name);
   if(!cin) { cerr << "Error during input\n"; return; }
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
   string cert_file_name;
   cout << "Please, type the PEM file containing peer's certificate: ";
   getline(cin, cert_file_name);
   if(!cin) { cerr << "Error during input\n"; return; }
   FILE* cert_file = fopen(cert_file_name.c_str(), "r");
   if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; return; }
   X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
   fclose(cert_file);
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

   // load the signature file:
   string sgnt_file_name;
   cout << "Please, type the signature file: ";
   getline(cin, sgnt_file_name);
   if(!cin) { cerr << "Error during input\n"; return; }
   FILE* sgnt_file = fopen(sgnt_file_name.c_str(), "rb");
   if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (file does not exist?)\n"; return; }

   // get the file size:
   // (assuming no failures in fseek() and ftell())
   fseek(sgnt_file, 0, SEEK_END);
   long int sgnt_size = ftell(sgnt_file);
   fseek(sgnt_file, 0, SEEK_SET);

   // read the signature from file:
   unsigned char* sgnt_buf = (unsigned char*)malloc(sgnt_size);
   if(!sgnt_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; return; }
   ret = fread(sgnt_buf, 1, sgnt_size, sgnt_file);
   if(ret < sgnt_size) { cerr << "Error while reading file '" << sgnt_file_name << "'\n"; return; }
   fclose(sgnt_file);

   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();
   const char clear_buf[] = "Hello, peer!\n";
   int clear_size = strlen(clear_buf);

   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return; }

   // verify the plaintext:
   // (perform a single update on the whole plaintext,
   // assuming that the plaintext is not huge)
   ret = EVP_VerifyInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; return; }
   ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
   if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; return; }
   ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, X509_get_pubkey(cert));
   if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
      cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
      return;
   }else if(ret == 0){
      cerr << "Error: Invalid signature!\n";
      return;
   }

   // print the successful signature verification to screen:
   cout << "The subject really said \"" << "Hello, peer!\n" << "\"\n";

   // deallocate data:
   EVP_MD_CTX_free(md_ctx);
   X509_free(cert);
   X509_STORE_free(store);
   //X509_free(cacert); // already deallocated by X509_STORE_free()
   //X509_CRL_free(crl); // already deallocated by X509_STORE_free()
   X509_STORE_CTX_free(certvfy_ctx);
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
  /*Setting the peer with its pubkey*/
  if (EVP_PKEY_derive_set_peer(der_ctx, peer_pubkey) <= 0) handleErrorsDH();
  /* Determine buffer length, by performing a derivation but writing the result nowhere */
  EVP_PKEY_derive(der_ctx, NULL, &skeylen);
  /*allocate buffer for the shared secret*/
  skey = (unsigned char*)(malloc(int(skeylen)));
  if (!skey) handleErrorsDH();
  /*Perform again the derivation and store it in skey buffer*/
  if (EVP_PKEY_derive(der_ctx, skey, &skeylen) <= 0) handleErrorsDH();

  //debug
  printf("Here it is the shared secret: \n");
  BIO_dump_fp (stdout, (const char *)skey, skeylen);

  //ATTENZIONEEEEEEEEEEEEEEEEEEEEEEEE
  /*WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
   * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
   * IN NEXT LABORATORY LESSON WE ADDRESS HASHING!
   */
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


int main(int argc, char const *argv[])
{
    checkCertificate();

    cin.get();
    cin.get();

    return 0;
}
