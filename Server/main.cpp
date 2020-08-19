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
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <vector>
#include <sys/ioctl.h>

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


int main(int argc, char const *argv[])
{
    int opt = 1;
       int master_socket , addrlen , new_socket , client_socket[30] ,
             max_clients = 30 , activity, i , valread , sd;
       int max_sd;
       struct sockaddr_in address;

       char buffer[1024] = {0};  //data buffer of 1K

       //set of socket descriptors
       fd_set readfds;

       //a message
       char *message = "ECHO Daemon v1.0 \r\n";

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
