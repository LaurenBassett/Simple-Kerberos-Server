
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include "packet_header.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define AUTHMAX 255     /* Longest string to auth */

void DieWithError(char *errorMessage)  /* External error handling function */
{
    perror(errorMessage);
    exit(1);
}

void gen_random(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len+1; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}
int main(int argc, char *argv[])
{
    int sock;                        /* Socket */
    struct sockaddr_in authServAddr; /* Local address */
    struct sockaddr_in authClntAddr; /* Client address */
    unsigned int cliAddrLen;         /* Length of incoming message */
    char authBuffer[AUTHMAX];        /* Buffer for auth string */
    unsigned short AuthServPort;     /* Server port */
    unsigned int recvMsgSize;        /* Size of received message */

    //Declare dummy structs--------------------------------------------------------------------------------
    
    if (argc != 6)         /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <authserverport> <clientID> <clientkey> <serverID> <serverkey>\n", argv[0]); //change print
        exit(1);
    }

    //assign inputs from the initialization---------------------------------------------------------------
    AuthServPort = atoi(argv[1]);               /* First arg:  auth server port */
    unsigned char *AuthClientID = (argv[2]);    /* Second arg: ClientID */
    unsigned char *AuthClientKey = argv[3];     /* Third arg: ClientKey */
    unsigned char *EchoServID = argv[4];        /* Fourth arg: ServerID */
    unsigned char *EchoServKey = argv[5];       /* Fifth arg: ServerKey */
    
    
    unsigned char iv[16];
    memset(iv, 0, 16);
    unsigned char SecretSharedKey[32];
    memset(&SecretSharedKey, 0, 32);
    memcpy(&SecretSharedKey, "abcdefghijklmnopqrstuvwxyzabcdef", 32);
    

    /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    /* Construct local address structure */
    memset(&authServAddr, 0, sizeof(authServAddr));   /* Zero out structure */
    authServAddr.sin_family = AF_INET;                /* Internet address family */
    authServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    authServAddr.sin_port = htons(AuthServPort);      /* Local port */
    memset(&authClntAddr, 0, sizeof(authClntAddr));   /* Zero out structure */
    authClntAddr.sin_family = AF_INET;                /* Internet address family */
    authClntAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    authClntAddr.sin_port = htons(AuthServPort);      /* Local port */

    /* Bind to the local address */
    if (bind(sock, (struct sockaddr *) &authServAddr, sizeof(authServAddr)) < 0)
        DieWithError("bind() failed");
    
    struct as_req ASRequest;
    memset(&ASRequest, 0, sizeof(ASRequest));

    //Recieve first packet from client-------------------------------------------------
    cliAddrLen = sizeof(authClntAddr);
    //FIRST AND ONLY INFO FROM THE CLIENT.
    if ((recvMsgSize = recvfrom(sock, &ASRequest, sizeof(struct as_req), 0,
            (struct sockaddr *) &authClntAddr, &cliAddrLen)) < 0)
                   DieWithError("recvfrom() failed");

    if (ASRequest.type != AS_REQ) {
           struct as_err failure;
            failure.type = AS_ERR;
            memset(&failure.client_id, 0, 40);
            memcpy(&failure.client_id, AuthClientID, sizeof(AuthClientID));
            if (sendto(sock, (struct as_rep*)&failure, sizeof(failure), 0, (struct sockaddr *)
               &authClntAddr, sizeof(authClntAddr)) != sizeof(failure)){
                   DieWithError("sendto() failed");
               }
            DieWithError("Incorrect Packet Type.");
            
        }
    
    //This ensures we are recieving information from the client------------------------
    //printf("Handling client %s\n", inet_ntoa(authClntAddr.sin_addr));
    //authBuffer[recvMsgSize] = '\0';
    
    //printf("Received: %i\n", recvMsgSize); //move

    //Create ticket with given information---------------------------------------------
    struct ticket t2;
    memset(&t2, 0, sizeof(t2));
    int t2_len;
    //printf("Seriously this is the ssk: %s\n", SecretSharedKey);
    t2_len = sizeof(struct ticket);
    memcpy(t2.AES_key, SecretSharedKey, sizeof(SecretSharedKey)); 
   // printf("Seriously this is the aes: %s\n", t2.AES_key);
    memcpy(&t2.client_id, ASRequest.client_id, strlen(ASRequest.client_id)); 
    memcpy(&t2.server_id, ASRequest.server_id, strlen(ASRequest.server_id));

    t2.ts2 = time(NULL);
    t2.lt = LIFETIME;
    unsigned char key[32];
    memset(key, 0, 32);
    strcpy(key, AuthClientKey);
    unsigned char skey[32];
    memset(skey, 0, 32);
    strcpy(skey, EchoServKey);

    //Now that we have the ticket, show we have the information. This will be commented out once we are done.
    //printf("\nReceived: (length=%d)\n", recvMsgSize);
    fflush(stdout);
    //printf("key=%s, client=%s, server=%s, time=%ld, lt=%d\n\n",
      //      t2.AES_key, t2.client_id, t2.server_id, t2.ts2, t2.lt);

    //printf("This is the unencypted ticket:\n");
    //BIO_dump_fp (stdout, (const char *)&t2, sizeof(struct ticket));
    //printf("\n");
    //Create the cipher to encrypt the ticket----------------------------------------------------------------
    unsigned char t2_cipher[STICKET];
    //printf("ecrypting with: %s\n", EchoServKey);
    int ciphertext_t2_len = encrypt((unsigned char *)&t2, sizeof(struct ticket), skey, iv, t2_cipher);
   // printf("This is the encrypted ticket: \n");
    //printf("\n");
    //BIO_dump_fp (stdout, (const char *)&t2_cipher, ciphertext_t2_len);

    //Create the credential---------------------------------------------------------------------------------
    struct credential credAuthServer;
    memset(&credAuthServer, 0, sizeof(credAuthServer));
    memcpy(&credAuthServer.AES_key, SecretSharedKey, strlen(credAuthServer.AES_key+1));
    memcpy(&credAuthServer.server_id, EchoServID, strlen(credAuthServer.server_id));
    credAuthServer.ts2 = time(NULL);
    credAuthServer.lt2 = LIFETIME;
    credAuthServer.tkt_length = ciphertext_t2_len;
    memcpy(&credAuthServer.tkt_serv, t2_cipher, ciphertext_t2_len);
    //  printf("memcopy: %s", credAuthServer.tkt_serv);
    //printf("This is the decrypted credential: \n");
    //BIO_dump_fp (stdout, (const char *)&credAuthServer, sizeof(struct credential));
    //printf("\n");
    //encrypt the entire credential--------------------------------------------------------------------------
    unsigned char credential_cipher[SCRED];
   // printf("encrypting with: %s\n", AuthClientKey);
    int ciphertext_cred_len = encrypt((unsigned char *)&credAuthServer, sizeof(struct credential), key, iv, credential_cipher);
    
   // printf("This is the encrypted credential: \n");
    //BIO_dump_fp (stdout, (const char *)&credential_cipher, ciphertext_cred_len);
    //printf("\n");

    //Create the response struct---------------------------------------------------------------------------
    struct as_rep ASResponse;
    memset(&ASResponse, 0, sizeof(ASResponse));
    ASResponse.type = AS_REP;
    ASResponse.cred_length = ciphertext_cred_len;
    memcpy(&ASResponse.cred, credential_cipher , ciphertext_cred_len);
   

    if (sendto(sock, (struct as_rep*)&ASResponse, sizeof(ASResponse), 0, (struct sockaddr *)
               &authClntAddr, sizeof(authClntAddr)) != sizeof(ASResponse)){
               DieWithError("sendto() failed"); 
               }
   else {
    printf("OK\n");
    exit(0);   
   }
}


