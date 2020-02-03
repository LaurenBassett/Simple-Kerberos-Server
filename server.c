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

#define ECHOMAX 255     /* Longest string to echo */

void DieWithError(char *errorMessage)  /* External error handling function */
{
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sock;                        /* Socket */
    struct sockaddr_in echoServAddr; /* Local address */
    struct sockaddr_in echoClntAddr; /* Client address */
    unsigned int cliAddrLen;         /* Length of incoming message */
    char echoBuffer[ECHOMAX];        /* Buffer for echo string */
    unsigned short echoServPort;     /* Server port */
    int recvMsgSize;                 /* Size of received message */

    unsigned char iv[16];
    memset(iv, 0, 16);
   // printf("IV after initialization = %s", iv);

    unsigned char SecretSharedKey[32];
    memset(&SecretSharedKey, 0, 32);
    memcpy(&SecretSharedKey, "abcdefghijklmnopqrstuvwxyzabcdef", 32);

    if (argc != 3)         /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <serverport> <server key> \n", argv[0]);
        exit(1);
    }
    //printf("Server exists!");
    char * justtesting = "abc";
    echoServPort = atoi(argv[1]);  /* First arg:  local port */
    char *echoServerKey = argv[2]; /* Second arg: server key */

    unsigned char key[32];
    memset(key, 0, 32);
    strcpy(key, echoServerKey);

    /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    /* Construct local address structure */
    memset(&echoServAddr, 0, sizeof(echoServAddr));   /* Zero out structure */
    echoServAddr.sin_family = AF_INET;                /* Internet address family */
    echoServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    echoServAddr.sin_port = htons(echoServPort);      /* Local port */

    struct ap_req APRequest;
    if (bind(sock, (const struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
        DieWithError("bind() failed");
  
    cliAddrLen = sizeof(echoClntAddr);
    
    if ((recvMsgSize = recvfrom(sock, &APRequest, sizeof(struct ap_req), 0,
            (struct sockaddr *) &echoClntAddr, &cliAddrLen)) < 0)
            DieWithError("recvfrom() failed");

  //  printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));

    unsigned char area_decrypted[1024];
    struct ticket v2;
   // printf("size: %i\n", APRequest.tkt_length);
    //printf("This is the encrypted ticket:\n");
    //BIO_dump_fp (stdout, (const char *)&APRequest.tkt_serv,APRequest.tkt_length);
    //printf("\n");
    //printf("decrypting with: %s\n", echoServerKey);
    int decryptsize;
    
    decryptsize = decrypt(APRequest.tkt_serv, APRequest.tkt_length, key, iv, (unsigned char*)area_decrypted);
    
    //printf("key=%s\n, iv=%s\n", key, iv); 
    memcpy(&v2, area_decrypted, decryptsize);
    memcpy(&v2.AES_key, SecretSharedKey, 32);

   // printf("AES_key=%s, client_id=%s, server_id=%s\n", v2.AES_key, v2.client_id, v2.server_id); 

    //memset(&v2.client_id, 0, 40 );
    //memcpy(&v2.client_id, "alice", 40);
    //memset(&v2.server_id, 0, 40 );
    //memcpy(&v2.server_id, "bob", 40);
   // v2.lt = LIFETIME;

    //BIO_dump_fp (stdout, (const char*)&v2,sizeof(v2));
    //printf("\n");

    unsigned char auth_decrypted[1024]; // unsigned char area_decrypted[1024];
    memset(auth_decrypted, 0, 1024);
    struct auth v3; // struct ticket v2;
    int decryptAuthsize; 
    // printf("size: %i\n", APRequest.tkt_length);
   // printf("This is my encrypted authentication\n");
    //BIO_dump_fp (stdout, (const char*)&APRequest.auth, APRequest.auth_length);
    //printf("\n");
    
    
    //decryptsize = decrypt(APRequest.tkt_serv, APRequest.tkt_length, key, iv, (unsigned char*)area_decrypted);
    decryptAuthsize = decrypt(APRequest.auth,  APRequest.auth_length, SecretSharedKey, iv, (unsigned char*)auth_decrypted);
    memcpy(&v3, auth_decrypted, decryptAuthsize);
    //printf("This is my decrypted authentication\n");
    //IO_dump_fp (stdout, (const char*)&auth_decrypted, decryptAuthsize);
    //printf("\n");
    //printf("\nV3 ID:%s. \nV2 ID:%s.\n", v3.client_id, v2.client_id);
    v3.ts3 = v2.ts2+1;

    unsigned char ticketID[40];
    unsigned char authID[40];
    strcpy(ticketID, v2.client_id);
    strcpy(authID, v3.client_id);
    if (*ticketID != *authID) {
        struct ap_err failure;
        failure.type = AP_ERR;
        memset(&failure.client_id, 0, 40);
            memcpy(&failure.client_id, v3.client_id, sizeof(v3.client_id));
            if (sendto(sock, (struct ap_err*)&failure, sizeof(failure), 0, (struct sockaddr *)
               &echoClntAddr, sizeof(echoClntAddr)) != sizeof(failure)){
                   DieWithError("sendto() failed");
               }
            DieWithError("Client ID is not Authenticated");

    }
    unsigned char nonce_cipher[MINENC];
    memset(&nonce_cipher, 0, sizeof(long int));
    //printf("\nNonce: %s\n", nonce_cipher);
    //int nonce_ciphertext_len =    encrypt((unsigned char *) &ts3, sizeof(long int), dec_ticket.AES_key, iv, nonce_cipher);
    int nonce_ciphertext_len = encrypt((unsigned char *) &v3.ts3, sizeof(long int), SecretSharedKey, iv, nonce_cipher);
    //printf("nonce ciphertext\n");
    //BIO_dump_fp (stdout, (const char *) nonce_cipher, sizeof(nonce_cipher)); printf("\n");

    struct ap_rep response_AP;
    memset(&response_AP, 0, sizeof(response_AP));
    response_AP.type = AP_REP;
    response_AP.nonce_length = sizeof((v2.ts2+1));
    memcpy(&response_AP.nonce, (unsigned char *) &nonce_cipher, sizeof(nonce_cipher));
     if (sendto(sock, (struct ap_rep*)&response_AP, (sizeof(response_AP)), 0, (struct sockaddr *) &echoClntAddr, cliAddrLen) != sizeof(response_AP))
        DieWithError("sendto() sent a different number of bytes than expected");
   // printf("sent ap_rep from AP\n\n");

 struct krb_prv ClientMessage;
 if ((recvMsgSize = recvfrom(sock, &ClientMessage, sizeof(struct krb_prv), 0,
            (struct sockaddr *) &echoClntAddr, &cliAddrLen)) < 0)
            DieWithError("recvfrom() failed");

    if (ClientMessage.type != KRB_PRV) {
          struct ap_err failure;
        failure.type = AP_ERR;
        memset(&failure.client_id, 0, 40);
            memcpy(&failure.client_id, v3.client_id, sizeof(v3.client_id));
            if (sendto(sock, (struct ap_err*)&failure, sizeof(failure), 0, (struct sockaddr *)
               &echoClntAddr, sizeof(echoClntAddr)) != sizeof(failure)){
                   DieWithError("sendto() failed");
               }
        DieWithError("Time stamp was not authenticated");
    }
   struct pdata s_pdata;
    memset(&s_pdata, 0, sizeof(s_pdata));
    int decrypted_s_pdata_len = decrypt(ClientMessage.prv, ClientMessage.prv_length, SecretSharedKey, iv, (unsigned char *) &s_pdata);
      struct pdata s_pdata2;
    memset(&s_pdata2, 0, sizeof(s_pdata2));
    s_pdata2.type = APP_DATA;
    s_pdata2.packet_length = strlen("Finally I got to send the data to the client. Succeed!");  //application payload length. Just consider the length of the 
                                                                                               //data stored in the pdata.data field. Discard the rest of the fields
    s_pdata2.pid = s_pdata.pid + 1;	//packet id, is a sequential number. Starts with 1.
    memcpy(s_pdata2.data, "Finally I got to send the data to the client. Succeed!", strlen("Finally I got to send the data to the client. Succeed!"));
    //BIO_dump_fp (stdout, (const char *) &s_pdata2, sizeof(s_pdata2)); printf("\n");

    /* encrypt pdata packter */
    unsigned char s_pdata2_cipher[BLOCK_SIZE];
    memset(&s_pdata2_cipher, 0, sizeof(s_pdata2_cipher));
  //int nonce_ciphertext_len =    encrypt((unsigned char *) &ts3, sizeof(long int), dec_ticket.AES_key, iv, nonce_cipher);
    int s_pdata2_ciphertext_len = encrypt((unsigned char *) &s_pdata2, sizeof(struct ticket), SecretSharedKey, iv, s_pdata2_cipher);
    //printf("\npdata_cipher ciphertext\n");
    //BIO_dump_fp (stdout, (const char *) s_pdata2_cipher, s_pdata2_ciphertext_len); printf("\n");

    /* create krb_prv packet */
    struct krb_prv msg_back;
    memset(&msg_back, 0, sizeof(msg_back));
    msg_back.type = KRB_PRV;
    msg_back.prv_length = s_pdata2_ciphertext_len;                   //encrypted data length
    memcpy(msg_back.prv, s_pdata2_cipher, s_pdata2_ciphertext_len);  //encrypted data from struct pdata 
   // printf("msg back\n");
    //BIO_dump_fp (stdout, (const char *) &msg_back, sizeof(msg_back)); printf("\n");

    /* send app_data to client */
    if (sendto(sock, (struct ap_rep*)&msg_back, (sizeof(msg_back)), 0, (struct sockaddr *) &echoClntAddr, cliAddrLen) != sizeof(msg_back))
        DieWithError("sendto() sent a different number of bytes than expected");
   // printf("sent app_data from AP\n");

    printf("OK\n");
    exit(0);
}
    


