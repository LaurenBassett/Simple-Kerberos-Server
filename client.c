#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "packet_header.h"

#define ECHOMAX 255     /* Longest string to echo */
#define LONGESTID 40 

void DieWithError(char *errorMessage)  /* External error handling function */
{
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[])
{  // printf("Literally it has started\n");
    int sock;    
    int sock2;                /* Socket descriptor */
    struct sockaddr_in echoServAddr; /* Echo server address */
    struct sockaddr_in authServAddr;
    struct sockaddr_in authClntAddr;
    /* Source address of echo */
    unsigned short echoServPort;     /* Echo server port */
    unsigned int fromSize;           /* In-out of address size for recvfrom() */
    char *servIP;   
    char *ASIP;                 /* IP address of server */
    char *echoString;                /* String to send to echo server */
    char echoBuffer[ECHOMAX+1];      /* Buffer for receiving echoed string */
    int echoStringLen;               /* Length of string to echo */
    int respStringLen;               /* Length of received response */
    int echoServerIDLength;
    int clientIDLength;

    //printf("prestruct");
   
    //printf("Struct made");
    if ((argc > 9) || (argc < 7))   /* Test for correct number of arguments */
    {
    
        fprintf(stderr,"Usage: %s<authservername> <authserverport> <clientkey> <server name> <server port> <clientID> <serverID>\n", argv[0]);
        exit(1);

    }
    
    char *authServName = argv[1];         /* First arg: auth server name */
    unsigned short authServPort = atoi(argv[2]);    /*  arg: Auth server port */
    unsigned char* clientKey = argv[3];           /*Third arg: Client Key*/
    char* echoServName = argv[4];       /*Fourth arg: echo Server Name*/
    echoServPort = atoi(argv[5]);   /*Fifth arg: Server port*/
    char *clientID = argv[6];           /* Sixth arg: Client ID */
    char *echoServerID = argv[7];       /*Seventh Arg: Server ID*/
    
    unsigned char iv[16];
    memset(iv, 0, 16);

     unsigned char SecretSharedKey[32];
    memset(&SecretSharedKey, 0, 32);
    memcpy(&SecretSharedKey, "abcdefghijklmnopqrstuvwxyzabcdef", 32);
    
    clientIDLength = sizeof(authClntAddr);

  if ((echoServerIDLength = strlen(echoServerID)) > LONGESTID) 
       DieWithError("Server ID is too long");

  if ((clientIDLength = strlen(clientID)) > LONGESTID) 
       DieWithError("Client ID is too long");
 
    if (argc == 8) {
       echoServPort = atoi(argv[5]); 
       authServPort = atoi(argv[2]);
       } 
    else{
        echoServPort = 9500;
        authServPort = 9501;  
    }
    /* Create a datagram/UDP socket */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    /* Construct the server address structure */
    memset(&echoServAddr, 0, sizeof(echoServAddr));    /* Zero out structure */
    echoServAddr.sin_family = AF_INET;                 /* Internet addr family */
    echoServAddr.sin_addr.s_addr = inet_addr(echoServName);  /* Server IP address */
    echoServAddr.sin_port   = htons(echoServPort);     /* Server port */

     //Construct the Auth Server address structure
    memset(&authServAddr, 0, sizeof(authServAddr));    /* Zero out structure */
    authServAddr.sin_family = AF_INET;                 /* Internet addr family */
    authServAddr.sin_addr.s_addr = inet_addr(authServName);  /* Server IP address */
    authServAddr.sin_port   = htons(authServPort);     /* Server port */

    /*create AES REQ struct send to AS */
    struct as_req ASrequest;
    memset(&ASrequest, 0, sizeof(ASrequest));    /* Zero out structure */
    ASrequest.type = AS_REQ;               /* Internet addr family */
    memcpy(&ASrequest.client_id, clientID, strlen(clientID));
    memcpy(&ASrequest.server_id, echoServerID, strlen(echoServerID));
    ASrequest.ts1 = time(NULL);
   
   //FIRST AND ONLY REQUEST TO AUTHENTICATION SERVER:
    if (sendto(sock, (struct as_req*)&ASrequest, sizeof(ASrequest), 0, (struct sockaddr *) 
            &authServAddr, sizeof(authServAddr)) != sizeof(ASrequest))
        DieWithError("sendto() sent a different number of bytes than expected");
   
    struct as_rep ASrespo;
    clientIDLength = sizeof(authServAddr);
    if ((respStringLen = recvfrom(sock, &ASrespo, sizeof(struct as_rep), 0,
           (struct sockaddr *) &authServAddr, &clientIDLength)) < 0) {
                DieWithError("recvfrom() failed");
           }
        if(ASrespo.type != AS_REP) {
            DieWithError("Client sent incorrect message");
        }
           
    //BIO_dump_fp (stdout, (const char *) &ASrespo, sizeof(ASrespo));

    unsigned char key[32];
    memset(key, 0, 32);
    strcpy(key, clientKey);

  //printf("This is the encrypted credential\n");
    //BIO_dump_fp (stdout, (const char*)&ASrespo.cred, ASrespo.cred_length);
    //printf("/n");
    unsigned char area_decrypted[1024];
    struct credential v2;

    //decrypt(t1_cipher, ciphertext_len, key, iv, (unsigned char *) &t2);
    //printf("decrypting with: %s\n", clientKey);
    int decryptsize;
    //printf("This is the decrypted credential:\n");
    decryptsize = decrypt(ASrespo.cred, ASrespo.cred_length, key, iv, area_decrypted);
    //printf("\n");
    //printf("%s", area_decrypted);
    //BIO_dump_fp (stdout, (const char*)&area_decrypted,decryptsize);
    //struct credential;
    /*
    memcpy(&v2.AES_key, SecretSharedKey, 32);

    int  i = 96;
    while (i < STICKET) {
        memcpy(&v2.tkt_serv[i-96], &area_decrypted[i], STICKET);
        i++;
    }
    */
    memcpy(&v2, area_decrypted, decryptsize);
   // v2.tkt_length = STICKET;
    
    struct auth Authenticator;
    memcpy(&Authenticator.client_id, clientID, clientIDLength);
    Authenticator.ts3 = time(NULL);

   // printf("\n");

    struct ap_req APrequest;
    APrequest.type = AP_REQ;
    memcpy(APrequest.tkt_serv, v2.tkt_serv, v2.tkt_length);
    APrequest.tkt_length = v2.tkt_length;
    //((unsigned char *) &t1, sizeof(struct ticket), key, iv, t1_cipher);
    unsigned char AuthEncrypted[SAUTH];
    //   int ciphertext_cred_len = encrypt((unsigned char *)&credAuthServer, sizeof(struct credential),key, iv, credential_cipher);
    int AuthLength = encrypt((unsigned char*)&Authenticator, sizeof(struct auth), SecretSharedKey, iv, AuthEncrypted);
    memcpy(&APrequest.auth, AuthEncrypted, AuthLength);
    APrequest.auth_length = AuthLength;

    if (sendto(sock, (struct ap_req*)&APrequest, sizeof(APrequest), 0, (struct sockaddr *) 
            &echoServAddr, sizeof(echoServAddr)) != sizeof(APrequest))
            DieWithError("sendto() sent a different number of bytes than expected");


    struct ap_rep APRespo;
    memset(&APRespo, 0, sizeof(APRespo));
    int echoServLength = sizeof(echoServAddr);
    if ((respStringLen = recvfrom(sock, &APRespo , sizeof(struct ap_rep), 0,
           (struct sockaddr *) &echoServAddr, &echoServLength)) < 0)
           DieWithError("recvfrom() failed");
    if (APRespo.type != AP_REP) {
        DieWithError("Client was not Authenticated");
    }


    //create c1_data
    struct pdata c1_data;
    memset(&c1_data, 0, sizeof(c1_data));
    c1_data.type = APP_DATA_REQ;
    c1_data.packet_length = strlen("One Sentence");
    c1_data.pid = 1;
    memcpy(c1_data.data, "One Sentence", sizeof("One Sentence"));

    //encryot c1_data
    unsigned char c1_data_CT[BLOCK_SIZE];
    memset(&c1_data_CT, 0, sizeof(c1_data_CT));
    int c1_data_CT_len = encrypt((unsigned char *) &c1_data, sizeof(struct ticket), SecretSharedKey, iv, c1_data_CT);

    //create krb_prv
    struct krb_prv msgToServer;
    memset(&msgToServer, 0, sizeof(msgToServer));
    msgToServer.type = KRB_PRV;
    msgToServer.prv_length = c1_data_CT_len;
    memcpy(msgToServer.prv, c1_data_CT, c1_data_CT_len);

    //send krb_prv
    if (sendto(sock, (struct krb_prv*)&msgToServer, sizeof(msgToServer), 0, (struct sockaddr*) &echoServAddr, sizeof(echoServAddr)) != sizeof(msgToServer))
        DieWithError("sendto() sent a different number of bytes than expected");
 

    //get krb_prv from server
    struct krb_prv msgFromServer;
    memset(&msgFromServer, 0, sizeof(msgFromServer));
    echoServLength = sizeof(echoServAddr);
    if((respStringLen = recvfrom(sock, &msgFromServer, sizeof(struct krb_prv), 0, (struct sockaddr *) &echoServAddr, &echoServLength)) < 0)
        DieWithError("recvfrom() failed");
    printf("Ciphertext: ");
   // BIO_dump_fp (stdout, (const char *) &msgFromServer, sizeof(msgFromServer));
    printf("%s\n", msgFromServer.prv);
    //
    struct pdata c2_data;
    memset(&c2_data, 0, sizeof(c2_data));
    int decrypted_c2_data_len = decrypt(msgFromServer.prv, msgFromServer.prv_length, SecretSharedKey, iv, (unsigned char *) &c2_data);

  //  BIO_dump_fp(stdout, (const char *) &c2_data, sizeof(c2_data));
//
    //decrpyt

    
   // printf("This is my decrypted authentication\n");
    //BIO_dump_fp (stdout, (const char*)&auth_decrypted, decryptAuthsize);
   // printf("\n");
    //printf("\nV3 ID:%s. \nV2 ID:%s.\n", v3.client_id, v2.client_id);
   // v3.ts3 = time(NULL);

    //move for decrypt

    


//Create and send packet back to server. 
  
    printf("%s\n",c2_data.data);
    printf("ok\n");
    close(sock);
    exit(0);
}

