# Simple-Kerberos-Server
Here is the list of files in this directory:

packet_header.h     -- defines the format of the packets. It should not be changed. 
aes_func.c          -- implements encryption and decryption function of AES_CBC.
                       It should not be changed. 
enc_dec_example.c   -- shows how to use the encryption and decryption functions of AES.
client.c            -- A client program that sends a string and then sends a 
                             structure to the server. 
server.c            -- A server program that receives a string and then receives a
                             structure from the client. 

To compile:  
make
Note: If there is any compile-time error, you may need to install openssl first: (on Ubuntu VM)
sudo apt-get install libssl-dev

To run:These should all be run in seperate terminals.

./authserver 9500 alice abc bob def 
./client 127.0.0.1 9500 abc 127.0.0.1 9501 alice bob
./server 9501 def

I collaborated heavi;y with Brian Bruns and Colton Thompson on multiple parts of the project. While some parts may look the same I can confirm 
that all of the work in this project is my own.
