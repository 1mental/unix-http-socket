#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netdb.h>
#include<errno.h>
#include<unistd.h>
#include<openssl/ssl.h>
#include<openssl/err.h>
 
 
 
#define MAXIMUM_BUFFER_SIZE 4096
 
/*
    FreeBCD TCP Socket Used For HTTP/HTTPS
    Programmed By @vpw3 on Instagram/ 043f on Discord :>
*/
 
 
typedef  int SOCKET;
typedef char* ANSIString;
 
typedef enum 
{
    SOCKET_CREATED,
    SOCKET_CLOSED,
    SOCKET_SHUTDOWNED,
    SOCKET_CONNECTED,
    SOCKET_CONNECTION_ERROR,
    SOCKET_CREATION_ERROR,
    MEMORY_ALLOCATION_ERROR,
    IP_RETRIVED,
    IP_GRABBING_ERROR,
    UNINIT_SOCKET,
    IP_NOT_RETRIVED,
    MESSAGE_SENT,
    MESSAGE_RECEIVED
    
} SOCKET_RESULT;
 
typedef enum
{
    SSL_CONNECTED,
    SSL_CTX_ERROR,
    SSL_CONNECTION_ERROR,
    SSL_READ_ERROR,
    SSL_WRITE_ERROR,
    NOT_CONNECTED_SOCKET
}SSL_RESULT;
 
typedef enum 
{
    HTTP = 80,
    HTTPS = 443
} PROTOCOL;
 
typedef struct 
{
    int* SOCK;
    ANSIString METHOD;
    ANSIString VERSION;
    ANSIString HOST;
    ANSIString USERAGENT;
    ANSIString CONNECTION;
    ANSIString CONTENTTYPE;
    ANSIString ACCEPT;
    ANSIString DOMAIN;
    ANSIString PATH;
    unsigned int READBYTES; // Shows how many bytes are read.
    char IsConnected;
    char IsSSLConnected;
    struct  sockaddr_in ADDRESS;
    struct hostent* HOSTNET;
    SSL_CTX* CTX;
    const SSL_METHOD* SSLMETHOD;
    SSL* CSSL;
    char SENDBUFF[MAXIMUM_BUFFER_SIZE];
    char RECVBUFF[MAXIMUM_BUFFER_SIZE];
}HTTPSOCKET;
 
int LastError;
SOCKET_RESULT CreateHTTPSocket(HTTPSOCKET* sock,ANSIString Domain, PROTOCOL protocol);
SOCKET_RESULT RetriveHostIP(HTTPSOCKET* socket,ANSIString Domain);
void BuildRequest(HTTPSOCKET* socket);
SSL_RESULT InitSSLConnection(HTTPSOCKET* socket);
void DeleteSSL(HTTPSOCKET* socket);
void PrintLastSSLError();
SOCKET_RESULT Connect(HTTPSOCKET* socket);
void Disconnect(HTTPSOCKET* socket);
SSL_RESULT SendSSLMessage(HTTPSOCKET* socket);
SSL_RESULT ReceiveSSLMessage(HTTPSOCKET* socket);
SOCKET_RESULT SendMessage(HTTPSOCKET* socket);
SOCKET_RESULT ReceiveMessage(HTTPSOCKET* socket);
int main(void)
{
    
    HTTPSOCKET sock;
    
    if (CreateHTTPSocket(&sock,"www.instagram.com",HTTPS) == SOCKET_CREATED)
    {
        if (LastError == (int)IP_GRABBING_ERROR)
            fprintf(stdout,"[=] Unable to Retrive the IP Address of the Given Domain\n");
            printf("[+] Socket has been created successfully!\nFD: 0x%x\n",*(sock.SOCK));
 
    }else
    {
        fprintf(stdout,"[-] Unable to create a socket, Error: %s\n",strerror(LastError));
        return -1;
    }
    if (Connect(&sock) != SOCKET_CONNECTED)
    {
        fprintf(stdout,"[-] Unable to connect to the server, Error: %s\n",strerror(LastError));
        return -1;
    }
    
    fprintf(stdout,"[+] Socket has connected to the server successfully!\n");
    
    if (InitSSLConnection(&sock) != SSL_CONNECTED)
    {
        fprintf(stdout,"[-] Unable to establish SSL Connection!, Error Code: %d\n", LastError);
        PrintLastSSLError();
        return -1;
    }
    fprintf(stdout,"[+] SSL Connection has been established successfully!\n");
        
    fprintf(stdout,"[=] Request Format:\n");
    sock.ACCEPT = "*/*";
    sock.CONTENTTYPE = "application/text";
    sock.METHOD = "GET";
    sock.PATH = "/huvn";
    sock.CONNECTION = "Keep-Alive";
    sock.VERSION = "HTTP/1.1";
    sock.HOST = "www.instagram.com";
    sock.USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
    BuildRequest(&sock);
 
    fprintf(stdout,"\n[*] Sending Request...\n\n");
    if (SendSSLMessage(&sock) != MESSAGE_SENT)
    {
        fprintf(stdout, "[-] Unable to send to the server..\n");
        PrintLastSSLError(); 
        DeleteSSL(&sock);
        Disconnect(&sock);
        return -1;
    }
        
    fprintf(stdout,"[+] Message Sent With Bytes Read: 0x%x\n", sock.READBYTES);
    
    fprintf(stdout,"[*] Receiving Response...\n\n");
    
    if (ReceiveSSLMessage(&sock) != MESSAGE_RECEIVED)
    {
        fprintf(stdout, "[-] Unable to read the response.\n");
        PrintLastSSLError(); 
        DeleteSSL(&sock);
        Disconnect(&sock);
        return -1;
    }
 
 
    fprintf(stdout,"[+] Response has been read with bytes: %d\n\n\nResponse:\n\n", sock.READBYTES);
    puts(sock.RECVBUFF);
    DeleteSSL(&sock);
    Disconnect(&sock);
 
    return 1;
    
}
 
 
 
SOCKET_RESULT CreateHTTPSocket(HTTPSOCKET* HttpSocket, ANSIString Domain, PROTOCOL protocol)
{
    memset(HttpSocket, 0, sizeof(HTTPSOCKET));
    SOCKET* temp = (SOCKET*)calloc(1,sizeof(SOCKET));
     *(temp) = socket(AF_INET, SOCK_STREAM, 0);
 
    if (temp < 0)
    {
        LastError = *temp;
        return SOCKET_CREATION_ERROR;
    }
 
    HttpSocket->IsConnected = 0;
    HttpSocket->SOCK = temp;
    HttpSocket->ADDRESS.sin_family = AF_INET;
    if (protocol == HTTP)
        HttpSocket->ADDRESS.sin_port = htons((int)HTTP);
    else
        HttpSocket->ADDRESS.sin_port = htons((int)HTTPS);
    RetriveHostIP(HttpSocket,Domain);
        
    return SOCKET_CREATED;
    
}
 
SOCKET_RESULT RetriveHostIP(HTTPSOCKET* socket,ANSIString Domain)
{
    if (socket == NULL)
        return UNINIT_SOCKET;
    else if (socket->SOCK < 0)
        return UNINIT_SOCKET;
        
    if ((socket->HOSTNET = gethostbyname(Domain)) == NULL)
    {
        LastError = (int)IP_GRABBING_ERROR;
        herror(Domain);
        return IP_GRABBING_ERROR;
    }
    
     bcopy(socket->HOSTNET->h_addr_list[0],&socket->ADDRESS.sin_addr, socket->HOSTNET->h_length);
     socket->DOMAIN = Domain;
     return IP_RETRIVED;
}
 
 
SOCKET_RESULT Connect(HTTPSOCKET* socket)
{
    if (socket == NULL)
        return UNINIT_SOCKET;
    else if (socket->SOCK < 0)
        return UNINIT_SOCKET;
    else if (socket->HOSTNET->h_length <=0)
        return IP_NOT_RETRIVED;
    LastError = connect(*(socket->SOCK),(struct sockaddr *)&socket->ADDRESS,sizeof socket->ADDRESS);
    if (LastError < 0)
    {
        perror("connect");
        return SOCKET_CONNECTION_ERROR;
    }
    socket->IsConnected = 1;
    return SOCKET_CONNECTED;
}
 
SSL_RESULT InitSSLConnection(HTTPSOCKET* socket)
{
    if (!(socket->IsConnected))
        return NOT_CONNECTED_SOCKET;
        
    socket->SSLMETHOD = TLS_client_method();
    socket->CTX = SSL_CTX_new(socket->SSLMETHOD);
    if (socket->CTX == NULL)
    {
        Disconnect(socket);
        return SSL_CTX_ERROR;
    }
    
    socket->CSSL = SSL_new(socket->CTX);
    SSL_set_fd(socket->CSSL , *(socket->SOCK));
    
    LastError = SSL_connect(socket->CSSL);
    
    if (LastError != 1)
    {
        
        LastError = SSL_get_error(socket->CSSL,LastError);
        Disconnect(socket);
        return SSL_CONNECTION_ERROR;
    }
    
    socket->IsSSLConnected = 1;
    
    return SSL_CONNECTED;
}
 
void Disconnect(HTTPSOCKET* socket)
{
    if (socket->IsConnected)
        close(*(socket->SOCK));
    socket->IsConnected = 0;
    free((SOCKET*)socket->SOCK);
}
 
void DeleteSSL(HTTPSOCKET* socket)
{
    if (socket->CSSL == NULL);
        return;
    
    SSL_free(socket->CSSL);
    SSL_CTX_free(socket->CTX);
    socket->IsSSLConnected = 0;
}
 
void PrintLastSSLError()
{
    ERR_print_errors_fp(stderr);
}
 
void BuildRequest(HTTPSOCKET* socket)
{
    snprintf(socket->SENDBUFF,MAXIMUM_BUFFER_SIZE,"%s %s %s\r\nHost: %s\r\nConnection: %s\r\nUser-Agent: %s\r\nContent-Type: %s\r\nAccept: %s\r\n\r\n",socket->METHOD, socket->PATH,socket->VERSION, socket->HOST, socket->CONNECTION, socket->USERAGENT,socket->CONTENTTYPE, socket->ACCEPT);
    
}
 
SSL_RESULT SendSSLMessage(HTTPSOCKET* socket)
{
 
    if (!(socket->IsConnected) || !(socket->IsSSLConnected))
        return NOT_CONNECTED_SOCKET;
        
 
    socket->READBYTES = SSL_write(socket->CSSL,socket->SENDBUFF,strlen(socket->SENDBUFF));
    if (socket->READBYTES < 0)
        return SSL_WRITE_ERROR;
            
    return MESSAGE_SENT;
        
}
 
SSL_RESULT ReceiveSSLMessage(HTTPSOCKET* socket)
{
    if (!(socket->IsConnected) || !(socket->IsSSLConnected))
        return NOT_CONNECTED_SOCKET;
        
 
    socket->READBYTES = SSL_read(socket->CSSL,socket->RECVBUFF,MAXIMUM_BUFFER_SIZE);
    if (socket->READBYTES < 0)
        return SSL_READ_ERROR;
 
            
    return MESSAGE_RECEIVED;
    
}
