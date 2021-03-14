
#include "Parse_buf.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include <netdb.h>

#include <signal.h>

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


#define serverport 443
#define clientport 443
#define serverQlen 20
#define MAXBYTE 16000

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_Scontext() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_Scontext(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "/etc/symbion/cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/symbion/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

}

void remove_Rstrline(char *str, char *Rstr) {






    char *tmp = (char*) calloc(strlen(str), sizeof (char));
    bcopy(str, tmp, strlen(str));

    char* token;



    memset(str, '\0', sizeof (str));

    while ((token = strtok_r(tmp, "\r\n", &tmp))) {

        if (!strstr(token, Rstr)) {


            strncat(str, token, strlen(token));
            strncat(str, "\r\n", strlen("\r\n"));

        }

    }

    strncat(str, "\r\n", strlen("\r\n"));

}

int create_Ssocket() {

    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(serverport);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, serverQlen) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void RecvfromClient(char *buffer, int client) {
    int bytes;
    bytes = recv(client, buffer, MAXBYTE, 0);

    while (bytes > 0) {
        int len = strlen(buffer);
        if (strstr(buffer, "\r\n\r\n") == NULL) {

            bytes = recv(client, buffer + len, MAXBYTE - len, 0);
        } else {
            break;
        }
    }
}

struct ProxyHeader {
    char *method;
    char *protocol;
    char *host;
    char *url;
    char *port;
};

struct ProxyHeader* CreateProxyHeader() {
    struct ProxyHeader *pr;
    pr = (struct ProxyHeader *) malloc(sizeof (struct ProxyHeader));
    if (pr != NULL) {


        pr->method = NULL;
        pr->protocol = NULL;
        pr->host = NULL;
        pr->port = NULL;
        pr->url = NULL;

    }
    return pr;
}

int SetProxyHeader(struct ProxyHeader *proxyheader, char *buffer) {

    char *index;
    char *saveptr;
    char *tmp_buf = (char *) malloc(strlen(buffer) + 1); /* including NUL */
    memcpy(tmp_buf, buffer, strlen(buffer));
    tmp_buf[strlen(buffer)] = '\0';

    index = strstr(tmp_buf, "\r\n\r\n");
    if (index == NULL) {
        debug("invalid Proxy request , no end of header\n");
        free(tmp_buf);
        return 0;
    }

    proxyheader->method = strtok_r(tmp_buf, " ", &saveptr);

    if (strstr(proxyheader->method, "GET")) {
        proxyheader->url = strtok_r(NULL, " ", &saveptr);
        proxyheader->protocol = strtok_r(NULL, "\r\n", &saveptr);
        char *line;
        while ((line = strtok_r(saveptr, "\r\n", &saveptr))) {
            if (strstr(line, "Host:")) {
                strtok_r(NULL, " ", &line);
                proxyheader->host = line;

            }
        }
    } else if (strstr(proxyheader->method, "CONNECT")) {
        proxyheader->host = strtok_r(NULL, ":", &saveptr);
        proxyheader->port = strtok_r(NULL, " ", &saveptr);
        proxyheader->protocol = strtok_r(NULL, "\r\n", &saveptr);
    } else {
        return 0;
    }
    return 1;



}

int SendtoClient(char *buf, int client) {

    return send(client, buf, strlen(buf), 0);
}

void DestroyProxyHeader(struct ProxyHeader * pr) {


    free(pr);

}

int ReadfromClient(SSL *Sssl, char *buf) {
    int b = 0;
    int bytes = SSL_read(Sssl, buf, 512);
    if (bytes > 0) {
        b = 1;
    }
    while (bytes > 0) {

        int len = strlen(buf);

        if (strstr(buf, "\r\n\r\n") != NULL) {


            break;
        }


        bytes = SSL_read(Sssl, buf + len, MAXBYTE - len);



    }
    return b;
}

int CreateCsocket(struct hostent *host) {
    int sd;
    struct sockaddr_in Caddr;
    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&Caddr, 0, sizeof (Caddr));
    Caddr.sin_family = AF_INET;
    Caddr.sin_port = htons(clientport);
    Caddr.sin_addr.s_addr = *(long*) (host ->h_addr);

    if (connect(sd, (struct sockaddr*) &Caddr, sizeof (Caddr)) == -1) {
        printf("Cannot connect to Server");
    }
    return sd;
}

struct SSL *ConfigureCcontext(int sd) {
    SSL *Cssl;
    BIO *outbio = NULL;
    SSL_METHOD *method;
    SSL_CTX *Cctx;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (SSL_library_init() < 0) {
        BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
    }

    method = SSLv23_client_method();
    Cctx = SSL_CTX_new(method);
    SSL_CTX_set_options(Cctx, SSL_OP_NO_SSLv2);

    Cssl = SSL_new(Cctx);
    SSL_set_fd(Cssl, sd);
    SSL_connect(Cssl);
    SSL_CTX_free(Cctx);
    return Cssl;
}

char *getHeaderValue(char *header, char *buf) {

    char *tmp = (char*) calloc(strlen(buf), sizeof (char));
    bcopy(buf, tmp, strlen(buf));

    char* line;

    while ((line = strtok_r(tmp, "\r\n", &tmp))) {
        if (strstr(line, header)) {
            strtok_r(NULL, " ", &line);

            return line;

        }

    }
    return NULL;
}

int SkipHeaderLen(SSL *ssl, char *buf) {


    int bytes = SSL_read(ssl, buf, 16000);

    while (bytes > 0) {

        char* point;
        if (point = strstr(buf, "\r\n\r\n")) {

            return bytes;

        }

        bytes = SSL_read(ssl, buf, 16000);

    }
    return 0;
}

int main(int argc, char **argv) {

    int serversock;
    SSL_CTX *Sctx;

    init_openssl();
    Sctx = create_Scontext();
    configure_Scontext(Sctx);
    serversock = create_Ssocket();

    //Handle connections 
    while (1) {

        struct sockaddr_in Saddr;
        uint len = sizeof (Saddr);
        SSL *Sssl;


        int client = accept(serversock, (struct sockaddr*) &Saddr, &len);

        if (client < 0) {
            perror("Unable to accept Client");
            close(client);
            goto exitserverloop;
        }
        printf("################################## Client Started #################################\n\n");

        char *buffer = (char*) calloc(MAXBYTE, sizeof (char));

        //  printf("%s\n", "Client Request ..................................\n");
        RecvfromClient(buffer, client);
        //printf("%s\n", buffer);
        // printf("%s", "..................................................\n\n");

        struct ProxyHeader *proxyheader = CreateProxyHeader();
        if (!SetProxyHeader(proxyheader, buffer)) {
            DestroyProxyHeader(proxyheader);
            goto exitserverloop;
        }

        printf("Host Name :  %s\n\n", proxyheader->host);
        printf("URL :  %s\n\n", proxyheader->url);

        // if (strstr(proxyheader->host,"w.go")){

        char *reply = proxyheader->protocol;
        strcat(reply, " 200 connection established\r\n\r\n");


        if (SendtoClient(reply, client) <= 0) {
            printf("Error in sending 'connection established ' reply to client .\n");
            DestroyProxyHeader(proxyheader);
            goto exitserverloop;
        } else {
            //  printf("Success in sending 'connection established ' reply to client .\n");

        }

        if (strstr(proxyheader->method, "GET")) {


        } else if (strstr(proxyheader->method, "CONNECT")) {

            Sssl = SSL_new(Sctx);
            SSL_set_fd(Sssl, client);

            if (SSL_accept(Sssl) <= 0) {
                ERR_print_errors_fp(stderr);
                printf("Error ssl handshake.\n");
            } else {

                printf("%s\n\n", "SSL Handshake Complete.........................................................\n\n");
                memset(buffer, '\0', sizeof (buffer));

                if (ReadfromClient(Sssl, buffer)) {
                    //printf("%s\n\n", "Client Request.........................................................\n\n");

                     // printf("%s\n\n", buffer);
                    // printf("%s", "..................................................\n\n");

                    struct hostent *host = gethostbyname(proxyheader->host);

                    if (host->h_length > 0) {
                        printf("%s\n\n", "DNS Success .........................................................\n\n");

printf("pending to socket 0000000000000000000000");
                        int clientsock = CreateCsocket(host);
                        if (clientsock) {
printf("socket success 0000000000000000000000");

                            SSL *Cssl = ConfigureCcontext(clientsock);

                            //**without removing accept encoding part, some times server gives encoded response. But signal error was come.
                            /* char *rstr;
                             rstr = "Accept-Encoding";
                             remove_Rstrline(buffer, rstr);
                             rstr = "Transfer-Encoding";
                             remove_Rstrline(buffer, rstr);
                            /* printf("%s\n", buffer);
                             */
                            int len;
                            int Cbytes;
                            char Cbuf[MAXBYTE];

                            len = strlen(buffer);
   printf("pending to write 0000000000000000000000");
                              
                            if (SSL_write(Cssl, buffer, len)) {
                                printf("write complete  0000000000000000000000");
                                int totalcont = 0;
                                int contlen = 0;
                                memset(buffer, '\0', sizeof (buffer));

                                Cbytes = SSL_read(Cssl, Cbuf, 5182);
                                printf("Server Responded ..................%d......................\n\n", Cbytes);
                                if (Cbytes > 0) {


                                    int headlen = 0;


                                    //Cbytes= SkipHeaderLen(Cssl,buffer); 

                                    char* value = getHeaderValue("Content-Length", Cbuf);

                                    if (value) {
                                        contlen = atoi(value);

                                        // number of bytes actually read
                                        // number of bytes received
                                        int i, line_length;

                                        // body assign = '\0'

                                        /***********Try to read byte by byte***********/

                                        i = 0;
                                        line_length = 0; // to check length of each line
                                        while (i <= Cbytes) {
                                            // read 1 byte to c[0]
                                            // read fall or connection closed
                                            if (Cbuf[i] == '\n') { // if '\n'
                                                if (line_length == 0) {
                                                    i++;
                                                    break;
                                                }// empty line, so end header
                                                else line_length = 0; // else reset for new line
                                            } else if (Cbuf[i] != '\r') line_length++; // inc length
                                            i++; // add to header
                                            // count
                                        }

                                        write(STDOUT_FILENO, Cbuf, i);


                                        totalcont = -i;


                                        printf("\n$$$$$$$$$$$$$ header length : %d $$$$$$$$$$$$$\n\n", i);
                                    }

                                    char *trnsfcoding = getHeaderValue("Tranfer-Coding", Cbuf);


                                    while (Cbytes > 0) {

                                        printf("In the Forwarding Loop ........................................\n\n");


                                        //write(STDOUT_FILENO, Cbuf, Cbytes);
                                        if (SSL_write(Sssl, Cbuf, Cbytes)) {

                                            totalcont += Cbytes;
                                            if (contlen) {

                                                if (contlen <= totalcont) {
                                                    break;
                                                    // write(STDOUT_FILENO, Cbuf, Cbytes);
                                                }



                                            } else if (trnsfcoding == NULL || trnsfcoding != "chunked") {


                                                if (strstr(Cbuf, "0\r\n\r\n") != NULL) {

                                                    break;
                                                }
                                            }
                                            memset(Cbuf, '\0', sizeof (Cbuf));
                                            Cbytes = 0;
                                            Cbytes = SSL_read(Cssl, Cbuf, 4096);

                                        }
                                    }

                                }
                                printf("$$$$$$$$$$$$$ ContLen %d $$$$$$$$$$$$$\n\n", contlen);
                                printf("$$$$$$$$$$$$$ ReceivedCont %d $$$$$$$$$$$$$\n\n", totalcont);
                                printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Connection Complete @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n");


                            }

                            close(clientsock);
                            SSL_free(Cssl);
                        }
                    }
                }
            }
            SSL_free(Sssl);
        }




        close(client);

exitserverloop:

        printf("################################## Client Closed #################################\n\n");

    }

    close(serversock);
    SSL_CTX_free(Sctx);
    cleanup_openssl();

}
