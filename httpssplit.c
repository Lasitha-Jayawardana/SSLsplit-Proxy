
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

int clientport = 4433;
int serverport = 443;
//#define serverport 4433
//#define clientport 433


//Server Side Functions

int create_socket(int port) {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
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

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
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

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "/home/paraqum/WORK/Lasitha/certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/paraqum/WORK/Lasitha/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
      //Server
  int Sbytes;
    char Sbuf[128];


    int sock;
    SSL_CTX *Sctx;





    init_openssl();
    Sctx = create_context();

    configure_context(Sctx);

    sock = create_socket(serverport);
 
    //Handle connections 
    while (1) {


        char data[10000];
         
        //Server
        struct sockaddr_in Saddr;
        uint len = sizeof (Saddr);
        SSL *Sssl;
        const char reply[] = "I'm Lasitha from server. \n";

        int client = accept(sock, (struct sockaddr*) &Saddr, &len);
        
        //

        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        Sssl = SSL_new(Sctx);
        SSL_set_fd(Sssl, client);

        if (SSL_accept(Sssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {

            memset(Sbuf, '\0', sizeof (Sbuf));
            Sbytes = SSL_read(Sssl, Sbuf, sizeof (Sbuf));
            while (Sbytes > 0) {
                write(STDOUT_FILENO, Sbuf, Sbytes);
                 
                strcat(data,Sbuf);
                memset(Sbuf, '\0', sizeof (Sbuf));
                Sbytes = SSL_read(Sssl, Sbuf, sizeof (Sbuf));
                if (Sbytes < 128) {
                    write(STDOUT_FILENO, Sbuf, Sbytes);

                     
                    
                    //Client staring......................
             
                    int sd;
	struct hostent *host;
	struct sockaddr_in Caddr;
	BIO *outbio = NULL;
	SSL_METHOD *method;
	SSL_CTX *Cctx;
	SSL *Cssl;
	char *req;
	int req_len;
	char hostname[] = "www.example.com";
	//char certs[] = "/etc/ssl/certs/ca-certificates.crt";

	int Cbytes;
	char Cbuf[4096];

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	outbio	= BIO_new(BIO_s_file());
	outbio	= BIO_new_fp(stdout, BIO_NOCLOSE);

        
        
        
        
        
	if(SSL_library_init() < 0){
		BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
	}

	method = SSLv23_client_method();
	Cctx = SSL_CTX_new(method);
	SSL_CTX_set_options(Cctx, SSL_OP_NO_SSLv2);

	host = gethostbyname(hostname);
	sd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&Caddr, 0, sizeof(Caddr));
	Caddr.sin_family = AF_INET;
	Caddr.sin_port = htons(clientport);
	Caddr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&Caddr, sizeof(Caddr)) == -1 ) {
		BIO_printf(outbio, "%s: Cannot connect to host %s [%s] on port %d.\n", argv[0], hostname, inet_ntoa(Caddr.sin_addr), clientport);
	}

	Cssl = SSL_new(Cctx); 
	SSL_set_fd(Cssl, sd);
	SSL_connect(Cssl);

	req = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";	
	
        
       // char inputString[4096];
  
  // printf("Enter a multi line string( press ';' to end input)\n");
   //scanf("%[^\t]s", inputString);
  
         
        req_len = strlen(req);
	SSL_write(Cssl, req, req_len);
        char Cdata[100000];
       //int i=0;
	memset(Cbuf, '\0', sizeof(Cbuf));
        memset(Cdata, '\0', sizeof(Cdata));
	Cbytes = SSL_read(Cssl, Cbuf, sizeof(Cbuf));
        //Cbytes=BIO_read(outbio, Cbuf, sizeof(Cbuf));
         // fd_set read_fd_set;
           //FD_ZERO(&read_fd_set);
                //FD_SET(sd, &read_fd_set);
        //i = i +Cbytes;
	while(Cbytes > 0){
		//write(STDOUT_FILENO, Cbuf, Cbytes);
               
                strncat(Cdata,Cbuf,Cbytes);
                 //write(STDOUT_FILENO, Cdata,  strlen(Cdata));
                  //printf("%s",".................\n"); 
                  //printf("%s",Cbuf);
                //SSL_write(Sssl, Cbuf, strlen(Cbuf));
               
               //int sock_fd;
               int r;
               
                 Cbuf[Cbytes]=0;
                
               //Cbytes=BIO_read(outbio, Cbuf, sizeof(Cbuf));
               //SSL_get_error(Cssl,r);
               
               //r=select(2,&read_fd_set,NULL,NULL,NULL);
               //r= SSL_pending(Cssl);
              // r=SSL_peek(Cssl, Cbuf, strlen(Cbuf));
              //SSL_CTX_set_read_ahead(Cctx,0);
               // printf("%i",r);
               SSL_write(Sssl, Cbuf, strlen(Cbuf));
               memset(Cbuf, '\0', sizeof(Cbuf)); 
		Cbytes = SSL_read(Cssl, Cbuf, sizeof(Cbuf)); 
               // i = i +Cbytes;
               /* if (Cbytes<1024 ){
               
                    i=i+1;
                  //write(STDOUT_FILENO, Cbuf, Cbytes);
                   
                   if (i>10){
                      
                      //strcat(Cdata,Cbuf); 
                     // memset(Cdata, '\0', sizeof(Cdata)); 
               memset(Cbuf, '\0', sizeof(Cbuf)); 
                  
                   break;
                   }
  
                }*/ 
               
	}
         //char str[100000];
    

   //printf( "Enter a value :");
       //scanf("%[^\t]s", str);
 strncat(Cdata,Cbuf,Cbytes);
        //write(STDOUT_FILENO, str,  strlen(str));
       // SSL_write(Sssl, str, strlen(str));
        //printf("%s",".................\n");
              //   printf("%i",i);
               //  printf("%s",".................\n");
        write(STDOUT_FILENO, Cdata,  strlen(Cdata));
        
        //SSL_write(Sssl, Cdata, strlen(Cdata));
	SSL_free(Cssl);
	close(sd);
	SSL_CTX_free(Cctx);
                
        //Client closed.......            
            
        
         
        
                    break;
                }


            }
           

        }

        SSL_free(Sssl);
        close(client);






 


    }

    close(sock);
    SSL_CTX_free(Sctx);
    cleanup_openssl();



 
 
}



//Client Side Functions

 