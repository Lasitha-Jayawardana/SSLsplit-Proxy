
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

//int clientport = 443;
//int serverport = 46;
#define serverport 46
#define clientport 443

#define MAXBYTE 14096
//#define NULL __null
 
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
    if (SSL_CTX_use_certificate_file(ctx, "/etc/symbion/cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/etc/symbion/key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } 
     
}


void remove_Rstrline(char *str,char *Rstr){
  
    
    
   
   	 
 //strcpy(tmp,str);
   char *tmp = (char*)calloc(strlen (str),sizeof(char));
        bcopy(str,tmp,strlen (str));
          printf("%s\n",str);	  
          printf("%s\n",tmp);	 
	  char* token; 
  

  
      memset(str, '\0', sizeof (str));
  
    while ((token = strtok_r(tmp, "\r\n", &tmp))) { 
     
     if ( !strstr(token,Rstr))
     {
	 
 
       strncat(str,token,strlen(token));
        strncat(str,"\r\n",strlen("\r\n"));
      
     } 
        
    }
  
  strncat(str,"\r\n",strlen("\r\n"));
    printf("%s\n",str);	
}

int main(int argc, char **argv) {
       

      //Server
  int Sbytes;
   char Sbuf[MAXBYTE];
   // char *Sbuf = (char*)calloc(MAXBYTE,sizeof(char));
 int bytes_send, len;

    int sock;
    SSL_CTX *Sctx;

   // char data[MAXBYTE];



    init_openssl();
    Sctx = create_context();

    configure_context(Sctx);

    sock = create_socket(serverport);
 
    //Handle connections 
    while (1) {


        
         
        //Server
        struct sockaddr_in Saddr;
        uint len = sizeof (Saddr);
        SSL *Sssl;
        //const char reply[] = "I'm Lasitha from server. \n" ;

        int client = accept(sock, (struct sockaddr*) &Saddr, &len);
        
        //

        if (client < 0) {
            perror("Unable to accept Client");
            exit(EXIT_FAILURE);
        }

    //**************************    
       											 
        
										
	char *buffer = (char*)calloc(MAXBYTE,sizeof(char));
        
        bytes_send = recv(client, buffer, MAXBYTE, 0);
        
	while(bytes_send > 0)
	{
		len = strlen(buffer);
		if(strstr(buffer, "\r\n\r\n") == NULL)
		{	
			
			bytes_send = recv(client, buffer + len, MAXBYTE - len, 0);
		}
		else{
			break;
		}
	}
         printf("%s\n","Client Request ..................................\n");
        printf("%s\n",buffer);
        printf("%s","..................................................\n\n");
        
        char *buffertemp = (char*)calloc(MAXBYTE,sizeof(char));
        bcopy(buffer,buffertemp,MAXBYTE);

        

         const char s[4] = " "; 
    char* tok; 
  
 
    tok = strtok(buffer, s);
    //printf("%s\n",tok);
    
    tok = strtok(0, s);
   // printf("%s\n",tok);
    
         const char st[4] = ":"; 
    char* hostname; 
   
  hostname =strtok(tok, st); //"sltctrackme.000webhostapp.com";
    printf("Host Name :  %s\n\n",hostname);
    
    
    
    
    if (strstr(hostname,"w.google.c") || strstr(hostname,"w.example.c")){
        
   
    //pppppppppppppppppppppppppppppppp
    const char reply[]= "HTTP/1.1 200 connection established\r\n\r\n";
      int bytes=0;
            
   
            bytes=send(client ,reply  , strlen(reply) , 0 );
		 

		if(bytes < 0)
		{
			perror("Error in sending 'connection established ' reply to client .\n");
			 
		}else{
                    perror("Success in sending 'connection established ' reply to client .\n");
			
                }
    
    //ppppppppppppppppppppppppppppppppp
    
      
        Sssl = SSL_new(Sctx);
        SSL_set_fd(Sssl, client);

        if (SSL_accept(Sssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            
    printf("%s\n\n","SSL Handshake Complete.........................................................\n\n");
        char *data = (char*)calloc(sizeof (Sbuf),sizeof(char));      
            
    memset(Sbuf, '\0', sizeof (Sbuf));
     memset(data, '\0', sizeof (data));
     printf("%s\n\n","Client Request.........................................................\n\n");
      
            Sbytes = SSL_read(Sssl, Sbuf, sizeof (Sbuf));
            while (Sbytes > 0) {
                //write(STDOUT_FILENO, Sbuf, Sbytes);
                 
                //strcat(data,Sbuf);
               
                 bcopy(Sbuf,data,strlen (Sbuf));
                
                if(strstr(Sbuf, "\r\n\r\n") != NULL)
                {
                    //write(STDOUT_FILENO, Sbuf, Sbytes);
 
                    break;
                } 
                
                memset(Sbuf, '\0', sizeof (Sbuf));
                Sbytes = SSL_read(Sssl, Sbuf, sizeof (Sbuf));
                


            }
            printf("%s\n\n",data);
      
      printf("%s","..................................................\n\n");
        
       //11111111111111111111
      char* token; 
      char *rest = (char*)calloc(strlen (data),sizeof(char));
        bcopy(data,rest,strlen (data));
	 
     
strtok_r(rest, "\n", &rest);
	 token = strtok_r(rest, "\n", &rest) ;
  strtok_r(token, " ", &token);
  token= strtok_r(token, " ", &token);
  
  printf("Host Name :  %s\n\n",token);
    
		 
      //111111111111111111111
              
      //Client starting----------------------
              int sd;
             // char hostname[] = "example.com";
	struct hostent *host;
	struct sockaddr_in Caddr;
        BIO *outbio = NULL;
	SSL_METHOD *method;
	SSL_CTX *Cctx;
	SSL *Cssl;
	
	
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
	  //printf("%s\n","%s: Cannot connect to host %s [%s] on port %d.\n", argv[0], token, inet_ntoa(Caddr.sin_addr), clientport);
        }
        
                
        
       /*int bytes_send = send(sd, buffertemp, strlen(buffertemp), 0);
        bzero(buffertemp, MAXBYTE);
        bytes_send = recv(sd, buffertemp, MAXBYTE-1, 0);
        
        while(bytes_send > 0)
	{
            printf("%s\n",buffertemp);
            
    
            break;
	} */
    
    
	Cssl = SSL_new(Cctx); 
	SSL_set_fd(Cssl, sd);
	SSL_connect(Cssl);

	int req_len;
	 
        
        
       //char str[10000];
      /* memset(str, '\0', sizeof (str));
       printf("Enter a multi line string( press 'tab' to end input)\n");
    
       scanf("%[^\t]s", str);
   strncat(str,"\r\n\r\n",strlen("\r\n\r\n"));*/
       //  char str[]="GET / HTTP/1.1\r\nAccept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko\r\nHost: www.google.com\r\nConnection: Keep-Alive\r\n\r\n";	
	 


 // char str[]="GET / HTTP/1.1\r\nAccept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko\r\nHost: www.google.com\r\nConnection: Keep-Alive\r\nAccept-Encoding: gzip, deflate\r\n\r\n";	
	 
  
//**without removing accept encoding part, some times server gives encoded response. But signal error was come.
  char *rstr="Accept-Encoding";
 remove_Rstrline(data, rstr); 
 printf("%s\n", data); 
 //**///////////////////////////////////////////////
 
 
 
 
 /*char *rstr2="Cookie";
 remove_Rstrline(data, rstr2); 
 printf("%s\n", data); 
 */
 //memset(data, '\0', sizeof(data));
 
 //char *req;   
 //printf("%d\n", strcmp(data,str));
 //data=str;

 //req = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Mobile Safari/537.36\r\nSec-Fetch-User: ?1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n";	
	
       // req = data;
        
    /*    char inputString[4096];
  
       printf("Enter a multi line string( press 'tab' to end input)\n");
   scanf("%[^\t]s", inputString);
  req = inputString;*/
         
        req_len = strlen(data);
	SSL_write(Cssl, data, req_len);
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
               
     //          strncat(Cdata,Cbuf,Cbytes);
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
               write(STDOUT_FILENO, Cbuf, Cbytes);
               
                if((strstr(Cbuf, "</html>") != NULL) || (strstr(Cbuf, "</HTML>") != NULL))
                {
                    //write(STDOUT_FILENO, Sbuf, Sbytes);
 
                    break;
                } 
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
 //strncat(Cdata,Cbuf,Cbytes);
        //write(STDOUT_FILENO, str,  strlen(str));
       // SSL_write(Sssl, str, strlen(str));
        //printf("%s",".................\n");
              //   printf("%i",i);
               //  printf("%s",".................\n");
        //write(STDOUT_FILENO, Cdata,  strlen(Cdata));
      printf( "End@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");   
        //SSL_write(Sssl, Cdata, strlen(Cdata));
	SSL_free(Cssl);
	close(sd);
	SSL_CTX_free(Cctx);
                
        //Client closed.......            
           
      
      
        }

        SSL_free(Sssl);
        close(client);

 }




 


    }

    close(sock);
    SSL_CTX_free(Sctx);
    cleanup_openssl();



 
 
}



//Client Side Functions

 