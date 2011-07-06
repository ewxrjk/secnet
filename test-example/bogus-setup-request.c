/*
   test-example/bogus-setup-request 127.0.0.1 19098 test-example/inside/inside 127.0.0.1 16096 test-example/outside/outside
  */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

				 /*
 | 00000  00 00 00 00 00 00 00 01  01 01 01 01 00 1a 74 65  ........ ......te |
          ~~~~~~~~~~~ ~~~~~~~~~~~  ~~~~~~~~~~~ ~~~~~|~~~~~
          sessionid   sender's     type         sender's
          zero in     index        fixed for     name
          msg1                     msg1

 | 00010  73 74 2d 65 78 61 6d 70  6c 65 2f 69 6e 73 69 64  st-examp le/insid |
 | 00020  65 2f 69 6e 73 69 64 65  00 1c 74 65 73 74 2d 65  e/inside ..test-e |
                                   ~~~~~|~~~~~~~~~~~~~~~~~
                                    recipient's name
				   
 | 00030  78 61 6d 70 6c 65 2f 6f  75 74 73 69 64 65 2f 6f  xample/o utside/o |
 | 00040  75 74 73 69 64 65 8d f0  3f 35 d6 c8 1f c0        utside.. ?5....   |
          ~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~
	                    sender's nonce
                                  */

typedef struct {
    const char *name;
    union {
	struct sockaddr sa;
	struct sockaddr_in sin;
    };
} Ep;

static void endaddr(Ep *ep, char **argv, int base) {
    int r;
    ep->sin.sin_family=AF_INET;
    r=inet_aton(argv[base],&ep->sin.sin_addr); assert(r);
    ep->sin.sin_port=htons(atoi(argv[base+1]));
    ep->name=argv[base+2];
}

static void endname(uint8_t **msgp, const Ep *ep) {
    int l=strlen(ep->name); assert(l<=65535);
    *(*msgp)++ = l>>8;
    *(*msgp)++ = l;
    memcpy(*msgp, ep->name, l);
    *msgp += l;
}

static Ep us, them;

int main(int argc, char **argv) {
    int r;

    assert(argc==7);

    endaddr(&us,argv,1);
    endaddr(&them,argv,4);

    static const uint8_t mprefix[]={
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01,
	0x01, 0x01, 0x01, 0x01,
    };
    static const uint8_t msuffix[]={
	/* our nonce, fixed he he */
	0x8d, 0xf0, 0x3f, 0x35, 0xd6, 0xc8, 0x1f, 0xc0
    };
    int msglen= (sizeof(mprefix) +
		 2+strlen(us.name) +
		 2+strlen(them.name) +
		 sizeof(msuffix));
    uint8_t msg[msglen];
    uint8_t *msgp=msg;

#define PREFIXSUFFIX(prefixsuffix) do {			\
    memcpy(msgp,prefixsuffix,sizeof(prefixsuffix));	\
    msgp += sizeof(prefixsuffix);			\
  }while(0)

    PREFIXSUFFIX(mprefix);
    
    endname(&msgp,&us);
    endname(&msgp,&them);

    PREFIXSUFFIX(msuffix);

    assert(msgp == msg+msglen);

    struct protoent *proto=getprotobyname("udp");
    int fd=socket(AF_INET, SOCK_DGRAM, proto->p_proto);
    r=bind(fd,&us.sa,sizeof(us.sin)); if (r) { perror("bind us2"); exit(1); }

    for (;;) {
	r=sendto(fd,msg,msglen,0,&them.sa,sizeof(them.sin));
	if (r < 0) perror("sendto");

	r=getchar();
	if (r==EOF) {
	    if (ferror(stdin)) { perror("getchar"); exit(1); }
	    break;
	}
	if (r!='\n')
	    break;
    }
    exit(0);
}
