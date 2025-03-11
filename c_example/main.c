#include <stdio.h>
#include <stdlib.h>
#include "libdessl.h"

int main(int argc, char **argv) {
    if (argc < 6) {
        printf("Usage: %s <certDerPath> <keyPemPath> <localPort> <httpProxyHost> <httpProxyPort>\n", argv[0]);
        return 1;
    }

    char *certDerPath = argv[1];
    char *keyPemPath = argv[2];
    int localPort = atoi(argv[3]);
    char *httpProxyHost = argv[4];
    int httpProxyPort = atoi(argv[5]);

    c_startDeSSLServer(certDerPath, keyPemPath, localPort, httpProxyHost, httpProxyPort);
    
    return 0;
}
