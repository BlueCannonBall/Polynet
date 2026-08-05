#include "../polynet.hpp"
#include "../tls.hpp"
#include <iostream>
#include <openssl/ssl.h>

int main() {
    (void) pn::init();

    pn::tcp::TLSClient client;
    if (pn::Status result = client.connect("localhost", 443); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    pn::TLSContext context;
    if (pn::Status result = context.init_client(SSL_VERIFY_PEER, "cert.pem"); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    if (pn::Status result = client.tls_init(context, "localhost"); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    if (pn::Status result = client.tls_connect(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    const char req[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (pn::Result<size_t> result = client.sendall(req, sizeof req - 1); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    char resp[32000];
    if (pn::Result<size_t> result = client.recv(resp, sizeof resp - 1); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    } else {
        resp[*result] = '\0';
    }
    std::cout << resp << std::endl;

    if (pn::Status result = client.close(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    (void) pn::quit();
}
