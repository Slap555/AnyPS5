#include "prx/libc/include/general/VabiMacros.hpp"
#include "SslCertificateFixture.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <thread>

extern "C" {
int APS5_VABI sceNetInit_nid_postfix();
int APS5_VABI sceNetSocket(const char*, int, int, int);
int APS5_VABI sceNetBind_nid_postfix(int, const void*, std::uint32_t);
int APS5_VABI sceNetListen(int, int);
int APS5_VABI sceNetAccept(int, void*, std::uint32_t*);
int APS5_VABI sceNetConnect(int, const void*, std::uint32_t);
int APS5_VABI sceNetGetsockname(int, void*, std::uint32_t*);
std::int64_t APS5_VABI sceNetSend(int, const void*, std::size_t, int);
std::int64_t APS5_VABI sceNetRecv(int, void*, std::size_t, int);
int APS5_VABI sceNetSocketClose(int);
int APS5_VABI sceSslInit_nid_postfix(std::size_t);
int APS5_VABI sceSslTerm_nid_postfix(int);
int APS5_VABI sceSslLoadCert(int, int, void**, void*, void*);
int APS5_VABI sceSslGetCaList(int, void*);
int APS5_VABI sceSslFreeCaList(int, void*);
int APS5_VABI sceSslCreateConnection(int, int, const char*);
int APS5_VABI sceSslDeleteConnection(int);
int APS5_VABI sceSslSetVerifyCallback(int, int (APS5_VABI *)(int, unsigned int, void**, int, void*), void*);
int APS5_VABI sceSslSetMinSslVersion(int, int);
int APS5_VABI sceSslSetAlpn(int, const char*);
const char* APS5_VABI sceSslGetAlpnSelected(int);
int APS5_VABI sceSslConnect(int);
int APS5_VABI sceSslRead(int, void*, std::size_t, int);
int APS5_VABI sceSslWrite(int, void*, std::size_t, int);
int APS5_VABI sceSslClose(int);
void* APS5_VABI sceSslGetSubjectName(int, void*);
void* APS5_VABI sceSslGetIssuerName(int, void*);
int APS5_VABI sceSslGetNameEntryCount(int, void*);
int APS5_VABI sceSslGetNameEntryInfo(int, void*, int, char*, std::size_t, std::uint8_t*, std::size_t, std::size_t*);
int APS5_VABI sceSslFreeSslCertName(int, void*);
}

struct SslData {
    const void* ptr;
    std::size_t size;
};

struct SslCaList {
    void** certs;
    int num;
};

static void Require(bool value) { if (!value) std::abort(); }

template <typename TCall>
static bool Throws(TCall call) {
    try {
        call();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

static int APS5_VABI VerifyCallback(int, unsigned int, void**, int, void*) { return 0; }

using Address = std::array<unsigned char, 16>;

static Address Loopback() {
    Address address{};
    address[0] = 16;
    address[1] = 2;
    address[4] = 127;
    address[7] = 1;
    return address;
}

static int ServerSend(void* socket, const unsigned char* buffer, std::size_t length) {
    const auto sent = sceNetSend(*static_cast<int*>(socket), buffer, length, 0);
    return sent < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : static_cast<int>(sent);
}

static int ServerReceive(void* socket, unsigned char* buffer, std::size_t length) {
    const auto received = sceNetRecv(*static_cast<int*>(socket), buffer, length, 0);
    return received < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : static_cast<int>(received);
}

class Server {
public:
    Server() {
        mbedtls_x509_crt_init(&chain);
        mbedtls_pk_init(&key);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        Require(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0) == 0);
        Require(mbedtls_x509_crt_parse(&chain, reinterpret_cast<const unsigned char*>(ServerPem), sizeof(ServerPem)) == 0);
        Require(mbedtls_pk_parse_key(&key, reinterpret_cast<const unsigned char*>(ServerKey), sizeof(ServerKey), nullptr, 0,
            mbedtls_ctr_drbg_random, &drbg) == 0);
        listener = sceNetSocket("server", 2, 1, 0);
        Require(listener >= 0);
        const auto address = Loopback();
        Require(sceNetBind_nid_postfix(listener, address.data(), address.size()) == 0);
        Require(sceNetListen(listener, 4) == 0);
        bound = address;
        std::uint32_t size = bound.size();
        Require(sceNetGetsockname(listener, bound.data(), &size) == 0);
    }

    ~Server() {
        sceNetSocketClose(listener);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&key);
        mbedtls_x509_crt_free(&chain);
    }

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    const Address& Bound() const { return bound; }

    bool Serve(bool exchange) {
        int peer = sceNetAccept(listener, nullptr, nullptr);
        Require(peer >= 0);
        mbedtls_ssl_config config;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config_init(&config);
        mbedtls_ssl_init(&ssl);
        const char* protocols[] = {"http/1.1", nullptr};
        Require(mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0);
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);
        Require(mbedtls_ssl_conf_own_cert(&config, &chain, &key) == 0);
        Require(mbedtls_ssl_conf_alpn_protocols(&config, protocols) == 0);
        Require(mbedtls_ssl_setup(&ssl, &config) == 0);
        mbedtls_ssl_set_bio(&ssl, &peer, ServerSend, ServerReceive, nullptr);
        bool passed = mbedtls_ssl_handshake(&ssl) == 0;
        if (passed && exchange) {
            unsigned char request[4]{};
            passed = mbedtls_ssl_read(&ssl, request, sizeof(request)) == 4 && std::memcmp(request, "ping", 4) == 0;
            passed = passed && mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>("pong"), 4) == 4;
            unsigned char rest[1]{};
            passed = passed && mbedtls_ssl_read(&ssl, rest, sizeof(rest)) == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
        }
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        sceNetSocketClose(peer);
        return passed;
    }

private:
    mbedtls_x509_crt chain;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    int listener = -1;
    Address bound{};
};

static int Dial(const Address& address) {
    const int socket = sceNetSocket("client", 2, 1, 0);
    Require(socket >= 0);
    Require(sceNetConnect(socket, address.data(), address.size()) == 0);
    return socket;
}

int main() {
    Require(sceNetInit_nid_postfix() == 0);
    const int context = sceSslInit_nid_postfix(0x100000);
    SslData root{RootPem, sizeof(RootPem)};
    void* roots[] = {&root};
    Require(sceSslLoadCert(context, 1, roots, nullptr, nullptr) == 0);
    Server server;

    bool served = false;
    std::thread serving([&] { served = server.Serve(true); });
    const int socket = Dial(server.Bound());
    const int connection = sceSslCreateConnection(context, socket, "localhost");
    Require(connection > 0);
    Require(sceSslGetAlpnSelected(connection) == nullptr);
    Require(sceSslSetMinSslVersion(connection, 5) == 0);
    Require(Throws([&] { sceSslSetMinSslVersion(connection, 6); }));
    Require(Throws([&] { sceSslSetAlpn(connection, "\x09http/1.1"); }));
    Require(sceSslSetAlpn(connection, "\x02h2\x08http/1.1") == 0);
    char buffer[8]{};
    Require(Throws([&] { sceSslRead(connection, buffer, sizeof(buffer), 0); }));
    Require(sceSslConnect(connection) == 0);
    Require(Throws([&] { sceSslConnect(connection); }));
    Require(Throws([&] { sceSslSetAlpn(connection, "\x02h2"); }));
    Require(std::string(sceSslGetAlpnSelected(connection)) == "http/1.1");
    char ping[] = "ping";
    Require(sceSslWrite(connection, ping, 4, 0) == 4);
    Require(sceSslRead(connection, buffer, sizeof(buffer), 0) == 4 && std::memcmp(buffer, "pong", 4) == 0);
    Require(sceSslClose(connection) == 0);
    Require(Throws([&] { sceSslWrite(connection, ping, 4, 0); }));
    serving.join();
    Require(served);
    Require(sceSslDeleteConnection(connection) == 0);
    Require(sceNetSocketClose(socket) == 0);

    std::thread rejecting([&] { served = server.Serve(false); });
    const int wrongSocket = Dial(server.Bound());
    const int wrongHost = sceSslCreateConnection(context, wrongSocket, "example.com");
    Require(Throws([&] { sceSslConnect(wrongHost); }));
    Require(sceSslDeleteConnection(wrongHost) == 0);
    Require(sceNetSocketClose(wrongSocket) == 0);
    rejecting.join();
    Require(!served);

    const int callbackConnection = sceSslCreateConnection(context, wrongSocket, "localhost");
    Require(sceSslSetVerifyCallback(callbackConnection, VerifyCallback, nullptr) == 0);
    Require(Throws([&] { sceSslConnect(callbackConnection); }));
    Require(sceSslDeleteConnection(callbackConnection) == 0);

    SslCaList list{};
    Require(sceSslGetCaList(context, &list) == 0 && list.num == 1);
    void* subject = sceSslGetSubjectName(context, list.certs[0]);
    void* issuer = sceSslGetIssuerName(context, list.certs[0]);
    Require(subject && issuer && subject != issuer);
    Require(sceSslGetNameEntryCount(context, subject) == 3);
    char oid[16]{};
    std::uint8_t value[32]{};
    std::size_t length = 0;
    Require(sceSslGetNameEntryInfo(context, subject, 2, oid, sizeof(oid), value, sizeof(value), &length) == 0);
    Require(std::string(oid) == "2.5.4.3" && std::string(reinterpret_cast<char*>(value), length) == "AnyPS5 fixture root");
    Require(sceSslGetNameEntryInfo(context, issuer, 0, oid, sizeof(oid), value, sizeof(value), &length) == 0);
    Require(std::string(oid) == "2.5.4.6" && std::string(reinterpret_cast<char*>(value), length) == "GB");
    Require(Throws([&] { sceSslGetNameEntryInfo(context, subject, 3, oid, sizeof(oid), value, sizeof(value), &length); }));
    Require(Throws([&] { sceSslGetNameEntryInfo(context, subject, 2, oid, 7, value, sizeof(value), &length); }));
    Require(Throws([&] { sceSslGetNameEntryInfo(context, subject, 2, oid, sizeof(oid), value, 4, &length); }));
    Require(sceSslFreeSslCertName(context, subject) == 0);
    Require(Throws([&] { sceSslFreeSslCertName(context, subject); }));
    Require(Throws([&] { sceSslGetNameEntryCount(context, subject); }));
    Require(sceSslFreeSslCertName(context, issuer) == 0);
    int foreign = 0;
    Require(Throws([&] { sceSslGetSubjectName(context, &foreign); }));
    Require(sceSslFreeCaList(context, &list) == 0);
    Require(sceSslTerm_nid_postfix(context) == 0);
    return 0;
}
