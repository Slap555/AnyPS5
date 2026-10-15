#include "SslTypes.hpp"
#include "prx/libc/include/General.hpp"

#include "prx/libc/include/GuestArena.hpp"

#include <mbedtls/asn1.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

extern "C" {
std::int64_t NetSend_nid_no_patch(int s, const void* buf, std::size_t len, int flags);
std::int64_t NetRecv_nid_no_patch(int s, void* buf, std::size_t len, int flags);
}

namespace {

constexpr int ErrorNotFound = static_cast<int>(0x8095f004);
constexpr int ErrorInvalidArg = static_cast<int>(0x8095177a);
constexpr int ErrorInvalidId = static_cast<int>(0x8095f006);
constexpr int SslVersionNone = 0;
constexpr int SslVersionTls12 = 5;

struct Pool {
    std::size_t size, current = 0, peak = 0;
    bool exhausted = false;
    std::mutex mutex;
};

struct alignas(std::max_align_t) Allocation {
    Pool* pool;
    std::size_t size;
};

thread_local Pool* currentPool = nullptr;

void* PoolCalloc(std::size_t count, std::size_t size) noexcept {
    if (!currentPool) return nullptr;
    std::lock_guard lock(currentPool->mutex);
    if (size && count > std::numeric_limits<std::size_t>::max() / size) {
        currentPool->exhausted = true;
        return nullptr;
    }
    const auto bytes = count * size;
    if (bytes > currentPool->size - currentPool->current || bytes > std::numeric_limits<std::size_t>::max() - sizeof(Allocation)) {
        currentPool->exhausted = true;
        return nullptr;
    }
    auto* allocation = static_cast<Allocation*>(std::calloc(1, sizeof(Allocation) + bytes));
    if (!allocation) {
        currentPool->exhausted = true;
        return nullptr;
    }
    allocation->pool = currentPool;
    allocation->size = bytes;
    currentPool->current += bytes;
    currentPool->peak = std::max(currentPool->peak, currentPool->current);
    return allocation + 1;
}

void PoolFree(void* pointer) noexcept {
    if (!pointer) return;
    auto* allocation = static_cast<Allocation*>(pointer) - 1;
    {
        std::lock_guard lock(allocation->pool->mutex);
        allocation->pool->current -= allocation->size;
    }
    mbedtls_platform_zeroize(pointer, allocation->size);
    std::free(allocation);
}

struct PoolScope {
    Pool* previous;
    explicit PoolScope(Pool& pool) : previous(std::exchange(currentPool, &pool)) { pool.exhausted = false; }
    ~PoolScope() { currentPool = previous; }
};

struct PoolDeleter {
    void operator()(std::uint8_t* bytes) const { PoolFree(bytes); }
};

using Block = std::unique_ptr<std::uint8_t, PoolDeleter>;

Block Allocate(std::size_t size) {
    Block block(static_cast<std::uint8_t*>(PoolCalloc(1, std::max<std::size_t>(1, size))));
    if (!block) throw std::bad_alloc();
    return block;
}

std::size_t Add(std::size_t left, std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) throw std::length_error("SSL allocation size overflow");
    return left + right;
}

void CheckBackend(int error, const char* message) {
    if (error == 0) return;
    if (currentPool && currentPool->exhausted) throw std::bad_alloc();
    throw std::invalid_argument(message);
}

struct CertificateChain;

struct CertificateHandle {
    std::weak_ptr<CertificateChain> owner;
    const mbedtls_x509_crt* certificate;
};

struct CertificateChain {
    mbedtls_x509_crt root;
    std::vector<CertificateHandle*> handles;
    CertificateChain() { mbedtls_x509_crt_init(&root); }
    ~CertificateChain() { mbedtls_x509_crt_free(&root); }
};

struct PrivateKey {
    mbedtls_pk_context key;
    PrivateKey() { mbedtls_pk_init(&key); }
    ~PrivateKey() { mbedtls_pk_free(&key); }
};

struct Random {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    Random() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
    }
    ~Random() {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
    }
    void Seed() {
        CheckBackend(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, nullptr, 0), "SSL random generator initialization failed");
    }
};

struct Identity {
    std::shared_ptr<CertificateChain> chain;
    PrivateKey key;
};

struct Snapshot {
    Block data;
    std::vector<std::shared_ptr<CertificateChain>> certificates;
    std::size_t count;
};

struct Context {
    Pool pool;
    std::vector<std::shared_ptr<CertificateChain>> authorities;
    std::shared_ptr<Identity> identity;
    std::vector<std::unique_ptr<CertificateHandle>> certificateHandles;
    std::unordered_map<void*, Snapshot> caLists;
    std::unordered_map<void*, Snapshot> caCerts;
    std::unordered_map<void*, std::unique_ptr<struct CertName>> names;
    explicit Context(std::size_t size) : pool{size} {}
};

using SslVerifyCallback = int (APS5_VABI *)(int, unsigned int, void**, int, void*);

Pool& TrustPool() {
    static auto* pool = new Pool{std::numeric_limits<std::size_t>::max()};
    return *pool;
}

using DerList = std::vector<std::vector<std::uint8_t>>;

#ifdef _WIN32
DerList ReadHostRoots() {
    DerList roots;
    const HCERTSTORE store = ::CertOpenSystemStoreW(0, L"ROOT");
    if (!store) return roots;
    for (PCCERT_CONTEXT certificate = ::CertEnumCertificatesInStore(store, nullptr); certificate;
        certificate = ::CertEnumCertificatesInStore(store, certificate)) {
        if (certificate->dwCertEncodingType & X509_ASN_ENCODING)
            roots.emplace_back(certificate->pbCertEncoded, certificate->pbCertEncoded + certificate->cbCertEncoded);
    }
    ::CertCloseStore(store, 0);
    return roots;
}
#else
DerList ReadHostRoots() {
    DerList roots;
    constexpr std::array<const char*, 5> bundles{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"};
    for (const auto* bundle : bundles) {
        std::error_code error;
        if (!std::filesystem::is_regular_file(bundle, error)) continue;
        PoolScope scope(TrustPool());
        mbedtls_x509_crt chain;
        mbedtls_x509_crt_init(&chain);
        if (mbedtls_x509_crt_parse_file(&chain, bundle) >= 0)
            for (auto* entry = &chain; entry && entry->raw.p; entry = entry->next) roots.emplace_back(entry->raw.p, entry->raw.p + entry->raw.len);
        mbedtls_x509_crt_free(&chain);
        if (!roots.empty()) break;
    }
    return roots;
}
#endif

const DerList& HostRoots() {
    static const DerList roots = ReadHostRoots();
    return roots;
}

enum class LinkState { Created, Connected, Closed };

struct Transport {
    std::shared_ptr<Context> context;
    int contextId;
    int socket;
    std::string host;
    SslVerifyCallback verifyCallback = nullptr;
    void* verifyArgument = nullptr;
    std::mutex mutex;
    LinkState state = LinkState::Created;
    int minimumVersion = 0;
    std::vector<std::string> protocols;
    std::vector<const char*> protocolList;
    std::shared_ptr<Identity> identity;
    std::int64_t netError = 0;
    Random random;
    mbedtls_x509_crt trust;
    mbedtls_ssl_config config;
    mbedtls_ssl_context ssl;
    Transport(std::shared_ptr<Context> owner, int id, int sockId, std::string name)
        : context(std::move(owner)), contextId(id), socket(sockId), host(std::move(name)) {
        mbedtls_x509_crt_init(&trust);
        mbedtls_ssl_config_init(&config);
        mbedtls_ssl_init(&ssl);
    }
    ~Transport() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_x509_crt_free(&trust);
    }
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
};

struct CertName {
    std::shared_ptr<CertificateChain> owner;
    const mbedtls_x509_name* name;
};

struct Runtime {
    std::mutex mutex;
    std::unordered_map<int, std::shared_ptr<Context>> contexts;
    std::unordered_map<int, std::shared_ptr<Transport>> connections;
    unsigned nextHandle = 1;
    Runtime() {
        if (mbedtls_platform_set_calloc_free(PoolCalloc, PoolFree) != 0)
            throw std::runtime_error("SSL allocator initialization failed");
    }
};

Runtime& State() {
    static auto* runtime = new Runtime;
    return *runtime;
}

Context& GetContext(int handle) {
    const auto found = State().contexts.find(handle);
    if (found == State().contexts.end()) throw std::invalid_argument("Invalid SSL context");
    return *found->second;
}

Transport& RequireConnection(const char* function, int sslConnectionId) {
    const auto connection = State().connections.find(sslConnectionId);
    if (connection == State().connections.end()) throw std::invalid_argument(std::string(function) + ": unknown connection");
    if (!State().contexts.contains(connection->second->contextId)) {
        throw std::invalid_argument(std::string(function) + ": the connection's context was terminated");
    }
    return *connection->second;
}

std::shared_ptr<Transport> PinConnection(const char* function, int sslConnectionId) {
    std::lock_guard lock(State().mutex);
    RequireConnection(function, sslConnectionId);
    return State().connections.at(sslConnectionId);
}

const mbedtls_x509_crt& RequireCertificate(const char* function, Context& context, void* certificate) {
    for (const auto& handle : context.certificateHandles) {
        if (handle.get() != certificate) continue;
        if (handle->owner.expired()) throw std::invalid_argument(std::string(function) + ": the certificate was unloaded");
        return *handle->certificate;
    }
    throw std::invalid_argument(std::string(function) + ": unknown certificate");
}

CertName& RequireName(const char* function, Context& context, void* certName) {
    const auto found = context.names.find(certName);
    if (found == context.names.end()) throw std::invalid_argument(std::string(function) + ": unknown certificate name");
    return *found->second;
}

int BioSend(void* argument, const unsigned char* buffer, std::size_t length) {
    auto& transport = *static_cast<Transport*>(argument);
    const auto sent = NetSend_nid_no_patch(transport.socket, buffer, std::min<std::size_t>(length, INT_MAX), 0);
    if (sent < 0) {
        transport.netError = sent;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return static_cast<int>(sent);
}

int BioReceive(void* argument, unsigned char* buffer, std::size_t length) {
    auto& transport = *static_cast<Transport*>(argument);
    const auto received = NetRecv_nid_no_patch(transport.socket, buffer, std::min<std::size_t>(length, INT_MAX), 0);
    if (received < 0) {
        transport.netError = received;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return static_cast<int>(received);
}

[[noreturn]] void ThrowBackend(const char* function, Transport& transport, int error) {
    std::string message = std::string(function) + ": ";
    if (error == MBEDTLS_ERR_NET_SEND_FAILED || error == MBEDTLS_ERR_NET_RECV_FAILED) {
        char code[16];
        std::snprintf(code, sizeof(code), "%08x", static_cast<unsigned>(transport.netError));
        throw std::runtime_error(message + "socket " + std::to_string(transport.socket) + " failed with libSceNet error 0x" + code);
    }
    if (error == MBEDTLS_ERR_SSL_WANT_READ || error == MBEDTLS_ERR_SSL_WANT_WRITE)
        throw std::runtime_error(message + "a non-blocking socket is not supported");
    if (const auto flags = mbedtls_ssl_get_verify_result(&transport.ssl); error == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && flags != 0) {
        char info[512];
        mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
        throw std::runtime_error(message + "server certificate verification failed: " + info);
    }
    char text[256];
    mbedtls_strerror(error, text, sizeof(text));
    throw std::runtime_error(message + text);
}

struct Input {
    Block bytes;
    std::size_t size;
};

Input CopyInput(const SceSsl::Data& data) {
    if (!data.ptr || !data.size) throw std::invalid_argument("Empty SSL certificate/key data");
    auto bytes = Allocate(Add(data.size, 1));
    std::memcpy(bytes.get(), data.ptr, data.size);
    auto size = data.size;
    std::size_t first = 0;
    while (first < size && (bytes.get()[first] == ' ' || bytes.get()[first] == '\r' || bytes.get()[first] == '\n' || bytes.get()[first] == '\t')) ++first;
    const bool pem = first < size && bytes.get()[first] == '-';
    if (pem) {
        if (bytes.get()[size - 1] != 0) ++size;
        if (std::memchr(bytes.get(), 0, size - 1)) throw std::invalid_argument("Embedded null in SSL PEM data");
    } else {
        auto* position = bytes.get();
        std::size_t length = 0;
        CheckBackend(mbedtls_asn1_get_tag(&position, bytes.get() + size, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE),
            "Invalid SSL DER sequence");
        if (length != static_cast<std::size_t>(bytes.get() + size - position)) throw std::invalid_argument("Trailing SSL DER data");
    }
    return {std::move(bytes), size};
}

std::shared_ptr<CertificateChain> ParseCertificate(const SceSsl::Data& data) {
    auto chain = std::make_shared<CertificateChain>();
    const auto input = CopyInput(data);
    CheckBackend(mbedtls_x509_crt_parse(&chain->root, input.bytes.get(), input.size), "Invalid SSL certificate chain");
    return chain;
}

std::size_t CertificateCount(const Context& context) {
    std::size_t count = 0;
    for (const auto& chain : context.authorities) count = Add(count, chain->handles.size());
    return count;
}

}

extern "C" {

int APS5_VABI sceSslInit_nid_postfix(std::uint64_t poolSize) {
    auto& state = State();
    std::lock_guard lock(state.mutex);
    if (state.nextHandle > static_cast<unsigned>(std::numeric_limits<int>::max())) throw std::overflow_error("SSL context handles exhausted");
    const auto handle = static_cast<int>(state.nextHandle);
    state.contexts.emplace(handle, std::make_shared<Context>(poolSize));
    ++state.nextHandle;
    return handle;
}

int APS5_VABI sceSslTerm_nid_postfix(int sslCtxId) {
    auto& state = State();
    std::lock_guard lock(state.mutex);
    state.contexts.erase(sslCtxId);
    return 0;
}

int APS5_VABI sceSslGetMemoryPoolStats(int sslCtxId, SceSsl::MemoryPoolStats* stats) {
    if (!stats) return static_cast<int>(0x8095F007);
    auto& state = State();
    std::lock_guard lock(state.mutex);
    const auto found = state.contexts.find(sslCtxId);
    if (found == state.contexts.end()) {
        std::memset(stats, 0, sizeof(*stats));
        return static_cast<int>(0x8095F006);
    }
    const auto& pool = found->second->pool;
    *stats = {pool.size, pool.peak, pool.current, 0};
    return 0;
}

int APS5_VABI sceSslLoadCert(int sslCtxId, int caCertNum, SceSsl::Data** caList, SceSsl::Data* cert, SceSsl::Data* privateKey) {
    if (caCertNum < 0 || (caCertNum && !caList) || (!!cert != !!privateKey))
        throw std::invalid_argument("Invalid SSL certificate load arguments");
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    PoolScope scope(context.pool);
    std::vector<std::shared_ptr<CertificateChain>> authorities;
    std::vector<std::unique_ptr<CertificateHandle>> handles;
    for (int index = 0; index < caCertNum; ++index) {
        if (!caList[index]) throw std::invalid_argument("Missing SSL certificate descriptor");
        auto chain = ParseCertificate(*caList[index]);
        for (auto* entry = &chain->root; entry; entry = entry->next) {
            auto handle = std::make_unique<CertificateHandle>(CertificateHandle{chain, entry});
            chain->handles.push_back(handle.get());
            handles.push_back(std::move(handle));
        }
        authorities.push_back(std::move(chain));
    }
    std::shared_ptr<Identity> identity;
    if (cert) {
        identity = std::make_shared<Identity>();
        identity->chain = ParseCertificate(*cert);
        const auto key = CopyInput(*privateKey);
        Random random;
        random.Seed();
        CheckBackend(mbedtls_pk_parse_key(&identity->key.key, key.bytes.get(), key.size, nullptr, 0,
            mbedtls_ctr_drbg_random, &random.drbg), "Invalid SSL private key");
        CheckBackend(mbedtls_pk_check_pair(&identity->chain->root.pk, &identity->key.key, mbedtls_ctr_drbg_random, &random.drbg),
            "SSL client certificate and private key do not match");
    }
    context.authorities.reserve(Add(context.authorities.size(), authorities.size()));
    context.certificateHandles.reserve(Add(context.certificateHandles.size(), handles.size()));
    for (auto& chain : authorities) context.authorities.push_back(std::move(chain));
    for (auto& handle : handles) context.certificateHandles.push_back(std::move(handle));
    if (identity) context.identity = std::move(identity);
    return 0;
}

int APS5_VABI sceSslUnloadCert(int sslCtxId) {
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    context.authorities.clear();
    context.identity.reset();
    return 0;
}

int APS5_VABI sceSslGetCaList(int sslCtxId, SceSsl::CaList* output) {
    if (!output) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    PoolScope scope(context.pool);
    const auto count = CertificateCount(context);
    if (!count) {
        *output = {};
        return ErrorNotFound;
    }
    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::length_error("Too many SSL authorities");
    Snapshot snapshot{Allocate(count * sizeof(void*)), context.authorities, count};
    auto** pointers = reinterpret_cast<void**>(snapshot.data.get());
    std::size_t index = 0;
    for (const auto& chain : snapshot.certificates) for (auto* handle : chain->handles) pointers[index++] = handle;
    context.caLists.emplace(pointers, std::move(snapshot));
    *output = {pointers, static_cast<int>(count)};
    return 0;
}

int APS5_VABI sceSslFreeCaList(int sslCtxId, SceSsl::CaList* list) {
    if (!list) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    auto& context = GetContext(sslCtxId);
    if (!list->certs && list->num == 0) return 0;
    const auto found = context.caLists.find(list->certs);
    if (found == context.caLists.end() || list->num < 0 || static_cast<std::size_t>(list->num) != found->second.count)
        throw std::invalid_argument("Invalid SSL CA list allocation");
    context.caLists.erase(found);
    *list = {};
    return 0;
}

int APS5_VABI sceSslGetCaCerts(int sslCtxId, SceSsl::CaCerts* output) {
    if (!output) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    const auto found = state.contexts.find(sslCtxId);
    if (found == state.contexts.end()) {
        *output = {};
        return ErrorNotFound;
    }
    auto& context = *found->second;
    PoolScope scope(context.pool);
    const auto count = CertificateCount(context);
    if (!count) {
        *output = {};
        return ErrorNotFound;
    }
    if (count > std::numeric_limits<std::size_t>::max() / sizeof(SceSsl::Data)) throw std::length_error("Too many SSL authorities");
    auto total = count * sizeof(SceSsl::Data);
    for (const auto& chain : context.authorities)
        for (auto* entry = &chain->root; entry; entry = entry->next) total = Add(total, entry->raw.len);
    Snapshot snapshot{Allocate(total), {}, count};
    auto* data = reinterpret_cast<SceSsl::Data*>(snapshot.data.get());
    auto* next = snapshot.data.get() + count * sizeof(SceSsl::Data);
    std::size_t index = 0;
    for (const auto& chain : context.authorities) {
        for (auto* entry = &chain->root; entry; entry = entry->next) {
            data[index++] = {next, entry->raw.len};
            std::memcpy(next, entry->raw.p, entry->raw.len);
            next += entry->raw.len;
        }
    }
    context.caCerts.emplace(data, std::move(snapshot));
    *output = {data, count, data};
    return 0;
}

int APS5_VABI sceSslFreeCaCerts(int sslCtxId, SceSsl::CaCerts* certificates) {
    if (!certificates) return ErrorInvalidArg;
    auto& state = State();
    std::lock_guard lock(state.mutex);
    const auto found = state.contexts.find(sslCtxId);
    if (found != state.contexts.end()) {
        auto& snapshots = found->second->caCerts;
        const auto allocation = snapshots.find(certificates->pool);
        if (allocation != snapshots.end()) {
            if (certificates->certs != certificates->pool || certificates->num != allocation->second.count)
                throw std::invalid_argument("Invalid SSL CA certificate allocation");
            snapshots.erase(allocation);
        }
    }
    *certificates = {};
    return 0;
}

int APS5_VABI sceSslCreateConnection(int sslCtxId, int sockId, const char* host) {
    if (!host) throw std::invalid_argument("sceSslCreateConnection: null host");
    std::lock_guard lock(State().mutex);
    auto& state = State();
    const auto context = state.contexts.find(sslCtxId);
    if (context == state.contexts.end()) return ErrorInvalidId;
    if (state.nextHandle > static_cast<unsigned>(std::numeric_limits<int>::max())) throw std::overflow_error("SSL connection handles exhausted");
    const auto id = static_cast<int>(state.nextHandle);
    state.connections.emplace(id, std::make_shared<Transport>(context->second, sslCtxId, sockId, host));
    ++state.nextHandle;
    return id;
}

int APS5_VABI sceSslDeleteConnection(int sslConnectionId) {
    std::shared_ptr<Transport> removed;
    {
        std::lock_guard lock(State().mutex);
        const auto found = State().connections.find(sslConnectionId);
        if (found == State().connections.end()) throw std::invalid_argument("sceSslDeleteConnection: unknown connection");
        removed = std::move(found->second);
        State().connections.erase(found);
    }
    return 0;
}

int APS5_VABI sceSslSetVerifyCallback(int sslConnectionId, SslVerifyCallback cbfunc, void* userArg) {
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    transport->verifyCallback = cbfunc;
    transport->verifyArgument = userArg;
    return 0;
}

int APS5_VABI sceSslSetMinSslVersion(int sslConnectionId, int version) {
    if (version < SslVersionNone || version > SslVersionTls12) throw std::invalid_argument("sceSslSetMinSslVersion: unknown version " + std::to_string(version));
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state != LinkState::Created) throw std::invalid_argument("sceSslSetMinSslVersion: the handshake already ran");
    transport->minimumVersion = version;
    return 0;
}

int APS5_VABI sceSslSetAlpn(int sslConnectionId, const char* proto) {
    if (!proto || !*proto) throw std::invalid_argument("sceSslSetAlpn: null or empty protocol list");
    std::vector<std::string> protocols;
    const auto* wire = reinterpret_cast<const std::uint8_t*>(proto);
    const std::size_t size = std::strlen(proto);
    for (std::size_t offset = 0; offset < size;) {
        const std::size_t length = wire[offset];
        if (offset + 1 + length > size) throw std::invalid_argument("sceSslSetAlpn: malformed wire-format protocol list");
        protocols.emplace_back(proto + offset + 1, length);
        offset += 1 + length;
    }
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state != LinkState::Created) throw std::invalid_argument("sceSslSetAlpn: the handshake already ran");
    transport->protocols = std::move(protocols);
    transport->protocolList.clear();
    for (const auto& protocol : transport->protocols) transport->protocolList.push_back(protocol.c_str());
    transport->protocolList.push_back(nullptr);
    return 0;
}

const char* APS5_VABI sceSslGetAlpnSelected(int sslConnectionId) {
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state == LinkState::Created) return nullptr;
    return mbedtls_ssl_get_alpn_protocol(&transport->ssl);
}

int APS5_VABI sceSslConnect(int sslConnectionId) {
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state != LinkState::Created) throw std::invalid_argument("sceSslConnect: the handshake already ran");
    if (transport->verifyCallback) NotImplemented_nid_no_patch("sceSslConnect: a verify callback");
    if (transport->host.empty()) throw std::invalid_argument("sceSslConnect: empty host");
    DerList anchors = HostRoots();
    {
        std::lock_guard lock(State().mutex);
        for (const auto& chain : transport->context->authorities)
            for (auto* entry = &chain->root; entry && entry->raw.p; entry = entry->next) anchors.emplace_back(entry->raw.p, entry->raw.p + entry->raw.len);
        transport->identity = transport->context->identity;
    }
    {
        PoolScope scope(TrustPool());
        for (const auto& anchor : anchors) mbedtls_x509_crt_parse_der(&transport->trust, anchor.data(), anchor.size());
    }
    PoolScope scope(transport->context->pool);
    transport->random.Seed();
    CheckBackend(mbedtls_ssl_config_defaults(&transport->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT),
        "SSL configuration failed");
    mbedtls_ssl_conf_authmode(&transport->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&transport->config, &transport->trust, nullptr);
    mbedtls_ssl_conf_rng(&transport->config, mbedtls_ctr_drbg_random, &transport->random.drbg);
    mbedtls_ssl_conf_min_tls_version(&transport->config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&transport->config, MBEDTLS_SSL_VERSION_TLS1_2);
    if (transport->identity)
        CheckBackend(mbedtls_ssl_conf_own_cert(&transport->config, &transport->identity->chain->root, &transport->identity->key.key),
            "SSL client certificate setup failed");
    if (!transport->protocolList.empty())
        CheckBackend(mbedtls_ssl_conf_alpn_protocols(&transport->config, transport->protocolList.data()), "SSL ALPN setup failed");
    CheckBackend(mbedtls_ssl_setup(&transport->ssl, &transport->config), "SSL connection setup failed");
    CheckBackend(mbedtls_ssl_set_hostname(&transport->ssl, transport->host.c_str()), "SSL host name setup failed");
    mbedtls_ssl_set_bio(&transport->ssl, transport.get(), BioSend, BioReceive, nullptr);
    transport->state = LinkState::Closed;
    if (const int error = mbedtls_ssl_handshake(&transport->ssl)) ThrowBackend(__func__, *transport, error);
    transport->state = LinkState::Connected;
    return 0;
}

int APS5_VABI sceSslRead(int sslConnectionId, void* buf, size_t len, int flags) {
    if (flags != 0) NotImplemented_nid_no_patch("sceSslRead: nonzero flags");
    if (!buf && len) throw std::invalid_argument("sceSslRead: null buffer");
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state != LinkState::Connected) throw std::invalid_argument("sceSslRead: the connection is not established");
    if (len == 0) return 0;
    const auto size = std::min<std::size_t>(len, INT_MAX);
    const GuestArena::HostWrite destination(buf, size);
    if (!destination.Open()) throw std::invalid_argument("sceSslRead: the buffer is not writable");
    PoolScope scope(transport->context->pool);
    const int result = mbedtls_ssl_read(&transport->ssl, static_cast<unsigned char*>(buf), size);
    if (result >= 0) return result;
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || result == MBEDTLS_ERR_SSL_CONN_EOF) return 0;
    ThrowBackend(__func__, *transport, result);
}

int APS5_VABI sceSslWrite(int sslConnectionId, void* buf, size_t len, int flags) {
    if (flags != 0) NotImplemented_nid_no_patch("sceSslWrite: nonzero flags");
    if (!buf && len) throw std::invalid_argument("sceSslWrite: null buffer");
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state != LinkState::Connected) throw std::invalid_argument("sceSslWrite: the connection is not established");
    if (len == 0) return 0;
    PoolScope scope(transport->context->pool);
    const int result = mbedtls_ssl_write(&transport->ssl, static_cast<const unsigned char*>(buf), std::min<std::size_t>(len, INT_MAX));
    if (result >= 0) return result;
    ThrowBackend(__func__, *transport, result);
}

int APS5_VABI sceSslClose(int sslConnectionId) {
    const auto transport = PinConnection(__func__, sslConnectionId);
    std::lock_guard lock(transport->mutex);
    if (transport->state != LinkState::Connected) throw std::invalid_argument("sceSslClose: the connection is not established");
    transport->state = LinkState::Closed;
    PoolScope scope(transport->context->pool);
    if (const int error = mbedtls_ssl_close_notify(&transport->ssl)) ThrowBackend(__func__, *transport, error);
    return 0;
}

void* APS5_VABI sceSslGetSubjectName(int sslCtxId, void* sslCert) {
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    const auto& certificate = RequireCertificate(__func__, context, sslCert);
    auto name = std::make_unique<CertName>(CertName{static_cast<CertificateHandle*>(sslCert)->owner.lock(), &certificate.subject});
    auto* handle = name.get();
    context.names.emplace(handle, std::move(name));
    return handle;
}

void* APS5_VABI sceSslGetIssuerName(int sslCtxId, void* sslCert) {
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    const auto& certificate = RequireCertificate(__func__, context, sslCert);
    auto name = std::make_unique<CertName>(CertName{static_cast<CertificateHandle*>(sslCert)->owner.lock(), &certificate.issuer});
    auto* handle = name.get();
    context.names.emplace(handle, std::move(name));
    return handle;
}

int APS5_VABI sceSslGetNameEntryCount(int sslCtxId, void* certName) {
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    const auto& name = RequireName(__func__, context, certName);
    int count = 0;
    for (const auto* entry = name.name; entry && entry->oid.p; entry = entry->next) ++count;
    return count;
}

int APS5_VABI sceSslGetNameEntryInfo(int sslCtxId, void* certName, int entryNum, char* oidname, size_t maxOidnameLen,
    std::uint8_t* value, size_t maxValueLen, size_t* valueLen) {
    if (!oidname || !value || !valueLen) throw std::invalid_argument("sceSslGetNameEntryInfo: null output");
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    const auto& name = RequireName(__func__, context, certName);
    const auto* entry = name.name;
    for (int index = 0; entry && entry->oid.p && index < entryNum; ++index) entry = entry->next;
    if (entryNum < 0 || !entry || !entry->oid.p) throw std::invalid_argument("sceSslGetNameEntryInfo: entry " + std::to_string(entryNum) + " does not exist");
    std::array<char, 128> oid{};
    const int written = mbedtls_oid_get_numeric_string(oid.data(), oid.size(), &entry->oid);
    if (written < 0) throw std::invalid_argument("sceSslGetNameEntryInfo: unprintable OID");
    if (static_cast<std::size_t>(written) >= maxOidnameLen) throw std::length_error("sceSslGetNameEntryInfo: OID buffer too small");
    if (entry->val.len > maxValueLen) throw std::length_error("sceSslGetNameEntryInfo: value buffer too small");
    std::memcpy(oidname, oid.data(), static_cast<std::size_t>(written) + 1);
    std::memcpy(value, entry->val.p, entry->val.len);
    *valueLen = entry->val.len;
    return 0;
}

int APS5_VABI sceSslFreeSslCertName(int sslCtxId, void* certName) {
    std::lock_guard lock(State().mutex);
    auto& context = GetContext(sslCtxId);
    RequireName(__func__, context, certName);
    context.names.erase(certName);
    return 0;
}

int APS5_VABI sceSslGetSerialNumber(int sslCtxId, void* sslCert, std::uint8_t* sboData, size_t* sboLen) {
    (void)sslCtxId;
    (void)sslCert;
    (void)sboData;
    (void)sboLen;
    NotImplemented_nid_no_patch(__func__);
    return 0;
}

int APS5_VABI sceSslEnableVerifyOption(int sslConnectionId, unsigned int option) {
    (void)sslConnectionId;
    (void)option;
    NotImplemented_nid_no_patch(__func__);
    return 0;
}

int APS5_VABI sceSslDisableVerifyOption(int sslConnectionId, unsigned int option) {
    (void)sslConnectionId;
    (void)option;
    NotImplemented_nid_no_patch(__func__);
    return 0;
}

int APS5_VABI sceSslGetPem(void) {
    NotImplemented_nid_no_patch(__func__);
    return 0;
}

}
