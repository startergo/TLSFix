#ifndef AQUATRANSPORT_H
#define AQUATRANSPORT_H

#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Availability.h>
#include <openssl/ssl.h>

// The 10.8 additions to Secure Transport that the 10.6 SDK predates: SSLCreateContext and
// the types it takes. Declared here, exactly as the 10.8+ SDKs declare them, when building
// against an SDK that does not know them (__MAC_10_8 first appears in the 10.8 SDK's
// Availability.h), so the library builds on a 10.6 machine with nothing but its own SDK.
// Compile-time only: the hooks resolve every Secure Transport entry point with dlsym at
// first call and never link against these, and on a 10.6 the hook for SSLCreateContext has
// no call sites to rebind, which is the `absent` row in the hook table.
#if !defined(__MAC_10_8)
typedef enum {
    kSSLClientSide = 0,
    kSSLServerSide
} SSLProtocolSide;
typedef enum {
    kSSLStreamType = 0,
    kSSLDataType
} SSLConnectionType;
extern SSLContextRef SSLCreateContext(CFAllocatorRef alloc, SSLProtocolSide protocolSide,
                                      SSLConnectionType connectionType);
#endif

// Secure Transport result codes
#ifndef errSSLWouldBlock
#define errSSLWouldBlock  -9803
#endif
// paramErr, which Secure Transport answers for a bad argument. Named the way the codes below
// are because it is not reachable through the headers this library compiles against: it lives
// in MacTypes, which nothing here imports.
#define ST_Param          -50
#define ST_ClosedGraceful -9805
#define ST_ClosedAbort    -9806
#define ST_PeerAuth       -9841
// errSSLClientCertRequested: the server has asked for a client certificate and the caller
// asked to be paused here -- kSSLSessionOptionBreakOnCertRequested, the on-demand identity
// flow. errSSLServerAuthCompleted (-9841, ST_PeerAuth above) is the other break.
#define ST_CertReq        -9842
#define ST_Internal       -9838
#define ST_Connected       2
#define ST_TLS12           8

// Security.framework on OS X exports SecKeyRawSign -- verified present on both 10.6.8 and
// 10.9.5, in both slices -- but declares it only in the iOS headers, so declare it here for
// the mtls signing path.
extern OSStatus SecKeyRawSign(SecKeyRef key, SecPadding padding,
                              const uint8_t *dataToSign, size_t dataToSignLen,
                              uint8_t *sig, size_t *sigLen);

// Same story for SecKeyDecrypt, which is how the PSS path reaches a bare private-key
// operation -- see rsa_seckey_priv_enc. SecKeyRawSign cannot do it: its kSecPaddingNone
// still applies PKCS#1 v1.5 padding on OS X ("None" means no DigestInfo, not no padding),
// measured as an input cap of blocksize-11 on 10.9.5 -- tools/pssprobe.c reproduces it.
extern OSStatus SecKeyDecrypt(SecKeyRef key, SecPadding padding,
                              const uint8_t *cipherText, size_t cipherTextLen,
                              uint8_t *plainText, size_t *plainTextLen);

typedef struct {
    SSLContextRef    ctx;
    SSLReadFunc      rf;
    SSLWriteFunc     wf;
    SSLConnectionRef conn;
    char             host[256];
    // The caller's SSLSetPeerID blob: opaque bytes that identify the endpoint, and the key
    // the session cache runs on. See the cache comment in aquatransport_engine.c. A peer id
    // longer than the buffer is recorded as absent (peerIDLen 0), which costs that connection
    // resumption and nothing else; CFNetwork's is 36 bytes.
    unsigned char    peerID[256];
    size_t           peerIDLen;
    int              inited;
    // Handshake states the hooks branch on: 0 fresh, 1 handshaking, 2 connected,
    // 3 paused at the server-auth break, 4 paused at the cert-request break.
    int              state;
    int              breakAuth;
    // kSSLSessionOptionBreakOnCertRequested: the caller wants errSSLClientCertRequested
    // when the server asks for a client certificate, whatever identity is installed, and
    // supplies its certificate only then -- SSLSetCertificate's contract allows exactly
    // that call between the pause and the resume. The pause itself is selected in
    // my_SSLHandshake; the suspension is client_cert_cb returning -1.
    int              breakCertReq;
    // SSLSetEnableCertVerify(false): the caller has taken the certificate check on itself --
    // what curl's -k does on this platform. Secure Transport then completes the handshake
    // whatever the chain says, and leaves the caller to fetch it with SSLCopyPeerTrust.
    int              noCertVerify;
    int              approved;
    // The cert-request pause's counterpart of approved: set when the caller has resumed
    // from it, so client_cert_cb does not suspend into the same pause twice.
    int              certApproved;
    // Set the first time client_cert_cb runs in this handshake. The callback fires exactly
    // when the server's CertificateRequest arrives, which is the fact the client-certificate
    // state query is asking about -- an identity being installed says nothing about whether
    // the server asked. Reset with the handshake, like approved.
    int              certReqSeen;
    int              clientBypass;
    // Set on a context created with kSSLServerSide. This engine speaks the client half of the
    // handshake -- ossl_init calls SSL_set_connect_state -- so a server context is left to the
    // system stack entire, the way clientBypass leaves it a client certificate we cannot carry.
    int              serverSide;
    X509            *clientX509;
    STACK_OF(X509)  *clientChain;
    SecKeyRef        clientKey;
    unsigned         lastUse;
    int              refcount;
    SSL             *ssl;
    // Evaluated peer trust for this connection, built once. CFNetwork asks for it on every
    // request, so it is built per connection rather than per request. See sh_build_trust.
    SecTrustRef      trust;
    // Set once the caller's write callback has reported would-block, and cleared each time
    // the caller re-enters us. See bio_bwrite: the callback must be asked at most once per
    // entry, the way Secure Transport asks it.
    int              wblocked;
    // Plaintext accepted from the caller that the socket has not taken yet -- Secure
    // Transport's write queue. See sh_flush_write.
    unsigned char   *wpend;
    size_t           wpendLen;
} Shadow;

// Re-entrancy guard. Our verify path calls into Security, which may itself open a
// connection (revocation checks); without this, that nested connection would come back
// through our hooks and call Security again. Set around our own Security calls; hooks
// fall through to the system stack while it is set. pthread_specific rather than __thread
// because native TLS needs a 10.7+ deployment target.
void       tf_guard_enter(void);
void       tf_guard_leave(void);
int        tf_reentrant(void);

int        ensure_ready(void);
Shadow    *sh_get(SSLContextRef c);
Shadow    *sh_create(SSLContextRef c);
void       sh_release(Shadow *s);
void       sh_free(SSLContextRef c);
int        ossl_init(Shadow *s);
void       capture_identity(Shadow *s, CFArrayRef certRefs, int mayBypass);
int        sh_build_trust(Shadow *s, SecTrustRef *trust);
CFArrayRef sh_cert_array(Shadow *s);
void       sh_unblock_write(Shadow *s);
void       sh_reset_write(Shadow *s);
int        sh_flush_write(Shadow *s);
int        sh_hold_write(Shadow *s, const void *data, size_t len);

// The largest run of a caller's buffer handed to one SSL_read or SSL_write, whose lengths are
// ints where SSLRead's and SSLWrite's dataLength is a size_t. Anything longer is transferred
// in several runs, so a caller may pass a buffer of any size -- as it may to Secure Transport,
// which fragments internally and documents no limit. Bounds the write queue too: a blocked run
// adds at most this much to it.
#define IO_RUN_MAX      ((size_t)65536)

#endif
