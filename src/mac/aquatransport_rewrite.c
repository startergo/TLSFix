// URL rewriting in pure C, on CFNetwork's own C API.
//
// WHY NOT NSURLProtocol
//
// An Objective-C NSURLProtocol bundle would have to dlopen into each process, pulling
// Foundation and the ObjC runtime in before main() -- fatal to anything that forks without
// exec: sshd's privilege-separation child aborts in libdispatch and every ssh connection
// dies, and loginwindow hits a login-keychain failure. No per-process gate avoids it --
// "a Foundation symbol is resolvable" is true inside sshd, and "the main executable links
// Foundation" excludes Safari and WebProcess (they reach it through WebKit) while including
// loginwindow. Excluding processes by name only hides the fragility. Pure C on CFNetwork's
// own API touches none of that.
//
// Foundation's own URL loading is built on the C API used here (Foundation imports 69 of
// these symbols on 10.9, 53 on 10.6.8), so working at this level covers NSURLConnection,
// NSURLSession and raw CFNetwork clients while touching no Objective-C at all.
//
// WHY fishhook RATHER THAN dyld INTERPOSING
//
// A __DATA,__interpose section only affects images bound after the interposing library is
// registered, and dyld registers it only for libraries inserted at launch. This library
// arrives as a dependency of Security.framework, which a process may dlopen at any point, and
// an image loaded then changes nothing in a process whose imports are already bound.
//
// Interposing also matches by address rather than by name, so a hook cannot be installed
// until the target library is loaded and its symbols are addressable. Rebinding by name
// needs nothing loaded, so the library sits inert in a process without CFNetwork and starts
// working if and when CFNetwork arrives.
//
// THE HOOK POINTS come from experiment, not from headers. Sync and async funnel through
// different entry points, and the request argument position is the one found by recording
// pointers returned from the request-creating functions and testing the funnel arguments for
// pointer *equality* -- no guessed pointer is ever dereferenced:
//
//   CFURLConnectionSendSynchronousRequest   arg0 = CFURLRequestRef   (sync)
//   CFURLConnectionCreateWithProperties     arg1 = CFURLRequestRef   (async)
//   CFHTTPMessageCreateRequest              arg2 = CFURLRef          (raw stream)
//   CFHTTPMessageSetHeaderFieldValue        arg0 = CFHTTPMessageRef  (raw stream)
//
// A client that builds a CFHTTPMessage and opens a stream on it reaches none of the
// CFURLRequest entry points. Such a message also carries only the headers its author set, so
// the request can go out with no User-Agent at all, which some servers answer with an error
// instead of results.
//
// The message is taken at creation rather than at CFReadStreamCreateForHTTPRequest because that
// function is one applications replace for themselves: Dictionary bundles a ProxyFix.dylib that
// interposes it to route requests through the system proxy. Two hooks on one symbol each call
// what they take to be the original, which is the other, and the pair recurses until the stack
// is gone. Creation is uncontended.
//
// The setter is hooked because a caller may set headers after creating the message --
// DictionaryServices stamps User-Agent: AppleDictionaryService/208 over whatever is there. A
// write to a header a rule owns is dropped, leaving the rule's value; every other header is set
// as the caller asked.

#include "aquatransport_config.h"
#include "aquatransport_gsa_mail.h"
#include "../../deps/fishhook/fishhook.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

typedef void *(*fn6)(void *, void *, void *, void *, void *, void *);

// Resolved at first use with dlsym rather than linked. By the time a hook runs we are
// inside a CFNetwork call, so CFNetwork is loaded and these always resolve.
static CFURLRef (*p_GetURL)(void *);
static void    *(*p_MutableCopy)(CFAllocatorRef, void *);
static void     (*p_SetURL)(void *, CFURLRef);
static void     (*p_SetHeader)(void *, CFStringRef, CFStringRef);
static fn6       p_CreateConnection;
static int       g_resolved;
static pthread_once_t g_resolve_once = PTHREAD_ONCE_INIT;

static void resolve_once(void) {
    p_GetURL      = (CFURLRef (*)(void *))dlsym(RTLD_DEFAULT, "CFURLRequestGetURL");
    p_MutableCopy = (void *(*)(CFAllocatorRef, void *))dlsym(RTLD_DEFAULT, "CFURLRequestCreateMutableCopy");
    p_SetURL      = (void (*)(void *, CFURLRef))dlsym(RTLD_DEFAULT, "CFURLRequestSetURL");
    p_SetHeader   = (void (*)(void *, CFStringRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFURLRequestSetHTTPHeaderFieldValue");
    p_CreateConnection = (fn6)dlsym(RTLD_DEFAULT, "CFURLConnectionCreate");
    g_resolved = (p_GetURL && p_MutableCopy && p_SetURL && p_SetHeader);
}
static int resolved(void) { pthread_once(&g_resolve_once, resolve_once); return g_resolved; }

// The CFHTTPMessage side, resolved the same way and for the same reason: a direct call would
// make CFNetwork a load-time dependency of this library. Nothing else interposes these, so the
// first definition in load order is CFNetwork's own.
static void *(*p_MsgCreate)(CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef);
static void  (*p_MsgSetHeader)(void *, CFStringRef, CFStringRef);
static CFURLRef (*p_MsgURL)(void *);
static int g_msg_resolved;
static pthread_once_t g_msg_once = PTHREAD_ONCE_INIT;

static void resolve_msg_once(void) {
    p_MsgCreate    = (void *(*)(CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef))
                     dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest");
    p_MsgSetHeader = (void (*)(void *, CFStringRef, CFStringRef))
                     dlsym(RTLD_DEFAULT, "CFHTTPMessageSetHeaderFieldValue");
    p_MsgURL       = (CFURLRef (*)(void *))dlsym(RTLD_DEFAULT, "CFHTTPMessageCopyRequestURL");
    g_msg_resolved = (p_MsgCreate && p_MsgSetHeader && p_MsgURL);
}
static int msg_resolved(void) { pthread_once(&g_msg_once, resolve_msg_once); return g_msg_resolved; }

static char *cf_to_c(CFStringRef s) {
    if (!s) return NULL;
    CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
    char *buf = (char *)malloc((size_t)max);
    if (!buf) return NULL;
    if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8)) { free(buf); return NULL; }
    return buf;
}

/* Authentication needs Foundation, but loading it from Security's constructor breaks
 * fork-based daemons. Load this authentication image only inside a relevant URL request,
 * after Foundation is already present, on Lion or later. No ObjC imports in the engine. */
static pthread_once_t g_gsa_once = PTHREAD_ONCE_INIT;
static void load_gsa_once(void) {
    struct utsname os;
    if (uname(&os) || atoi(os.release) < 11) return;
    Dl_info info;
    char path[1024];
    if (!dladdr((void *)&load_gsa_once, &info) || !info.dli_fname) return;
    const char *slash = strrchr(info.dli_fname, '/');
    if (!slash || snprintf(path, sizeof path, "%.*s/aquatransport_gsa.dylib",
            (int)(slash-info.dli_fname), info.dli_fname) >= sizeof path) return;
    if (!dlopen(path, RTLD_NOW | RTLD_LOCAL) && tf_debug())
        tf_log("iCloud GSA module could not be loaded");
}

static void prepare_gsa(void) {
    void *(*get_class)(const char *) = dlsym(RTLD_DEFAULT, "objc_getClass");
    // A C-only request must not consume the once token: Foundation may arrive later.
    if (get_class && get_class("NSURLConnection")) pthread_once(&g_gsa_once, load_gsa_once);
}

/* Mail's socket transport need not make an HTTP request before authentication.
 * Enter here from TLS setup, outside all TLS locks and after MailCore is loaded.
 * No Foundation or Objective-C library is linked into this C engine. */
void tf_gsa_prepare_mail(const char *host, size_t length) {
    if (!aq_mail_host(host, length) || tf_flag("disable-icloud-gsa")) return;
    void *(*get_class)(const char *) = dlsym(RTLD_DEFAULT, "objc_getClass");
    if (!get_class || !get_class("_MCAppleTokenSaslClient")) return;
    prepare_gsa();
    void *adapter = get_class("AQMailTokenAdapter");
    void *(*selector)(const char *) = dlsym(RTLD_DEFAULT, "sel_registerName");
    void (*send)(void *, void *) = dlsym(RTLD_DEFAULT, "objc_msgSend");
    if (adapter && selector && send) send(adapter, selector("install"));
}

/* Keychain traffic arrives here for the same reason Mail does: syncdefaultsd
 * builds its KVS requests inside NSURLSession, which passes through none of
 * the request or message construction points above, so the first this library
 * learns of the exchange is the TLS peer name. Loading the module here arms
 * the streaming adapter in time for the next attempt -- the KVS client
 * retries -- and the direct message injection covers any stream-path callers
 * the Foundation protocol still cannot see. */
void tf_gsa_prepare_keychain(const char *host, size_t length) {
    if (tf_flag("disable-icloud-gsa")) return;
    /* Reached from the SSLSetPeerDomainName hook before Secure Transport has
     * validated anything, so a NULL name arrives exactly as the caller sent it. */
    if (!host || length < 22) return;
    int kv = length >= 26 && !strncasecmp(host + length - 26, "keyvalueservice.icloud.com", 26);
    int escrow = !kv && !strncasecmp(host + length - 22, "escrowproxy.icloud.com", 22);
    if (!kv && !escrow) return;
    prepare_gsa();
}

static int gsa_dav_url(const char *url) {
    if (strncasecmp(url, "https://", 8)) return 0;
    const char *h = url + 8, *end = h + strcspn(h, "/?#");
    /* Native CoreDAV discovery embeds the account name in the authority. Match
     * the host after userinfo, never a hostname inside the username or path. */
    for (const char *p = h; p < end; p++) if (*p == '@') h = p + 1;
    if (*h == 'p' || *h == 'P') {
        h++;
        const char *digits = h;
        while (*h >= '0' && *h <= '9') h++;
        if (h == digits || *h++ != '-') return 0;
    }
    size_t n; const char *legacy;
    if (!strncasecmp(h, "caldav.icloud.com", 17)) { n = 17; legacy = ":8443"; }
    else if (!strncasecmp(h, "contacts.icloud.com", 19)) { n = 19; legacy = ":8843"; }
    /* iCloud Keychain parameter and escrow traffic carries the same modern
     * token authentication and needs the same device headers as DAV; the KVS
     * client (syncdefaultsd) is Foundation and runs the streaming adapter.
     * These hosts are 443-only. */
    else if (!strncasecmp(h, "keyvalueservice.icloud.com", 26)) { n = 26; legacy = NULL; }
    else if (!strncasecmp(h, "escrowproxy.icloud.com", 22)) { n = 22; legacy = NULL; }
    else return 0;
    return h+n == end || (end-(h+n) == 4 && !strncmp(h+n, ":443", 4)) ||
           (legacy && end-(h+n) == 5 && !strncmp(h+n, legacy, 5));
}

/* iCloud Keychain traffic (secd through syncdefaultsd) is token-authenticated
 * and needs the same device headers as DAV, but its daemons build requests as
 * raw CFHTTPMessages on the stream path, where no NSURLProtocol can ever run:
 * the Foundation module, armed or not, cannot help them. The hosts below get
 * their headers set directly on the message. The narrower list than the DAV
 * matcher is deliberate: caldav/contacts clients are Foundation applications
 * where the streaming adapter owns the request, and a second header pass here
 * would duplicate what it already added. */
static int device_auth_url(const char *url) {
    if (strncasecmp(url, "https://", 8)) return 0;
    const char *h = url + 8, *end = h + strcspn(h, "/?#");
    for (const char *p = h; p < end; p++) if (*p == '@') h = p + 1;
    if (*h == 'p' || *h == 'P') {
        h++;
        const char *digits = h;
        while (*h >= '0' && *h <= '9') h++;
        if (h == digits || *h++ != '-') return 0;
    }
    size_t n;
    if (!strncasecmp(h, "keyvalueservice.icloud.com", 26)) n = 26;
    else if (!strncasecmp(h, "escrowproxy.icloud.com", 22)) n = 22;
    else return 0;
    return h+n == end || (end-(h+n) == 4 && !strncmp(h+n, ":443", 4));
}

/* The device data comes from the same provider the GSA module uses, fetched
 * here with a socket because this side has no HTTP stack it may lean on.
 * Loopback HTTP only -- the module's own URL check permits exactly that
 * without a certificate, and this code has nowhere to validate one -- or an
 * exec: helper, the same arrangement the Foundation adapter accepts. Values
 * are base64, UUID or digit strings, so scanning for the closing quote is a
 * complete parse; anything else is refused rather than half-trusted. One
 * fetch per minute; a failed refresh serves the previous data for up to five
 * minutes, as the OTP bucket outlives a brief provider outage. */
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <openssl/sha.h>

static const char *const device_keys[] = {
    "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO",
    "X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info", NULL
};
#define DEVICE_VALUES 7
#define DEVICE_VALUE_MAX 16384

static pthread_mutex_t device_lock = PTHREAD_MUTEX_INITIALIZER;

/* Values are base64, UUID or digit strings, so scanning to the closing quote
 * is a complete parse; the needle carries both quotes so a key can never match
 * a longer sibling (X-Apple-I-MD vs X-Apple-I-MD-M). Whitespace between the
 * colon and the value's opening quote is accepted -- pretty-printed providers
 * are legal JSON. */
static int device_parse(const char *body, char out[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    int found = 0;
    for (int i = 0; device_keys[i]; i++) {
        out[i][0] = 0;
        char needle[64];
        snprintf(needle, sizeof needle, "\"%s\"", device_keys[i]);
        const char *v = strstr(body, needle);
        if (!v) continue;
        v += strlen(needle);
        while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
        if (*v != ':') continue;
        v++;
        while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
        if (*v != '"') continue;
        v++;
        const char *endv = strchr(v, '"');
        if (!endv) continue;
        size_t len = (size_t)(endv - v);
        if (!len || len >= DEVICE_VALUE_MAX) continue;
        memcpy(out[i], v, len); out[i][len] = 0;
        found++;
    }
    /* The one-time password and the machine data are the irreducible pair. */
    return out[0][0] && out[1][0] && found >= 2;
}

/* The provider line, trimmed at both ends: an indented line would otherwise
 * silently disable injection by failing the prefix checks. */
static int device_read_line(char *url, size_t n) {
    char path[1024];
    snprintf(path, sizeof path, "%s/gsa-anisette-url.txt", tf_dir());
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int have = fgets(url, (int)n, f) != NULL;
    fclose(f);
    if (!have) return 0;
    char *end = url + strlen(url);
    while (end > url && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
    char *start = url;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
    if (start != url) memmove(url, start, strlen(start) + 1);
    return url[0] != 0;
}

/* The exec form runs the same helpers the Foundation side accepts: an absolute
 * path and nothing else on the line. No arguments and no shell, the identical
 * restriction aq_exec_anisette applies, so one config line behaves the same
 * for both. The child's stdout is capped at 64 KiB and read under the same
 * ten-second bound as the HTTP fetch, counted from launch; a helper that
 * overruns it is killed rather than left holding the pipe. */
static int device_fetch_exec(const char *spec, char out[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    if (spec[0] != '/' || strcspn(spec, " \t\r\n") != strlen(spec)) return 0;
    int fds[2];
    if (pipe(fds)) return 0;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return 0; }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1);
        close(fds[1]);
        execl(spec, spec, (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    char body[64 * 1024];
    size_t total = 0;
    int eof = 0;
    time_t deadline = time(NULL) + 10;
    struct pollfd pfd = {fds[0], POLLIN, 0};
    while (total < sizeof body - 1) {
        time_t left = deadline - time(NULL);
        if (left <= 0) break;
        if (poll(&pfd, 1, (int)(left * 1000)) <= 0) break;
        ssize_t got = read(fds[0], body + total, sizeof body - 1 - total);
        if (got <= 0) { eof = got == 0; break; }
        total += (size_t)got;
    }
    close(fds[0]);
    int status = 0;
    if (eof) waitpid(pid, &status, 0);          /* output closed: the exit follows it */
    else { kill(pid, SIGKILL); waitpid(pid, &status, 0); }   /* wedged, or overran the cap */
    if (!eof || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 0;
    body[total] = 0;
    return device_parse(body, out);
}

/* One plain-HTTP exchange with a loopback provider. Returns the response body
 * (after the blank line) or NULL. Plain HTTP is permitted exactly on loopback,
 * and this side has no certificate validation to offer any other transport. */
static char *device_loopback_http(const char *url, const char *method,
                                  const char *body, const char *ctype,
                                  char resp[], size_t resp_size) {
    const char *prefix = NULL;
    if (!strncasecmp(url, "http://127.0.0.1:", 17)) prefix = url + 7;
    else if (!strncasecmp(url, "http://localhost:", 17)) prefix = url + 7;
    if (!prefix) return NULL;
    const char *slash = strchr(prefix, '/');
    char authority[256];
    size_t alen = slash ? (size_t)(slash - prefix) : strlen(prefix);
    if (!alen || alen >= sizeof authority) return NULL;
    memcpy(authority, prefix, alen); authority[alen] = 0;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("127.0.0.1", strrchr(authority, ':') ? strrchr(authority, ':')+1 : "80", &hints, &res) || !res)
        return NULL;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return NULL; }
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int connected = connect(fd, res->ai_addr, res->ai_addrlen) == 0;
    freeaddrinfo(res);
    if (!connected) { close(fd); return NULL; }

    size_t blen = body ? strlen(body) : 0;
    char req[2048];
    int n = snprintf(req, sizeof req,
        "%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n%s%s%s%zu\r\n\r\n",
        method, slash ? slash : "/", authority,
        body ? "Content-Type: " : "", body ? ctype : "", body ? "\r\nContent-Length: " : "", blen);
    if (n <= 0 || n >= (int)sizeof req) { close(fd); return NULL; }
    if (write(fd, req, (size_t)n) < 0 || (blen && write(fd, body, blen) < 0)) { close(fd); return NULL; }

    size_t total = 0;
    ssize_t got;
    while (total < resp_size - 1 && (got = read(fd, resp + total, resp_size - 1 - total)) > 0) total += (size_t)got;
    close(fd);
    resp[total] = 0;

    char *b = strstr(resp, "\r\n\r\n");
    if (!b || total < 12 || strncmp(resp, "HTTP/1.", 7) || strncmp(resp + 9, "200", 3)) return NULL;
    return b + 4;
}

/* Base64 decode of the identity fields, sized for the 16-byte identifier and
 * the bounded adi.pb; rejects anything that would not fit. */
static int device_b64(const char *s, unsigned char *out, size_t max, size_t *len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0, acc = 0, bits = 0;
    for (; *s && *s != '"'; s++) {
        const char *p = strchr(tbl, *s);
        if (*s == '=' ) continue;
        if (!p || *s == '\n' || *s == '\r' || *s == ' ') continue;
        acc = (acc << 6) | (size_t)(p - tbl);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= max) return 0;
            out[n++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    *len = n;
    return 1;
}

/* Read the string value that follows a "key" occurrence in a JSON document:
 * find the colon, skip whitespace, copy between the quotes. */
static int device_json_value(const char *keypos, char out[], size_t n) {
    const char *v = strchr(keypos, ':');
    if (!v) return 0;
    v++;
    while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
    if (*v != '"') return 0;
    v++;
    const char *e = strchr(v, '"');
    if (!e || (size_t)(e - v) >= n) return 0;
    memcpy(out, v, (size_t)(e - v));
    out[e - v] = 0;
    return 1;
}

/* The V3 form posts the local identity (gsa-anisette-v3.json beside the URL
 * config) to the derivation server and completes the header set with the same
 * local derivations as the Foundation provider: the local-user hash is the
 * raw SHA-256 of the identifier, the device UUID is the identifier bytes in
 * UUID form. This side has no TLS, so the server URL must be loopback --
 * the same tunnel arrangement the GET provider uses. */
static int device_fetch_v3(const char *url, char out[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    char path[1024];
    snprintf(path, sizeof path, "%s/gsa-anisette-v3.json", tf_dir());
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char idf[8 * 1024];
    size_t have = fread(idf, 1, sizeof idf - 1, f);
    fclose(f);
    if (have >= sizeof idf - 1) return 0;
    idf[have] = 0;

    unsigned char ident[16];
    size_t identlen = 0;
    char identb64[64], pbb64[8 * 1024], cibuf[512];
    char *v = strstr(idf, "\"adi_identifier\"");
    if (!v || !device_json_value(v, identb64, sizeof identb64)) return 0;
    if (!device_b64(identb64, ident, sizeof ident, &identlen) || identlen != 16) return 0;
    v = strstr(idf, "\"adi_pb\"");
    if (!v || !device_json_value(v, pbb64, sizeof pbb64)) return 0;
    const char *ci = "";
    v = strstr(idf, "\"client-info\"");
    if (v && device_json_value(v, cibuf, sizeof cibuf)) ci = cibuf;

    char body[8 * 1024];
    int n = snprintf(body, sizeof body, "{\"identifier\":\"%s\",\"adi_pb\":\"%s\"}", identb64, pbb64);
    if (n <= 0 || n >= (int)sizeof body) return 0;

    char resp[32 * 1024];
    char *jb = device_loopback_http(url, "POST", body, "application/json", resp, sizeof resp);
    if (!jb) return 0;

    /* Fill the provider fields by key, then the two local derivations. */
    char tmp[DEVICE_VALUES][DEVICE_VALUE_MAX];
    if (!device_parse(jb, tmp)) return 0;
    snprintf(out[0], DEVICE_VALUE_MAX, "%s", tmp[0]);   /* X-Apple-I-MD */
    snprintf(out[1], DEVICE_VALUE_MAX, "%s", tmp[1]);   /* X-Apple-I-MD-M */
    unsigned char lu[32];
    SHA256(ident, 16, lu);
    for (int i = 0; i < 16; i++) snprintf(out[2] + 2*i, 3, "%02x", lu[i]);
    snprintf(out[3], DEVICE_VALUE_MAX, "%s",
             tmp[3][0] ? tmp[3] : "17106176");          /* X-Apple-I-MD-RINFO */
    const unsigned char *b = ident;
    snprintf(out[4], DEVICE_VALUE_MAX,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    out[5][0] = 0;                                      /* no serial from this path */
    snprintf(out[6], DEVICE_VALUE_MAX, "%s", ci);       /* X-MMe-Client-Info */
    return out[0][0] && out[1][0];
}

static int device_fetch(char out[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    char url[512];
    if (!device_read_line(url, sizeof url)) return 0;

    if (!strncasecmp(url, "exec:", 5)) return device_fetch_exec(url + 5, out);
    if (!strncasecmp(url, "v3:", 3)) return device_fetch_v3(url + 3, out);

    char resp[32 * 1024];
    char *b = device_loopback_http(url, "GET", NULL, NULL, resp, sizeof resp);
    return b ? device_parse(b, out) : 0;
}

/* Returns 1 with fresh-enough values in out, locking the cache. A failed
 * refresh falls back to the previous data for as long as it is plausibly
 * still live: the one-time password is bucketed well beyond a minute, and a
 * brief provider outage must not strip device headers from keychain traffic.
 * Five minutes bounds how stale a served value may be. */
static int device_values(char out[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    static char cache[DEVICE_VALUES][DEVICE_VALUE_MAX];
    static time_t when;
    int ok = 0;
    pthread_mutex_lock(&device_lock);
    time_t now = time(NULL);
    if (when && now - when < 60) {
        memcpy(out, cache, sizeof cache);
        ok = out[0][0] && out[1][0];
    } else if (device_fetch(out)) {
        memcpy(cache, out, sizeof cache);
        when = now;
        ok = 1;
    } else if (when && now - when < 300) {
        memcpy(out, cache, sizeof cache);
        ok = out[0][0] && out[1][0];
    }
    pthread_mutex_unlock(&device_lock);
    return ok;
}

/* The Foundation adapter stamps every anisette use with client time, time zone
 * and locale; the C injection presents the same set so the request does not
 * read as a different client class. Both come from CoreFoundation: the system
 * time-zone identifier (what NSTimeZone reports, not an abbreviation) and the
 * process's current locale. Sending each process's real locale is the point,
 * not a regression -- it is exactly what the Foundation adapter's own traffic
 * from that same process would carry, so the two paths stay indistinguishable
 * even where a daemon's locale differs from a GUI app's. */
static void device_generated(char out[3][64]) {
    time_t now = time(NULL);
    struct tm utc;
    gmtime_r(&now, &utc);
    strftime(out[0], 64, "%Y-%m-%dT%H:%M:%SZ", &utc);
    /* Foundation stamps the system time-zone identifier ("Europe/Berlin",
     * not an abbreviation) and the current locale; CoreFoundation supplies
     * both without pulling in Objective-C, and this side already links it.
     * A mismatch would present keychain requests as a different client
     * class than the adapter's own traffic. */
    CFTimeZoneRef z = CFTimeZoneCopySystem();
    CFStringRef zn = z ? CFTimeZoneGetName(z) : NULL;
    char *zone = zn ? cf_to_c(zn) : NULL;
    snprintf(out[1], 64, "%s", zone && *zone ? zone : "UTC");
    if (zone) free(zone);
    if (z) CFRelease(z);
    CFLocaleRef lc = CFLocaleCopyCurrent();
    CFStringRef ln = lc ? CFLocaleGetIdentifier(lc) : NULL;
    char *locale = ln ? cf_to_c(ln) : NULL;
    snprintf(out[2], 64, "%s", locale && *locale ? locale : "en_US");
    if (locale) free(locale);
    if (lc) CFRelease(lc);
}

/* Set the device headers on a CFHTTPMessage for a device-auth URL. Used only
 * where no NSURLProtocol can be running for this request: the raw stream path,
 * and request-path processes where the Foundation module could not arm. The
 * values arrive pre-fetched -- the message call runs under the rules lock, and
 * the fetch can take seconds. Returns the number of headers set. The generated
 * fields ride along only with provider data: alone, they would present a
 * request as anisette-authenticated that carries no credentials. */
static int device_headers_message(void *msg, const char values[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    int set = 0;
    for (int i = 0; device_keys[i]; i++) {
        if (!values[i][0]) continue;
        CFStringRef n = CFStringCreateWithCString(NULL, device_keys[i], kCFStringEncodingUTF8);
        CFStringRef v = CFStringCreateWithCString(NULL, values[i], kCFStringEncodingUTF8);
        if (n && v) { p_MsgSetHeader(msg, n, v); set++; }
        if (n) CFRelease(n);
        if (v) CFRelease(v);
    }
    if (set) {
        char gen[3][64];
        device_generated(gen);
        static const char *const genkeys[3] = {"X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale"};
        for (int i = 0; i < 3; i++) {
            CFStringRef n = CFStringCreateWithCString(NULL, genkeys[i], kCFStringEncodingUTF8);
            CFStringRef v = CFStringCreateWithCString(NULL, gen[i], kCFStringEncodingUTF8);
            if (n && v) { p_MsgSetHeader(msg, n, v); set++; }
            if (n) CFRelease(n);
            if (v) CFRelease(v);
        }
    }
    if (set) tf_log("device authentication headers added to keychain request");
    return set;
}

static int device_headers_request(void *req, const char values[DEVICE_VALUES][DEVICE_VALUE_MAX]) {
    int set = 0;
    for (int i = 0; device_keys[i]; i++) {
        if (!values[i][0]) continue;
        CFStringRef n = CFStringCreateWithCString(NULL, device_keys[i], kCFStringEncodingUTF8);
        CFStringRef v = CFStringCreateWithCString(NULL, values[i], kCFStringEncodingUTF8);
        if (n && v) { p_SetHeader(req, n, v); set++; }
        if (n) CFRelease(n);
        if (v) CFRelease(v);
    }
    if (set) {
        char gen[3][64];
        device_generated(gen);
        static const char *const genkeys[3] = {"X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale"};
        for (int i = 0; i < 3; i++) {
            CFStringRef n = CFStringCreateWithCString(NULL, genkeys[i], kCFStringEncodingUTF8);
            CFStringRef v = CFStringCreateWithCString(NULL, gen[i], kCFStringEncodingUTF8);
            if (n && v) { p_SetHeader(req, n, v); set++; }
            if (n) CFRelease(n);
            if (v) CFRelease(v);
        }
    }
    if (set) tf_log("device authentication headers added to keychain request");
    return set;
}

/* The reservation shields the GSA exchange from general rules, but only where the
 * module can actually run: on Snow Leopard (which load_gsa_once below gates out by
 * the same Darwin-11 check), and on a Lion-or-newer install built without the optional
 * module, there is no exchange to protect, and holding its hosts out of the configured
 * rules would only discard the admin's redirect and header settings. Both facts are
 * settled once: the kernel release, and whether the module image sits beside this
 * library where load_gsa_once will look for it. */
static int gsa_possible(void) {
    static int ok = -1;
    if (ok < 0) {
        struct utsname os;
        int darwin = !uname(&os) && atoi(os.release) >= 11;
        int present = 0;
        Dl_info info;
        if (darwin && dladdr((void *)&gsa_possible, &info) && info.dli_fname) {
            const char *slash = strrchr(info.dli_fname, '/');
            char path[1024];
            if (slash && snprintf(path, sizeof path, "%.*s/aquatransport_gsa.dylib",
                    (int)(slash-info.dli_fname), info.dli_fname) < sizeof path)
                present = access(path, R_OK) == 0;
        }
        ok = darwin && present;
    }
    return ok;
}

/* Armed means the module is actually running in this process: its principal class
 * resolves. Presence on disk is not enough -- an image that exists but would not load
 * (the wrong slice for this process, a broken dependency) protects nothing, and
 * holding reserved URLs out of the configured rules beside it is exactly the harm the
 * reservation was tightened to avoid. The request path below attempts the load before
 * asking; the message-path sites ask without attempting, so a process that never loads
 * the module keeps its rules there. */
static int gsa_armed(void) {
    void *(*get_class)(const char *) = dlsym(RTLD_DEFAULT, "objc_getClass");
    return get_class && get_class("AQGSAProtocol") != NULL;
}

static int gsa_reserved_url(const char *url) {
    /* Authentication requests must not be redirected or have credentials logged by
     * general URL/header rules. Match a full authority, including its slash. */
    return gsa_dav_url(url) || !strncasecmp(url, "https://gsa.apple.com/", 22) ||
           !strncasecmp(url, "https://setup.icloud.com/", 25) ||
           !strncasecmp(url, "https://profile.ess.apple.com/", 30) ||
           !strncasecmp(url, "https://service.ess.apple.com/", 30) ||
           !strncasecmp(url, "https://profile.ess.apple.com:443/", 34) ||
           !strncasecmp(url, "https://service.ess.apple.com:443/", 34) ||
           !strncasecmp(url, "https://gsa.apple.com:443/", 26) ||
           !strncasecmp(url, "https://setup.icloud.com:443/", 29);
}

// Caller holds tf_rules_lock: the rule returned points into the array a concurrent reload
// frees, so it is valid only until the caller releases it.
static const tf_headerrule *match_headers(const char *url) {
    const tf_headerrule *rules = NULL;
    int n = tf_headerrules(&rules);
    for (int i = 0; i < n; i++)
        if (tf_scope_matches(rules[i].scope) && tf_glob_prefix(rules[i].pattern, url))
            return &rules[i];
    return NULL;
}

// Both request objects take their headers through a setter of the same shape, so the rule is
// walked once here. A line with nothing after the colon removes the header: the setters take a
// NULL value as removal, where an empty string would send the header with an empty value.
typedef void (*hdr_set)(void *, CFStringRef, CFStringRef);

static void apply_header_rule(const tf_headerrule *hr, void *target, hdr_set set) {
    for (int i = 0; i < hr->nlines; i++) {
        const char *line = hr->lines[i];
        const char *colon = strchr(line, ':');
        if (!colon || colon == line) continue;
        char name[128];
        size_t nl = (size_t)(colon - line);
        if (nl >= sizeof name) continue;
        memcpy(name, line, nl); name[nl] = 0;
        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        CFStringRef cn = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
        CFStringRef cv = *val ? CFStringCreateWithCString(NULL, val, kCFStringEncodingUTF8) : NULL;
        if (cn) { set(target, cn, cv); tf_log("header %s: %s", name, val); }
        if (cn) CFRelease(cn);
        if (cv) CFRelease(cv);
    }
}

// Applies the rules to an already-mutable request, in place. Returns 1 if anything
// changed. Idempotent: an applied redirect leaves a URL the rule's "from" prefix does not
// match, so a second pass over the same request does nothing.
static int apply_rules(void *m) {
    if (!m || !resolved()) return 0;

    CFURLRef url = p_GetURL(m);
    if (!url) return 0;
    char *before = cf_to_c(CFURLGetString(url));
    if (!before) return 0;

    if (gsa_possible() && !tf_flag("disable-icloud-gsa") && gsa_reserved_url(before)) {
        prepare_gsa();
        if (gsa_armed()) { free(before); return 0; }
        /* A process where the module could not arm still gets its keychain
         * traffic through: the rewritten copy carries the device headers, so
         * report the change and let the caller send it. */
        if (device_auth_url(before)) {
            char values[DEVICE_VALUES][DEVICE_VALUE_MAX];
            if (device_values(values) && device_headers_request(m, values) > 0) {
                free(before);
                return 1;
            }
            /* A failed fetch must not strand the request: fall through so the
             * configured rules still apply to it. */
        }
    }

    // One critical section across the redirect, the match, and the use of what matched: the
    // rule points into an array a concurrent reload frees.
    tf_rules_lock();
    char *after = tf_apply_redirect(before);
    const char *effective = after ? after : before;
    const tf_headerrule *hr = match_headers(effective);
    if (!after && !hr) { tf_rules_unlock(); free(before); return 0; }

    if (after) {
        CFStringRef s = CFStringCreateWithCString(NULL, after, kCFStringEncodingUTF8);
        CFURLRef nu = s ? CFURLCreateWithString(NULL, s, NULL) : NULL;
        if (nu) {
            p_SetURL(m, nu);
            // Host is derived from the URL; a stale explicit one would follow us to the
            // new host and be wrong.
            //
            // Built rather than written as CFSTR("Host"): a constant CFString is a *data*
            // reference to CoreFoundation (___CFConstantStringClassReference), and the one
            // thing lazy linking does not allow is a data reference. Lazy linking is what
            // lets this library be loaded into a process that has not initialised
            // CoreFoundation, which is what removes the need for any load-time gate.
            CFStringRef hostKey = CFStringCreateWithCString(NULL, "Host", kCFStringEncodingUTF8);
            if (hostKey) { p_SetHeader(m, hostKey, NULL); CFRelease(hostKey); }
            CFRelease(nu);
        }
        if (s) CFRelease(s);
        tf_log("rewrite %s -> %s", before, after);
    }
    if (hr) apply_header_rule(hr, m, (hdr_set)p_SetHeader);
    tf_rules_unlock();
    free(before); free(after);
    return 1;
}

// Copies an immutable request and applies the rules, or returns NULL when nothing matched
// and the caller should use the original untouched. The caller releases the result.
// p_MutableCopy is the real function resolved by dlsym, not our hook, so this does not
// recurse into my_MutableCopy below.
static void *rewritten(void *req) {
    if (!req || !resolved()) return NULL;
    void *m = p_MutableCopy(NULL, req);
    if (!m) return NULL;
    if (apply_rules(m)) return m;
    CFRelease(m);
    return NULL;
}

// Hooks call through to the ORIGINAL captured by fishhook, so a request we rewrote is
// never re-entered through the same hook.
static fn6 o_SendSync, o_CreateWithProps, o_Create, o_MutableCopy, o_MsgCreate, o_MsgSetHeader;

static void *my_SendSync(void *a, void *b, void *c, void *d, void *e, void *f) {
    void *m = rewritten(a);
    void *r = o_SendSync(m ? m : a, b, c, d, e, f);
    if (m) CFRelease(m);
    return r;
}

static void *my_CreateWithProps(void *a, void *b, void *c, void *d, void *e, void *f) {
    void *m = rewritten(b);
    void *r = o_CreateWithProps(a, m ? m : b, c, d, e, f);
    if (m) CFRelease(m);
    return r;
}

// Mavericks AOSRequest calls this entry directly, before any mutable-copy funnel.
static void *my_Create(void *a, void *b, void *c, void *d, void *e, void *f) {
    // Resolve the real function even when fishhook captured an unbound lazy slot.
    resolved();
    void *m = rewritten(b);
    void *r = (p_CreateConnection ? p_CreateConnection : o_Create)(a, m ? m : b, c, d, e, f);
    if (m) CFRelease(m);
    return r;
}

// The raw-stream path: rules applied to the URL the message is built around, and to the message
// once it exists.
static void *my_MsgCreate(void *alloc, void *method, void *url, void *version, void *e, void *f) {
    (void)e; (void)f;
    if (!msg_resolved() || !url) return o_MsgCreate(alloc, method, url, version, e, f);

    char *before = cf_to_c(CFURLGetString((CFURLRef)url));
    if (!before) return p_MsgCreate((CFAllocatorRef)alloc, (CFStringRef)method,
                                    (CFURLRef)url, (CFStringRef)version);
    if (gsa_possible() && gsa_armed() && !tf_flag("disable-icloud-gsa") && gsa_reserved_url(before)) {
        free(before);
        return p_MsgCreate((CFAllocatorRef)alloc, (CFStringRef)method, (CFURLRef)url, (CFStringRef)version);
    }

    /* The device fetch runs before the rules lock: it can take seconds on a
     * stalled provider, and holding the lock across it would freeze every
     * other request in the process. Only the header writes happen locked. */
    char device_vals[DEVICE_VALUES][DEVICE_VALUE_MAX];
    int have_device = gsa_possible() && !gsa_armed() && !tf_flag("disable-icloud-gsa") &&
        device_auth_url(before) && device_values(device_vals);

    // Held across match and use, as in apply_rules: the rule points into an array a reload frees.
    tf_rules_lock();
    char *after = tf_apply_redirect(before);
    const tf_headerrule *hr = match_headers(after ? after : before);

    CFURLRef use = (CFURLRef)url;
    CFStringRef ns = NULL;
    CFURLRef nu = NULL;
    if (after) {
        ns = CFStringCreateWithCString(NULL, after, kCFStringEncodingUTF8);
        nu = ns ? CFURLCreateWithString(NULL, ns, NULL) : NULL;
        if (nu) { use = nu; tf_log("rewrite %s -> %s", before, after); }
    }

    void *msg = p_MsgCreate((CFAllocatorRef)alloc, (CFStringRef)method, use, (CFStringRef)version);
    if (msg && hr) apply_header_rule(hr, msg, (hdr_set)p_MsgSetHeader);
    /* No NSURLProtocol exists for this stream: whatever runs here keeps its
     * native token authentication and gains the device headers directly. Only
     * when the module is not armed -- an armed process sends its keychain
     * traffic through the streaming adapter, which has added its own. */
    if (msg && have_device)
        device_headers_message(msg, device_vals);
    tf_rules_unlock();

    if (nu) CFRelease(nu);
    if (ns) CFRelease(ns);
    free(before); free(after);
    return msg;
}

// Does this rule set a header of this name? Compared case-insensitively, as header names are.
static int rule_sets_header(const tf_headerrule *hr, const char *name) {
    size_t n = strlen(name);
    for (int i = 0; i < hr->nlines; i++) {
        const char *colon = strchr(hr->lines[i], ':');
        if (!colon) continue;
        if ((size_t)(colon - hr->lines[i]) == n && strncasecmp(hr->lines[i], name, n) == 0) return 1;
    }
    return 0;
}

// A rule beats the application's own header.
//
// Setting headers when the message is created is not enough on its own: the caller sets its
// own afterwards and overwrites them. DictionaryServices does exactly that, stamping
// User-Agent: AppleDictionaryService/208 over the rule -- and that User-Agent is the whole
// reason the request needs rewriting. Dropping the caller's value for a header the rule
// controls leaves the rule's value, set at creation, in place.
//
// This is the setter, not the stream, deliberately: hooking CFReadStreamCreateForHTTPRequest
// would be the natural place to have the last word, and it is the one function another library
// here already interposes. Nothing contends for this one.
static void my_MsgSetHeader(void *msg, void *name, void *value, void *d, void *e, void *f) {
    if (!msg_resolved() || !msg || !name) { o_MsgSetHeader(msg, name, value, d, e, f); return; }

    char *hn = cf_to_c((CFStringRef)name);
    CFURLRef url = p_MsgURL(msg);
    char *before = url ? cf_to_c(CFURLGetString(url)) : NULL;
    if (url) CFRelease(url);
    if (!hn || !before) { free(hn); free(before); p_MsgSetHeader(msg, (CFStringRef)name, (CFStringRef)value); return; }
    if (gsa_possible() && gsa_armed() && !tf_flag("disable-icloud-gsa") && gsa_reserved_url(before)) {
        free(hn); free(before); p_MsgSetHeader(msg, (CFStringRef)name, (CFStringRef)value); return;
    }

    tf_rules_lock();                     // the rule is read below, still under the lock
    char *after = tf_apply_redirect(before);
    const tf_headerrule *hr = match_headers(after ? after : before);
    int ours = (hr && rule_sets_header(hr, hn));
    tf_rules_unlock();
    if (ours) tf_log("header %s kept from rule, caller overruled", hn);
    free(hn); free(before); free(after);

    if (!ours) p_MsgSetHeader(msg, (CFStringRef)name, (CFStringRef)value);
}

// The universal funnel. Measured on 10.9: every path makes a mutable copy of the request
// before sending it -- synchronous NSURLConnection, asynchronous NSURLConnection, and
// NSURLSession alike. NSURLSession matters especially because it touches none of the
// CFURLConnection* entry points at all, so without this hook it would go unrewritten.
// The result is already mutable, so the rules are applied to it directly.
static void *my_MutableCopy(void *a, void *b, void *c, void *d, void *e, void *f) {
    void *m = o_MutableCopy(a, b, c, d, e, f);
    if (m) apply_rules(m);
    return m;
}

// Six pointer parameters are declared on purpose. The real arities are 4; on both x86_64
// and i386 passing more arguments than the callee reads is harmless, whereas declaring
// fewer than the real count would make the callee read uninitialised registers or stack.
// This keeps the pass-through safe without depending on private headers being exact.
void tf_rewrite_install(void) {
    struct rebinding r[] = {
        { "CFURLRequestCreateMutableCopy",         (void *)my_MutableCopy,     (void **)&o_MutableCopy },
        { "CFURLConnectionSendSynchronousRequest", (void *)my_SendSync,        (void **)&o_SendSync },
        { "CFURLConnectionCreateWithProperties",   (void *)my_CreateWithProps, (void **)&o_CreateWithProps },
        { "CFURLConnectionCreate",                 (void *)my_Create,          (void **)&o_Create },
        { "CFHTTPMessageCreateRequest",            (void *)my_MsgCreate,       (void **)&o_MsgCreate },
        { "CFHTTPMessageSetHeaderFieldValue",      (void *)my_MsgSetHeader,    (void **)&o_MsgSetHeader },
    };
    // Also arms a dyld add-image callback, so CFNetwork loaded later still gets rebound.
    rebind_symbols(r, sizeof r / sizeof r[0]);
}
