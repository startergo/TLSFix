/* anisette-server: serves GrandSlam device authentication data minted by this
 * Mac's own AOSKit provisioning, for AquaTransport clients on machines whose
 * AOSKit can no longer mint it (see docs/ICLOUD.md). The GET-JSON contract is
 * the one aq_remote_anisette accepts: HTTP 200, a flat dictionary, string
 * values, no redirects.
 *
 * The listener binds 127.0.0.1 only. A client on another machine reaches it
 * through an SSH tunnel, so the endpoint URL stays a loopback address and the
 * transport is the tunnel's encryption rather than a certificate the TLSFix
 * engine would have to trust. tools/anisette-host.sh installs this server and
 * the tunnel as launch agents.
 *
 * Each request mints a fresh one-time password through AOSKit; nothing is
 * cached. Apple account credentials never reach this process. Logs carry
 * methods, statuses and a non-reversible 8-hex prefix of each OTP so freshness
 * can be checked without recording the values. */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <arpa/inet.h>
#import <errno.h>
#import <netinet/in.h>
#import <signal.h>
#import <stdarg.h>
#import <sys/socket.h>
#import <unistd.h>

static Class gUtility, gAKDevice;
static SEL gOTP, gSerial;

static void logline(const char *fmt, ...) {
    char stamp[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "%s anisette-server[%d]: ", stamp, getpid());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Log-safe identity tag: 8 hex of MD5. Not reversible to the value. */
static NSString *tag8(NSString *s) {
    const char *c = [s UTF8String];
    unsigned char d[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), d);
    char hex[17];
    for (int i = 0; i < 8; i++) snprintf(hex + 2*i, 3, "%02x", d[i]);
    return [NSString stringWithUTF8String:hex];
}

static NSDictionary *mint(NSString **error) {
    NSDictionary *d = ((id (*)(id, SEL, id))objc_msgSend)(gUtility, gOTP, @"-2");
    NSString *machine = [d objectForKey:@"X-Apple-MD-M"];
    NSString *oneTime = [d objectForKey:@"X-Apple-MD"];
    if (![machine isKindOfClass:[NSString class]] || ![oneTime isKindOfClass:[NSString class]]) {
        *error = @"AOSKit returned no provisioning data; is this Mac signed into iCloud?";
        return nil;
    }
    /* AOSKit's one-time password is minted under the current machine's AuthKit
     * provisioning, so the identity fields must come from AKDevice (the same
     * pairing SideStore's MacAnisette uses): its serverFriendlyDescription is
     * the client info the OTP pairs with, and the local user is the account's
     * localUserUUID, not a derived value. A mismatched pair is rejected. */
    id device = ((id (*)(id, SEL, id))objc_msgSend)((id)gAKDevice, NSSelectorFromString(@"currentDevice"), nil);
    NSString *clientInfo = ((id (*)(id, SEL))objc_msgSend)(device, NSSelectorFromString(@"serverFriendlyDescription"));
    NSString *udid = ((id (*)(id, SEL))objc_msgSend)(device, NSSelectorFromString(@"uniqueDeviceIdentifier"));
    NSString *lu = ((id (*)(id, SEL))objc_msgSend)(device, NSSelectorFromString(@"localUserUUID"));
    NSString *serial = ((id (*)(id, SEL, id))objc_msgSend)((id)gUtility, gSerial, nil);
    if (![clientInfo isKindOfClass:[NSString class]] || ![udid isKindOfClass:[NSString class]] ||
        ![lu isKindOfClass:[NSString class]]) {
        *error = @"AKDevice returned no machine identity; is this Mac signed into iCloud?";
        return nil;
    }
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithObjectsAndKeys:
        oneTime, @"X-Apple-I-MD",
        machine, @"X-Apple-I-MD-M",
        udid, @"X-Mme-Device-Id",
        lu, @"X-Apple-I-MD-LU",
        @"0", @"X-Apple-I-MD-RINFO",
        clientInfo, @"X-MMe-Client-Info", nil];
    if ([serial isKindOfClass:[NSString class]] && [serial length])
        [out setObject:serial forKey:@"X-Apple-I-SRL-NO"];
    return out;
}

static void respond(int fd, int status, const char *reason, NSData *body) {
    char head[256];
    int n = snprintf(head, sizeof head,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n",
        status, reason, (unsigned long)[body length]);
    if (n > 0 && n < (int)sizeof head) {
        if (write(fd, head, n) < 0 || write(fd, [body bytes], [body length]) < 0)
            logline("write failed: %s", strerror(errno));
    }
}

int main(int argc, char **argv) {
    @autoreleasepool {
        int port = argc > 1 ? atoi(argv[1]) : 9724;
        if (port < 1 || port > 65535) { logline("bad port %d", port); return 2; }

        void *lib = dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_LAZY | RTLD_LOCAL);
        if (!lib) { logline("dlopen AOSKit: %s", dlerror()); return 2; }
        dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_LAZY | RTLD_LOCAL);
        gUtility = NSClassFromString(@"AOSUtilities");
        gAKDevice = NSClassFromString(@"AKDevice");
        gOTP = NSSelectorFromString(@"retrieveOTPHeadersForDSID:");
        gSerial = NSSelectorFromString(@"machineSerialNumber");
        if (![gUtility respondsToSelector:gOTP] || !gAKDevice) {
            logline("this system cannot mint device authentication data");
            return 2;
        }

        signal(SIGPIPE, SIG_IGN);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) { logline("socket: %s", strerror(errno)); return 2; }
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)port);
        if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
            logline("bind 127.0.0.1:%d: %s", port, strerror(errno));
            return 2;
        }
        if (listen(s, 8) < 0) { logline("listen: %s", strerror(errno)); return 2; }
        logline("listening on 127.0.0.1:%d", port);

        for (;;) {
            int c = accept(s, NULL, NULL);
            if (c < 0) {
                if (errno != EINTR) logline("accept: %s", strerror(errno));
                continue;
            }
            struct timeval tv = {5, 0};
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

            char buf[8192];
            ssize_t got = 0;
            while (got < (ssize_t)(sizeof buf - 1)) {
                ssize_t n = recv(c, buf + got, sizeof buf - 1 - got, 0);
                if (n <= 0) break;
                got += n;
                buf[got] = 0;
                if (strstr(buf, "\r\n\r\n")) break;
            }
            if (got <= 0) { close(c); continue; }
            buf[got] = 0;

            char method[16] = "", path[256] = "";
            sscanf(buf, "%15s %255s", method, path);
            if (strcmp(method, "GET") != 0) {
                NSData *body = [@"{\"error\":\"GET only\"}" dataUsingEncoding:NSUTF8StringEncoding];
                respond(c, 405, "Method Not Allowed", body);
                logline("%s %s -> 405", method, path);
                close(c);
                continue;
            }

            NSString *error = nil;
            @try {
                NSDictionary *d = mint(&error);
                if (!d) {
                    NSData *body = [[NSString stringWithFormat:@"{\"error\":\"%@\"}", error]
                        dataUsingEncoding:NSUTF8StringEncoding];
                    respond(c, 503, "Service Unavailable", body);
                    logline("GET %s -> 503 (%s)", path, [error UTF8String]);
                } else {
                    NSData *body = [NSJSONSerialization dataWithJSONObject:d options:0 error:NULL];
                    respond(c, 200, "OK", body ?: [@"{\"error\":\"encoding failed\"}" dataUsingEncoding:NSUTF8StringEncoding]);
                    logline("GET %s -> 200 (otp %s, machine %s)",
                        path, [tag8([d objectForKey:@"X-Apple-I-MD"]) UTF8String],
                        [tag8([d objectForKey:@"X-Apple-I-MD-M"]) UTF8String]);
                }
            }
            @catch (NSException *e) {
                NSData *body = [@"{\"error\":\"mint failed\"}" dataUsingEncoding:NSUTF8StringEncoding];
                respond(c, 503, "Service Unavailable", body);
                logline("GET %s -> 503 (exception %s)", path, [[e name] UTF8String]);
            }
            close(c);
        }
    }
    return 0;
}
