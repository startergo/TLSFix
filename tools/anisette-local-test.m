/* `local:` with no service to answer must fail closed, on the service's own error: the
 * configured provider is the only one tried, and no request of any other kind is made.
 * The selftest builds this with AQ_ANISETTE_SOCKET naming a path nothing listens on, and
 * with a configuration directory of its own, so that the case holds on a machine that has
 * the real service installed and does not fall through to the mock URL the other probes use.
 *
 * The same binary then takes the header set the provider itself returns, with the generator
 * replaced by the fixture, and checks how that set reaches Apple. The provider's set, not a
 * copy of it built here: a copy built on 2026-11-26 spelled one key as the adapter's readers
 * did not, and so hid that they were never seeing the generator's identity. */
#include "../src/mac/aquatransport_gsa.m"
#include "local-anisette-fixture.h"
@interface AQLocalNoHTTP : NSURLProtocol @end
@implementation AQLocalNoHTTP
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading { assert(!"local: must never make an HTTP request"); }
@end
/* What the worker would return, without a worker. */
static id fixtureOTP(id self, SEL selector, id owner, NSError **error) {
    return [NSDictionary dictionaryWithObjectsAndKeys:@"fake-otp", @"X-Apple-MD", @"fake-machine", @"X-Apple-MD-M",
        @"84215040", @"X-Apple-I-MD-RINFO", @"fake-device", @"device", nil];
}
int main(void) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[AQLocalNoHTTP class]];
    NSError *error = nil;
    NSDictionary *headers = aq_anisette(nil, &error);
    assert(!headers);
    assert([[error domain] isEqual:AQErrorDomain] && [error code] == 10);

    aq_test_install_otp((IMP)fixtureOTP);
    error = nil;
    NSDictionary *local = aq_local_anisette(nil, &error);
    assert(local && !error);
    assert([[local objectForKey:@"X-Apple-I-MD"] isEqual:@"fake-otp"] && [[local objectForKey:@"X-Mme-Device-Id"] isEqual:@"fake-device"]);
    assert([local objectForKey:AQGenerated]);
    /* How a header set reaches Apple. The local generator's carries the machine it minted
     * for, and a mark of where it came from; the mark is neither a header nor client data,
     * and the user agent is a header only. */
    NSString *akd = aq_client_info(), *agent = aq_akd_user_agent();
    assert([akd length] && [agent length]);
    assert(aq_copied(@"X-MMe-Client-Info", NO) && aq_copied(@"X-MMe-Client-Info", YES));
    assert(aq_copied(@"User-Agent", NO) && !aq_copied(@"User-Agent", YES));
    assert(!aq_copied(@"AQ-Generated", NO) && !aq_copied(@"AQ-Generated", YES));
    /* The machine is in the set once, under the key the request builders read. */
    NSUInteger spellings = 0;
    for (NSString *k in local) if ([[k lowercaseString] isEqual:@"x-mme-client-info"]) spellings++;
    assert(spellings == 1 && [[local objectForKey:@"X-MMe-Client-Info"] isEqual:akd]);
    assert([[local objectForKey:@"User-Agent"] isEqual:agent]);
    /* On the wire: every request builder says what the generator said. */
    NSMutableURLRequest *request = aq_apple_request(@"https://gsa.apple.com/grandslam/GsService2", local);
    assert([[request valueForHTTPHeaderField:@"X-Mme-Client-Info"] isEqual:akd]);
    assert([[request valueForHTTPHeaderField:@"User-Agent"] isEqual:agent]);
    assert(![request valueForHTTPHeaderField:@"AQ-Generated"]);
    NSDictionary *envelope = aq_grandslam_envelope(local);
    assert([envelope count] == 4);
    assert([[envelope objectForKey:@"X-MMe-Client-Info"] isEqual:akd]);
    assert([[envelope objectForKey:@"User-Agent"] isEqual:agent]);
    assert(![envelope objectForKey:@"X-Apple-I-MD"]);
    /* A server's set names no user agent, and the envelope invents none for it. */
    NSDictionary *remote = [NSDictionary dictionaryWithObjectsAndKeys:@"otp", @"X-Apple-I-MD",
        @"<other> <macOS;13.1;22C65> <com.apple.AOSKit/282 (com.apple.accountsd/113)>", @"X-MMe-Client-Info", nil];
    NSDictionary *remoteEnvelope = aq_grandslam_envelope(remote);
    assert([remoteEnvelope count] == 1 && [[remoteEnvelope objectForKey:@"X-MMe-Client-Info"] isEqual:[remote objectForKey:@"X-MMe-Client-Info"]]);
    /* The verification step: the real machine with Xcode's token for the local generator,
     * and for another source whatever that source's request carries. */
    NSRange application = [akd rangeOfString:@" <" options:NSBackwardsSearch];
    assert(application.location != NSNotFound);
    assert([aq_verification_identity(local) isEqual:[[akd substringToIndex:application.location] stringByAppendingString:
        @" <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"]]);
    assert(aq_verification_identity(remote) == [remote objectForKey:@"X-MMe-Client-Info"]);
    puts("PASS: local: without a service fails closed with the service's error and makes no request; the provider's own set reaches Apple as the machine it minted for");
    [pool drain]; return 0;
}
