/* `local:` with no service to answer must fail closed, on the service's own error: the
 * configured provider is the only one tried, and no request of any other kind is made.
 * The selftest builds this with AQ_ANISETTE_SOCKET naming a path nothing listens on, and
 * with a configuration directory of its own, so that the case holds on a machine that has
 * the real service installed and does not fall through to the mock URL the other probes use. */
#include "../src/mac/aquatransport_gsa.m"
#include <assert.h>
@interface AQLocalNoHTTP : NSURLProtocol @end
@implementation AQLocalNoHTTP
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading { assert(!"local: must never make an HTTP request"); }
@end
int main(void) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[AQLocalNoHTTP class]];
    NSError *error = nil;
    NSDictionary *headers = aq_anisette(nil, &error);
    assert(!headers);
    assert([[error domain] isEqual:AQErrorDomain] && [error code] == 10);
    /* How a header set reaches Apple. The local generator's carries the machine it minted
     * for, and a mark of where it came from; the mark is neither a header nor client data,
     * and the user agent is a header only. */
    NSString *akd = @"<MacPro5,1> <Mac OS X;10.9.5;13F1911> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
    NSString *agent = @"akd/1.0 CFNetwork/673.6 Darwin/13.4.0";
    NSDictionary *local = [NSDictionary dictionaryWithObjectsAndKeys:
        akd, @"X-Mme-Client-Info", agent, @"User-Agent", @"local", @"AQ-Generated", nil];
    assert(aq_copied(@"X-Mme-Client-Info", NO) && aq_copied(@"X-Mme-Client-Info", YES));
    assert(aq_copied(@"User-Agent", NO) && !aq_copied(@"User-Agent", YES));
    assert(!aq_copied(@"AQ-Generated", NO) && !aq_copied(@"AQ-Generated", YES));
    NSMutableURLRequest *request = aq_apple_request(@"https://gsa.apple.com/grandslam/GsService2", local);
    assert([[request valueForHTTPHeaderField:@"X-Mme-Client-Info"] isEqual:akd]);
    assert([[request valueForHTTPHeaderField:@"User-Agent"] isEqual:agent]);
    assert(![request valueForHTTPHeaderField:@"AQ-Generated"]);
    /* The verification step: the real machine with Xcode's token for the local generator,
     * and for another source whatever that source's request carries. */
    assert([aq_verification_identity(local) isEqual:
        @"<MacPro5,1> <Mac OS X;10.9.5;13F1911> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"]);
    NSDictionary *remote = [NSDictionary dictionaryWithObject:@"<other> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>" forKey:@"X-Mme-Client-Info"];
    assert(aq_verification_identity(remote) == [remote objectForKey:@"X-Mme-Client-Info"]);
    puts("PASS: local: without a service fails closed with the service's error, and makes no request; a header set reaches Apple as its source meant it");
    [pool drain]; return 0;
}
