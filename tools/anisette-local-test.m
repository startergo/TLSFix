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
    puts("PASS: local: without a service fails closed with the service's error, and makes no request");
    [pool drain]; return 0;
}
