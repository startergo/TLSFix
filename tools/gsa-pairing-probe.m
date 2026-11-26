/* Does Apple accept a device identity for an account? No password is involved. This is the
 * first step of the GrandSlam exchange, `init`, which carries the account name and the device
 * headers and is answered with a salt and the server's public value. For a device pairing it
 * will not have, Apple's edge answers a bare HTTP 503 -- an nginx error page, with no
 * GrandSlam Status at all -- which the adapter reports as a rejected exchange and logs with
 * the HTTP status, hsc and ec.
 *
 * Runs the provider the configuration names, through the adapter's own exchange code. Prints
 * the outcome and nothing else: no header value and nothing of the account's.
 *
 *   AQUATRANSPORT_DIR=/usr/share/aquatransport/config build/gsa-pairing-probe <apple id>
 */
#include "../src/mac/aquatransport_gsa.m"

int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    if (argc != 2 || !argv[1][0]) { fprintf(stderr, "usage: %s <apple id>\n", argv[0]); return 2; }
    NSError *error = nil;
    NSDictionary *headers = aq_anisette(nil, &error);
    if (!headers) {
        fprintf(stderr, "init NOT SENT: the provider failed (%ld: %s)\n",
                (long)[error code], [[error localizedDescription] UTF8String]);
        [pool drain]; return 1;
    }
    unsigned char A[256];
    aq_srp *srp = aq_srp_new(A);
    if (!srp) { fprintf(stderr, "init NOT SENT: could not initialize SRP\n"); [pool drain]; return 1; }
    NSDictionary *challenge = nil;
    @try {
        NSMutableDictionary *init = [NSMutableDictionary dictionaryWithObjectsAndKeys:
            [NSData dataWithBytes:A length:sizeof A], @"A2k", [NSArray arrayWithObjects:@"s2k", @"s2k_fo", nil], @"ps",
            [NSString stringWithUTF8String:argv[1]], @"u", @"init", @"o", nil];
        challenge = aq_exchange(nil, init, headers, &error);
    } @finally { aq_srp_free(srp); }
    if (!challenge) {
        fprintf(stderr, "init REJECTED (%ld: %s); the HTTP status, hsc and ec are in the system log\n",
                (long)[error code], [[error localizedDescription] UTF8String]);
        [pool drain]; return 1;
    }
    NSData *salt = aq_data([challenge objectForKey:@"s"]), *B = aq_data([challenge objectForKey:@"B"]);
    NSString *protocol = aq_string([challenge objectForKey:@"sp"]);
    printf("init ACCEPTED: a structured challenge (protocol %s, salt %lu bytes, server value %lu bytes)\n",
           [protocol UTF8String] ?: "?", (unsigned long)[salt length], (unsigned long)[B length]);
    [pool drain]; return 0;
}
