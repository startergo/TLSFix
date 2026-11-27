/* Device authentication only. Never reads a password or starts Apple sign-in.
 * Including the adapter lets this probe use exactly the production provider path. */
#include "../src/mac/aquatransport_gsa.m"
#include <assert.h>
int main(void) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    NSError *error = nil;
    NSDictionary *headers = aq_anisette(nil, &error);
    if (!headers) {
        /* Only our own fixed error messages are printed; transport errors can embed URLs. */
        fprintf(stderr, "Anisette failed: domain=%s code=%ld\n", [[error domain] UTF8String], (long)[error code]);
        if ([[error domain] isEqual:AQErrorDomain]) fprintf(stderr, "%s\n", [[error localizedDescription] UTF8String]);
        [pool drain]; return 1;
    }
    printf("PASS: live anisette provider returned all required headers (%lu fields); values withheld\n", (unsigned long)[headers count]);
    [pool drain]; return 0;
}
