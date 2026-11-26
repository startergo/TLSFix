#ifndef AQUATRANSPORT_ANISETTE_SERVICE_H
#define AQUATRANSPORT_ANISETTE_SERVICE_H
#define AQ_ANISETTE_JOB "/usr/share/aquatransport/org.aquatransport.anisette.plist"
#define AQ_ANISETTE_EXECUTABLE "/usr/share/aquatransport/aquatransport-anisette"
/* Where the clients reach the broker. A build may name another path, which is how the
 * selftest points the `local:` provider at a socket nothing listens on. */
#ifndef AQ_ANISETTE_SOCKET
#define AQ_ANISETTE_SOCKET "/var/run/org.aquatransport.anisette.sock"
#endif
#endif
