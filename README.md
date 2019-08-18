# syncthing-dns

`syncthing-dns` converts DNS queries for `<Syncthing ID>.<domain>` to lookup
requests to Syncthing's Discovery server. If a match is found, directly
accessible IPv6 addresses are identified and returned.

This is useful as an ad-hoc Dynamic DNS replacement if you are running
Syncthing on the target machine anyway.

To set it up you will need to delegate a domain to your machine. By default
it will listen on port 53, alternative you could also instruct a different
DNS server to recurse into `syncthing-dns` running on a different port.
