// syncthing-dns converts DNS queries for `<Syncthing ID>.<domain>`` to lookup
// requests to Syncthing's Discovery server. If a match is found, directly
// accessible IPv6 addresses are identified and returned.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	dnsAddr     = flag.String("dns-address", ":53", "Host:port to serve DNS from")
	metricsAddr = flag.String("metrics-address", "localhost:9999", "Host:port to serve metrics from")
	domain      = flag.String("domain", "syncthing.example.org", "Domain to serve Syncthing DNS under")
	ttl         = flag.Uint("ttl", 10, "TTL for resulting DNS entries")
)

var (
	queriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "syncthing_dns_queries_total",
		Help: "Total number of queries processed",
	})

	queriesSuccessful = promauto.NewCounter(prometheus.CounterOpts{
		Name: "syncthing_dns_queries_successful_total",
		Help: "Total number of successful queries processed",
	})

	queriesNotFound = promauto.NewCounter(prometheus.CounterOpts{
		Name: "syncthing_dns_queries_not_found_total",
		Help: "Total number of not found responses returned",
	})

	queriesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "syncthing_dns_queries_failed_total",
		Help: "Total number of server failure responses returned",
	})
)

// LookupResponse is the data the lookup server responds with when asked
// about a certain machine.
type LookupResponse struct {
	// Last seen timestamp. This may be hours in the past in case the client
	// went away.
	Seen time.Time `json:seen`

	// List of URLs to connect to the Syncthing instance. This includes raw
	// tcp://, as well as quic:// and relay://. The latter is always an IP that
	// does not actually belong to the client. The IPv4 addresses present are
	// likely NATed and thus not usable for anything beyond Syncthing.
	Addresses []string `json:addresses`
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func lookup(id string) ([]net.IP, *time.Time, error) {
	resp, err := http.Get(fmt.Sprintf("https://discovery.syncthing.net/v2/?device=%s", id))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Compare(body, []byte("Not Found\n")) == 0 {
		return nil, nil, errNotFound{}
	}
	res := LookupResponse{}
	if err := json.Unmarshal(body, &res); err != nil {
		// Note that this also triggers for semantically invalid IDs.
		return nil, nil, err
	}
	addrMap := make(map[string]bool)
	for _, addr := range res.Addresses {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, nil, nil
		}
		switch u.Scheme {
		case "tcp", "quic":
		default:
			continue
		}
		ip := net.ParseIP(u.Hostname())
		if ip == nil {
			continue
		}
		if strings.Contains(ip.String(), ":") {
			// Addresses may appear twice (e.g. with different protocols), so
			// deduplicate them before returning them to the caller.
			addrMap[string(ip)] = true
		}
	}
	addresses := make([]net.IP, 0, len(addrMap))
	for ip := range addrMap {
		addresses = append(addresses, net.IP(ip))
	}
	return addresses, &res.Seen, nil
}

var idRegexp = regexp.MustCompile(`([A-Z0-9]{7}-){7}[A-Z0-9]{7}`)

func handler(w dns.ResponseWriter, req *dns.Msg) {
	queriesTotal.Inc()

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	parts := strings.Split(m.Question[0].Name, ".")
	name := strings.ToUpper(parts[0])
	if !idRegexp.MatchString(name) {
		log.Printf("Invalid name: %q", name)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		queriesFailed.Inc()
		return
	}

	addresses, seen, err := lookup(name)
	if _, ok := err.(errNotFound); ok {
		w.WriteMsg(m)
		queriesNotFound.Inc()
		return
	} else if err != nil {
		log.Printf("Lookup error: %v", err)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		queriesFailed.Inc()
		return
	}

	// This is pretty much cowboy-style answering. The client might not even
	// have asked for AAAA, yet alone TXT. But it works. Do not rely on the
	// TXT record being present for non-ANY queries in the future, though.
	m.Answer = make([]dns.RR, 0, len(addresses))
	for _, ip := range addresses {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(*ttl)},
			AAAA: ip,
		})
	}
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(*ttl)},
		Txt: []string{seen.String()},
	})
	w.WriteMsg(m)
	queriesSuccessful.Inc()
}

func main() {
	flag.Parse()

	// Syncthing uses self-signed certificates for its infrastructure as every host
	// has its own identity key. Turn off validation entirely for now.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if *metricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
				log.Fatalf("Failed to listen for HTTP requests: %v", err)
			}
		}()
	}

	dns.DefaultServeMux.HandleFunc(*domain, handler)

	go func() {
		if err := (&dns.Server{Addr: *dnsAddr, Net: "tcp"}).ListenAndServe(); err != nil {
			log.Fatalf("s.ListenAndServe() failed: %v", err)
		}
	}()
	if err := (&dns.Server{Addr: *dnsAddr, Net: "udp"}).ListenAndServe(); err != nil {
		log.Fatalf("s.ListenAndServe() failed: %v", err)
	}

}
