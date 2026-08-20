package artifact_test

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// A DNS server, in a test file, for one reason: the DNS-rebinding test needs a name whose
// resolution it controls.
//
// The property being proven is that this service validates THE ADDRESS IT CONNECTS TO and not the
// hostname it was given. Every other way of testing that is a test of something else — a literal
// `https://10.0.0.1/` proves the address check works but says nothing about where in the sequence
// it runs, and a real hostname that happens to resolve somewhere private makes the suite depend on
// the internet and on somebody else's DNS zone.
//
// So: a name that resolves to whatever the test says, answered by a server the test owns, and an
// assertion that the dial is refused with the RESOLVED ADDRESS in the error rather than the name.
// A guard that checked the hostname would pass every other test in this package and fail this one.

// dnsRecords is what a fakeDNS answers, keyed by the fully qualified name including the trailing
// dot, which is how it arrives on the wire.
type dnsRecords map[string]net.IP

// fakeDNS is a UDP DNS server answering exactly the records it was given.
type fakeDNS struct {
	conn *net.UDPConn
	wg   sync.WaitGroup
}

// startFakeDNS answers records and nothing else, on loopback, until the test ends.
func startFakeDNS(t *testing.T, records dnsRecords) *net.Resolver {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	s := &fakeDNS{conn: conn}
	s.wg.Add(1)
	go s.serve(records)

	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		// Waited for rather than abandoned: goleak runs after the suite, and a server goroutine
		// still reading from a closed socket is exactly what it exists to report.
		s.wg.Wait()
	})

	addr := conn.LocalAddr().String()
	return &net.Resolver{
		// PreferGo AND Dial. Dial alone would still let cgo answer on a platform where the system
		// resolver is the default, and this test is worthless if the lookup goes anywhere else.
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The address the resolver wanted is ignored: whatever /etc/resolv.conf says, this
			// test's questions go to this test's server.
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

func (s *fakeDNS) serve(records dnsRecords) {
	defer s.wg.Done()

	buf := make([]byte, 512) // a UDP DNS message without EDNS0; the queries here are tiny
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // the test closed the socket
		}
		reply, err := answer(buf[:n], records)
		if err != nil {
			continue // a question this server does not understand goes unanswered, as one would
		}
		if _, err := s.conn.WriteToUDP(reply, from); err != nil {
			return
		}
	}
}

// The pieces of the DNS wire format this needs. Named rather than inline, because a bare 12 in the
// middle of a slice expression is the reason binary parsers are hard to read.
const (
	dnsHeaderLen  = 12
	dnsTypeA      = 1
	dnsTypeAAAA   = 28
	dnsClassIN    = 1
	dnsFlagsReply = 0x8180 // QR=1 response, RD=1, RA=1, RCODE=0 NOERROR
	dnsTTL        = 60
	// dnsNamePointer is a compression pointer to offset 12, where the question's name sits. Every
	// answer here is for the name that was asked about, so pointing at it is both correct and the
	// shortest encoding.
	dnsNamePointer = 0xC00C
)

// answer builds a reply to query. It handles exactly one question, of type A or AAAA, in class IN.
func answer(query []byte, records dnsRecords) ([]byte, error) {
	if len(query) < dnsHeaderLen {
		return nil, errShortQuery
	}
	name, offset, err := readName(query, dnsHeaderLen)
	if err != nil {
		return nil, err
	}
	if len(query) < offset+4 {
		return nil, errShortQuery
	}
	qtype := binary.BigEndian.Uint16(query[offset:])
	qclass := binary.BigEndian.Uint16(query[offset+2:])
	if qclass != dnsClassIN {
		return nil, errUnsupportedQuery
	}
	questionEnd := offset + 4

	reply := make([]byte, 0, len(query)+16)
	reply = append(reply, query[:2]...) // the transaction id, echoed
	reply = binary.BigEndian.AppendUint16(reply, dnsFlagsReply)
	reply = binary.BigEndian.AppendUint16(reply, 1) // QDCOUNT

	ip, known := records[name]
	rdata := rdataFor(ip, qtype)
	// An answer count of zero with RCODE=0 is NODATA: "this name exists, and not with that type".
	// It is what makes an A-only record answer an AAAA question promptly, instead of the resolver
	// waiting out its own timeout and turning a fast test into a slow one.
	if !known || rdata == nil {
		reply = binary.BigEndian.AppendUint16(reply, 0) // ANCOUNT
		reply = binary.BigEndian.AppendUint16(reply, 0) // NSCOUNT
		reply = binary.BigEndian.AppendUint16(reply, 0) // ARCOUNT
		return append(reply, query[dnsHeaderLen:questionEnd]...), nil
	}

	reply = binary.BigEndian.AppendUint16(reply, 1) // ANCOUNT
	reply = binary.BigEndian.AppendUint16(reply, 0) // NSCOUNT
	reply = binary.BigEndian.AppendUint16(reply, 0) // ARCOUNT
	reply = append(reply, query[dnsHeaderLen:questionEnd]...)

	reply = binary.BigEndian.AppendUint16(reply, dnsNamePointer)
	reply = binary.BigEndian.AppendUint16(reply, qtype)
	reply = binary.BigEndian.AppendUint16(reply, dnsClassIN)
	reply = binary.BigEndian.AppendUint32(reply, dnsTTL)
	reply = binary.BigEndian.AppendUint16(reply, uint16(len(rdata)))
	return append(reply, rdata...), nil
}

// rdataFor renders ip for the question type, or nil when the record does not answer it.
func rdataFor(ip net.IP, qtype uint16) []byte {
	switch qtype {
	case dnsTypeA:
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	case dnsTypeAAAA:
		// To4 first: an IPv4 address held in a 16-byte net.IP would otherwise be served as an
		// IPv4-mapped AAAA record, which is a different answer from the one the test wrote down.
		if ip.To4() == nil {
			if v6 := ip.To16(); v6 != nil {
				return v6
			}
		}
	}
	return nil
}

// readName decodes a DNS name into its dotted form, trailing dot included.
func readName(msg []byte, at int) (string, int, error) {
	var labels []string
	for at < len(msg) {
		n := int(msg[at])
		switch {
		case n == 0:
			return strings.Join(labels, ".") + ".", at + 1, nil
		case n&0xC0 != 0:
			// A compression pointer in a question is not something a resolver sends, and
			// following one here would be parsing generosity this test has no use for.
			return "", 0, errUnsupportedQuery
		case at+1+n > len(msg):
			return "", 0, errShortQuery
		}
		labels = append(labels, string(msg[at+1:at+1+n]))
		at += 1 + n
	}
	return "", 0, errShortQuery
}

var (
	errShortQuery       = &dnsError{"the query is shorter than its own header"}
	errUnsupportedQuery = &dnsError{"the query is a shape this test server does not answer"}
)

type dnsError struct{ msg string }

func (e *dnsError) Error() string { return e.msg }
