package webauthn

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Origin is a browser origin a ceremony may be conducted at: a scheme, a host
// and an optional port, with no path, query, fragment or userinfo. Construct
// one with [ParseOrigin]; the zero value is not a usable origin.
type Origin struct {
	scheme string
	host   string
	port   string
}

const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// OriginRejection names why an origin cannot conduct a ceremony, or why a
// string is not a usable origin at all.
type OriginRejection string

// The parse-stage rejections, reported by [ParseOrigin] with an empty
// [OriginError.RPID].
const (
	RejectMalformed   OriginRejection = "malformed"
	RejectTrailingDot OriginRejection = "trailing_dot"
	RejectEmptyLabel  OriginRejection = "empty_label"
	RejectNonASCII    OriginRejection = "non_ascii"
)

// The policy-stage rejections, reported by [RelyingParty.CheckOrigin].
const (
	RejectNoOrigin       OriginRejection = "no_origin"
	RejectInsecureScheme OriginRejection = "insecure_scheme"
	RejectIPHost         OriginRejection = "ip_host"
	RejectHostNotCovered OriginRejection = "host_not_covered"
)

// RejectNotAllowlisted is the list-stage rejection: the policy accepted the
// origin, RPConfig.Origins was set, and it does not hold this origin.
const RejectNotAllowlisted OriginRejection = "not_allowlisted"

// OriginError reports a string that is not a usable origin, or an origin the
// relying party will not conduct a ceremony at. Matchable with errors.As as
// the pointer form. Error's message is diagnostic; a consumer composes its own
// user-facing sentence from Reason, because only the consumer knows what it
// calls the setting that holds the relying-party ID.
type OriginError struct {
	// Origin is the refused value: as given for a parse failure, in canonical
	// form for a policy or list refusal.
	Origin string
	// RPID is the relying party that refused the origin; empty for a parse
	// failure, which involves no relying party.
	RPID   string
	Reason OriginRejection
}

func (e *OriginError) Error() string {
	if e.RPID == "" {
		return fmt.Sprintf("auth/webauthn: %q is not a usable browser origin: %s", e.Origin, e.Reason.clause())
	}
	return fmt.Sprintf("auth/webauthn: origin %q cannot conduct a ceremony for relying party %q: %s", e.Origin, e.RPID, e.Reason.clause())
}

// OriginsError reports an RPConfig.Origins entry [New] refused: one that is not
// a usable origin, or one the origin policy for this relying party would itself
// reject. A list may only narrow what the policy admits, never widen it. It
// wraps the *OriginError naming the reason, so errors.As reaches both.
type OriginsError struct {
	Err   *OriginError
	Entry string
	RPID  string
	Index int
}

func (e *OriginsError) Error() string {
	return fmt.Sprintf("auth/webauthn: RPConfig.Origins[%d] %q cannot narrow the origin policy for relying party %q: %s",
		e.Index, e.Entry, e.RPID, e.Err.Reason.clause())
}

func (e *OriginsError) Unwrap() error { return e.Err }

func (r OriginRejection) clause() string {
	switch r {
	case RejectMalformed:
		return "the value is not an http or https origin of the form scheme://host[:port]"
	case RejectTrailingDot:
		return "the host must not end with a dot"
	case RejectEmptyLabel:
		return "the host must not contain an empty label"
	case RejectNonASCII:
		return "the host must be ASCII; apply IDNA normalization to it first"
	case RejectNoOrigin:
		return "no origin was presented"
	case RejectInsecureScheme:
		return "the scheme must be https unless the host is localhost"
	case RejectIPHost:
		return "the host is an IP address, and an IP address can never be a relying-party ID"
	case RejectHostNotCovered:
		return "the host is not the relying-party ID or a subdomain of it"
	case RejectNotAllowlisted:
		return "the relying party restricts ceremonies to an explicit list of origins, and this is not one of them"
	default:
		return string(r)
	}
}

// ParseOrigin parses a browser origin as a browser serializes it, typically the
// value of an Origin request header. The error is a *[OriginError].
//
// The result is the value a ceremony's response is later compared against, so
// the parser performs only the two normalizations that comparison also
// performs, ASCII case folding and default-port elision, and refuses rather
// than repairs everything else: a trailing dot, an empty label and a non-ASCII
// host are all refused, and an IP literal is kept exactly as written. Repairing
// any of those would move the failure from a clean refusal before the
// authenticator prompt to a mismatch after it.
func ParseOrigin(raw string) (Origin, error) {
	o, err := parseOrigin(raw)
	if err != nil {
		return Origin{}, err
	}
	return o, nil
}

func parseOrigin(raw string) (Origin, *OriginError) {
	refuse := func(reason OriginRejection) (Origin, *OriginError) {
		return Origin{}, &OriginError{Origin: raw, Reason: reason}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return refuse(RejectMalformed)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != schemeHTTPS && scheme != schemeHTTP) || u.Opaque != "" {
		return refuse(RejectMalformed)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return refuse(RejectMalformed)
	}
	if u.Path != "" && u.Path != "/" {
		return refuse(RejectMalformed)
	}
	host, reason := parseHost(u.Hostname())
	if reason != "" {
		return refuse(reason)
	}
	port, ok := parsePort(u.Port(), scheme)
	if !ok || strings.HasSuffix(u.Host, ":") {
		return refuse(RejectMalformed)
	}
	return Origin{scheme: scheme, host: host, port: port}, nil
}

// parseHost lowercases the host and refuses the three shapes no relying-party
// ID can ever cover, each with its own reason; "" means accepted.
func parseHost(raw string) (string, OriginRejection) {
	host := strings.ToLower(raw)
	switch {
	case host == "":
		return "", RejectMalformed
	case strings.HasSuffix(host, "."):
		return "", RejectTrailingDot
	case strings.HasPrefix(host, ".") || strings.Contains(host, ".."):
		return "", RejectEmptyLabel
	case !isASCII(host):
		return "", RejectNonASCII
	}
	return host, ""
}

// parsePort returns the port to carry, "" for the scheme's default, and false
// for a value outside 1..65535 or one not spelled canonically (a leading zero):
// the comparator matches the port textually, so a spelling it would not match
// is refused rather than repaired. url.Parse already refuses a non-numeric port.
func parsePort(port, scheme string) (string, bool) {
	if port == "" {
		return "", true
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", false
	}
	if (scheme == schemeHTTPS && n == 443) || (scheme == schemeHTTP && n == 80) {
		return "", true
	}
	return strconv.Itoa(n), true
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// String renders the origin in its canonical form, "scheme://host[:port]",
// with an IPv6 host bracketed. It is the value the ceremony's response is
// compared against.
func (o Origin) String() string {
	host := o.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if o.port == "" {
		return o.scheme + "://" + host
	}
	return o.scheme + "://" + host + ":" + o.port
}

// Host returns the ASCII-lowercased host, without brackets or port.
func (o Origin) Host() string { return o.host }

// IsZero reports whether o is the zero value rather than a parsed origin.
func (o Origin) IsZero() bool { return o == Origin{} }

func (o Origin) isIPHost() bool { return net.ParseIP(o.host) != nil }
