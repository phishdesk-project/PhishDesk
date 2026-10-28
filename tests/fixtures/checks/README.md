# C03 synthetic fixtures

Five hand-authored invented FableBank lab messages. All DNS names use `.test`;
IP literals use reserved documentation addresses. Nothing is visited or resolved.
The offline dates and lookup statuses in `examples/checks-context.json` are invented
test observations, never WHOIS/RDAP results. This is development regression data,
not a detection benchmark or the future frozen evaluation set.

1. Legitimate routine message: exact reference, same Reply-To domain, older age.
2. One-edit lookalike, different Reply-To, three-day offline domain-age observation.
3. Forged Authentication-Results with an apparently trusted service identifier.
4. HTTP, userinfo, deceptive subdomain, IPv4/IPv6 and non-default port.
5. Timeout, unsupported Reply-To and invalid port; uncertainty remains visible.
