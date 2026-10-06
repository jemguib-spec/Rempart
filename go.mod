module github.com/rempart-dns/rempart

go 1.24

replace (
	go.uber.org/mock => github.com/uber-go/mock v0.5.2
	golang.org/x/crypto => github.com/golang/crypto v0.41.0
	golang.org/x/mod => github.com/golang/mod v0.27.0
	golang.org/x/net => github.com/golang/net v0.43.0
	golang.org/x/sync => github.com/golang/sync v0.16.0
	golang.org/x/sys => github.com/golang/sys v0.35.0
	golang.org/x/text => github.com/golang/text v0.28.0
	golang.org/x/tools => github.com/golang/tools v0.36.0
	gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20161208181325-20d25e280405
	gopkg.in/yaml.v3 => github.com/go-yaml/yaml/v3 v3.0.1
)

require (
	github.com/miekg/dns v1.1.62
	github.com/miekg/pkcs11 v1.1.1
	github.com/quic-go/quic-go v0.59.1
	golang.org/x/crypto v0.41.0
	golang.org/x/sys v0.35.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
)
