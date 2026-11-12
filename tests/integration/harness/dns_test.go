package main

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func dnsRequest(name string, queryType uint16) *dns.Msg {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	return message
}

func Test_answerQuery(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings dnsSettings
		name     string
		qtype    uint16
		rcode    int
		answers  int
		answer   string
	}{
		"verify A": {
			settings: dnsSettings{answer: "198.51.100.53", ttl: 60},
			name:     "verify.test",
			qtype:    dns.TypeA,
			rcode:    dns.RcodeSuccess,
			answers:  1,
			answer:   "198.51.100.53",
		},
		"any A": {
			settings: dnsSettings{answer: "198.51.100.53", ttl: 60},
			name:     "anything.example",
			qtype:    dns.TypeA,
			rcode:    dns.RcodeSuccess,
			answers:  1,
			answer:   "198.51.100.53",
		},
		"AAAA nodata": {
			settings: dnsSettings{answer: "198.51.100.53", ttl: 60},
			name:     "verify.test",
			qtype:    dns.TypeAAAA,
			rcode:    dns.RcodeSuccess,
			answers:  0,
		},
		"AAAA answer": {
			settings: dnsSettings{
				answer:  "198.51.100.53",
				answer6: "2001:db8::53", ttl: 60,
			},
			name:    "verify.test",
			qtype:   dns.TypeAAAA,
			rcode:   dns.RcodeSuccess,
			answers: 1,
			answer:  "2001:db8::53",
		},
		"servfail": {
			settings: dnsSettings{answer: "198.51.100.53", ttl: 60},
			name:     "servfail.test",
			qtype:    dns.TypeA,
			rcode:    dns.RcodeServerFailure,
			answers:  0,
		},
		"refused": {
			settings: dnsSettings{answer: "198.51.100.53", ttl: 60},
			name:     "refused.test",
			qtype:    dns.TypeA,
			rcode:    dns.RcodeRefused,
			answers:  0,
		},
		"fail all": {
			settings: dnsSettings{
				answer: "198.51.100.53", ttl: 60,
				failAll: true,
			},
			name:    "verify.test",
			qtype:   dns.TypeA,
			rcode:   dns.RcodeServerFailure,
			answers: 0,
		},
		"nxdomain unknown": {
			settings: dnsSettings{
				answer: "198.51.100.53", ttl: 60,
				nxdomain: true,
			},
			name:    "unknown.test",
			qtype:   dns.TypeA,
			rcode:   dns.RcodeNameError,
			answers: 0,
		},
		"nxdomain verify": {
			settings: dnsSettings{
				answer: "198.51.100.53", ttl: 60,
				nxdomain: true,
			},
			name:    "verify.test",
			qtype:   dns.TypeA,
			rcode:   dns.RcodeSuccess,
			answers: 1,
			answer:  "198.51.100.53",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := answerQuery(dnsRequest(testCase.name, testCase.qtype),
				testCase.settings)

			assert.Equal(t, testCase.rcode, response.Rcode)
			assert.Len(t, response.Answer, testCase.answers)
			if testCase.answer != "" {
				record, ok := response.Answer[0].(*dns.A)
				if ok {
					assert.Equal(t, testCase.answer, record.A.String())
					return
				}
				record6, ok := response.Answer[0].(*dns.AAAA)
				if ok {
					assert.Equal(t, testCase.answer, record6.AAAA.String())
				}
			}
		})
	}
}

func Test_answerQuery_formatError(t *testing.T) {
	t.Parallel()

	response := answerQuery(new(dns.Msg), dnsSettings{answer: "198.51.100.53"})
	assert.Equal(t, dns.RcodeFormatError, response.Rcode)
}
