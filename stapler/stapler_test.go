package stapler

import (
	"encoding/hex"
	"golang.org/x/crypto/ocsp"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/log"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/timetools"
	"github.com/mailgun/vulcand/engine"

	. "github.com/mailgun/vulcand/Godeps/_workspace/src/gopkg.in/check.v1"
)

func TestStapler(t *testing.T) { TestingT(t) }

var _ = Suite(&StaplerSuite{})

type StaplerSuite struct {
	st    *stapler
	clock *timetools.FreezedTime
}

func (s *StaplerSuite) SetUpSuite(c *C) {
	log.Init([]*log.LogConfig{&log.LogConfig{Name: "console"}})
	// initialize clock to OCSP response current update:
	bytes, err := hex.DecodeString(ocspResponseHex)
	c.Assert(err, IsNil)
	re, err := ocsp.ParseResponse(bytes, nil)
	c.Assert(err, IsNil)
	s.clock = &timetools.FreezedTime{CurrentTime: re.ThisUpdate.Add(time.Hour)}
}

func (s *StaplerSuite) SetUpTest(c *C) {
	v, err := New(Clock(s.clock))
	c.Assert(err, IsNil)
	s.st = v.(*stapler)
}

func (s *StaplerSuite) TearDownTest(c *C) {
	s.st.Close()
}

func (s *StaplerSuite) TestCRUD(c *C) {
	srv := newResponder()
	defer srv.Close()

	h, err := engine.NewHost("localhost",
		engine.HostSettings{
			KeyPair: &engine.KeyPair{Key: localhostKey, Cert: localhostCert},
			OCSP:    &engine.OCSPSettings{Period: "1h", Responder: srv.URL, SkipSignatureCheck: true},
		})
	c.Assert(err, IsNil)

	re, err := s.st.StapleHost(h)
	c.Assert(err, IsNil)
	c.Assert(re, NotNil)

	c.Assert(re.Response.Status, Equals, ocsp.Good)

	// subsequent call will return cached response
	other, err := s.st.StapleHost(h)
	c.Assert(err, IsNil)
	c.Assert(re, NotNil)
	c.Assert(other, Equals, re)

	// delete host
	hk := engine.HostKey{Name: h.Name}
	s.st.DeleteHost(hk)
	c.Assert(len(s.st.v), Equals, 0)

	// second call succeeds
	s.st.DeleteHost(hk)
}

// Update of the settings re-initializes staple
func (s *StaplerSuite) TestUpdateSettings(c *C) {
	srv := newResponder()
	defer srv.Close()

	h, err := engine.NewHost("localhost",
		engine.HostSettings{
			KeyPair: &engine.KeyPair{Key: localhostKey, Cert: localhostCert},
			OCSP:    &engine.OCSPSettings{Period: "1h", Responder: srv.URL, SkipSignatureCheck: true},
		})
	c.Assert(err, IsNil)

	re, err := s.st.StapleHost(h)
	c.Assert(err, IsNil)
	c.Assert(re, NotNil)

	c.Assert(re.Response.Status, Equals, ocsp.Good)

	id := s.st.v[h.Name].id

	h2, err := engine.NewHost("localhost",
		engine.HostSettings{
			KeyPair: &engine.KeyPair{Key: localhostKey, Cert: localhostCert},
			OCSP:    &engine.OCSPSettings{Period: "2h", Responder: srv.URL, SkipSignatureCheck: true},
		})
	c.Assert(err, IsNil)

	re2, err := s.st.StapleHost(h2)
	c.Assert(err, IsNil)
	c.Assert(re2, NotNil)
	c.Assert(re2.Response.Status, Equals, ocsp.Good)

	// the host stapler has been updated
	id2 := s.st.v[h.Name].id

	c.Assert(re2, Not(Equals), re)
	c.Assert(id2, Not(Equals), id)
}

// Periodic update updated the staple value
func (s *StaplerSuite) TestUpdateStapleResult(c *C) {
	srv := newResponder()
	defer srv.Close()

	h, err := engine.NewHost("localhost",
		engine.HostSettings{
			KeyPair: &engine.KeyPair{Key: localhostKey, Cert: localhostCert},
			OCSP:    &engine.OCSPSettings{Period: "1h", Responder: srv.URL, SkipSignatureCheck: true},
		})
	c.Assert(err, IsNil)

	events := make(chan *StapleUpdated, 1)
	close := make(chan struct{})
	go s.st.Subscribe(events, close)

	re, err := s.st.StapleHost(h)
	c.Assert(err, IsNil)
	c.Assert(re, NotNil)
	c.Assert(re.Response.Status, Equals, ocsp.Good)

	s.st.kickC <- true

	var update *StapleUpdated
	select {
	case update = <-events:
		c.Assert(update, NotNil)
	case <-time.After(10 * time.Millisecond):
		c.Fatalf("timeout waiting for update")
	}
}

func (s *StaplerSuite) TestBadArguments(c *C) {
	h, err := engine.NewHost("localhost", engine.HostSettings{})
	c.Assert(err, IsNil)

	re, err := s.st.StapleHost(h)
	c.Assert(err, NotNil)
	c.Assert(re, IsNil)
}

func newResponder() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bytes, err := hex.DecodeString(ocspResponseHex)
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "ocsp-response")
		w.Write(bytes)
	}))
}

var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBdzCCASOgAwIBAgIBADALBgkqhkiG9w0BAQUwEjEQMA4GA1UEChMHQWNtZSBD
bzAeFw03MDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTlaMBIxEDAOBgNVBAoTB0Fj
bWUgQ28wWjALBgkqhkiG9w0BAQEDSwAwSAJBAN55NcYKZeInyTuhcCwFMhDHCmwa
IUSdtXdcbItRB/yfXGBhiex00IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEA
AaNoMGYwDgYDVR0PAQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1Ud
EwEB/wQFMAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAA
AAAAAAAAAAAAAAEwCwYJKoZIhvcNAQEFA0EAAoQn/ytgqpiLcZu9XKbCJsJcvkgk
Se6AbGXgSlq+ZCEVo0qIwSgeBqmsJxUu7NCSOwVJLYNEBO2DtIxoYVk+MA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBdzCCASOgAwIBAgIBADALBgkqhkiG9w0BAQUwEjEQMA4GA1UEChMHQWNtZSBD
bzAeFw03MDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTlaMBIxEDAOBgNVBAoTB0Fj
bWUgQ28wWjALBgkqhkiG9w0BAQEDSwAwSAJBAN55NcYKZeInyTuhcCwFMhDHCmwa
IUSdtXdcbItRB/yfXGBhiex00IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEA
AaNoMGYwDgYDVR0PAQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1Ud
EwEB/wQFMAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAA
AAAAAAAAAAAAAAEwCwYJKoZIhvcNAQEFA0EAAoQn/ytgqpiLcZu9XKbCJsJcvkgk
Se6AbGXgSlq+ZCEVo0qIwSgeBqmsJxUu7NCSOwVJLYNEBO2DtIxoYVk+MA==
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN55NcYKZeInyTuhcCwFMhDHCmwaIUSdtXdcbItRB/yfXGBhiex0
0IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEAAQJBAQdUx66rfh8sYsgfdcvV
NoafYpnEcB5s4m/vSVe6SU7dCK6eYec9f9wpT353ljhDUHq3EbmE4foNzJngh35d
AekCIQDhRQG5Li0Wj8TM4obOnnXUXf1jRv0UkzE9AHWLG5q3AwIhAPzSjpYUDjVW
MCUXgckTpKCuGwbJk7424Nb8bLzf3kllAiA5mUBgjfr/WtFSJdWcPQ4Zt9KTMNKD
EUO0ukpTwEIl6wIhAMbGqZK3zAAFdq8DD2jPx+UJXnh0rnOkZBzDtJ6/iN69AiEA
1Aq8MJgTaYsDQWyU/hDq5YkDJc9e9DSCvUIzqxQWMQE=
-----END RSA PRIVATE KEY-----`)

// Took from golang.org/x/crypto/ocsp
const ocspResponseHex = "308206bc0a0100a08206b5308206b106092b0601050507300101048206a23082069e3081" +
	"c9a14e304c310b300906035504061302494c31163014060355040a130d5374617274436f" +
	"6d204c74642e312530230603550403131c5374617274436f6d20436c6173732031204f43" +
	"5350205369676e6572180f32303130303730373137333531375a30663064303c30090605" +
	"2b0e03021a050004146568874f40750f016a3475625e1f5c93e5a26d580414eb4234d098" +
	"b0ab9ff41b6b08f7cc642eef0e2c45020301d0fa8000180f323031303037303731353031" +
	"30355aa011180f32303130303730373138333531375a300d06092a864886f70d01010505" +
	"000382010100ab557ff070d1d7cebbb5f0ec91a15c3fed22eb2e1b8244f1b84545f013a4" +
	"fb46214c5e3fbfbebb8a56acc2b9db19f68fd3c3201046b3824d5ba689f99864328710cb" +
	"467195eb37d84f539e49f859316b32964dc3e47e36814ce94d6c56dd02733b1d0802f7ff" +
	"4eebdbbd2927dcf580f16cbc290f91e81b53cb365e7223f1d6e20a88ea064104875e0145" +
	"672b20fc14829d51ca122f5f5d77d3ad6c83889c55c7dc43680ba2fe3cef8b05dbcabdc0" +
	"d3e09aaf9725597f8c858c2fa38c0d6aed2e6318194420dd1a1137445d13e1c97ab47896" +
	"17a4e08925f46f867b72e3a4dc1f08cb870b2b0717f7207faa0ac512e628a029aba7457a" +
	"e63dcf3281e2162d9349a08204ba308204b6308204b23082039aa003020102020101300d" +
	"06092a864886f70d010105050030818c310b300906035504061302494c31163014060355" +
	"040a130d5374617274436f6d204c74642e312b3029060355040b13225365637572652044" +
	"69676974616c204365727469666963617465205369676e696e6731383036060355040313" +
	"2f5374617274436f6d20436c6173732031205072696d61727920496e7465726d65646961" +
	"746520536572766572204341301e170d3037313032353030323330365a170d3132313032" +
	"333030323330365a304c310b300906035504061302494c31163014060355040a130d5374" +
	"617274436f6d204c74642e312530230603550403131c5374617274436f6d20436c617373" +
	"2031204f435350205369676e657230820122300d06092a864886f70d0101010500038201" +
	"0f003082010a0282010100b9561b4c45318717178084e96e178df2255e18ed8d8ecc7c2b" +
	"7b51a6c1c2e6bf0aa3603066f132fe10ae97b50e99fa24b83fc53dd2777496387d14e1c3" +
	"a9b6a4933e2ac12413d085570a95b8147414a0bc007c7bcf222446ef7f1a156d7ea1c577" +
	"fc5f0facdfd42eb0f5974990cb2f5cefebceef4d1bdc7ae5c1075c5a99a93171f2b0845b" +
	"4ff0864e973fcfe32f9d7511ff87a3e943410c90a4493a306b6944359340a9ca96f02b66" +
	"ce67f028df2980a6aaee8d5d5d452b8b0eb93f923cc1e23fcccbdbe7ffcb114d08fa7a6a" +
	"3c404f825d1a0e715935cf623a8c7b59670014ed0622f6089a9447a7a19010f7fe58f841" +
	"29a2765ea367824d1c3bb2fda308530203010001a382015c30820158300c0603551d1301" +
	"01ff04023000300b0603551d0f0404030203a8301e0603551d250417301506082b060105" +
	"0507030906092b0601050507300105301d0603551d0e0416041445e0a36695414c5dd449" +
	"bc00e33cdcdbd2343e173081a80603551d230481a030819d8014eb4234d098b0ab9ff41b" +
	"6b08f7cc642eef0e2c45a18181a47f307d310b300906035504061302494c311630140603" +
	"55040a130d5374617274436f6d204c74642e312b3029060355040b132253656375726520" +
	"4469676974616c204365727469666963617465205369676e696e67312930270603550403" +
	"13205374617274436f6d2043657274696669636174696f6e20417574686f726974798201" +
	"0a30230603551d12041c301a8618687474703a2f2f7777772e737461727473736c2e636f" +
	"6d2f302c06096086480186f842010d041f161d5374617274436f6d205265766f63617469" +
	"6f6e20417574686f72697479300d06092a864886f70d01010505000382010100182d2215" +
	"8f0fc0291324fa8574c49bb8ff2835085adcbf7b7fc4191c397ab6951328253fffe1e5ec" +
	"2a7da0d50fca1a404e6968481366939e666c0a6209073eca57973e2fefa9ed1718e8176f" +
	"1d85527ff522c08db702e3b2b180f1cbff05d98128252cf0f450f7dd2772f4188047f19d" +
	"c85317366f94bc52d60f453a550af58e308aaab00ced33040b62bf37f5b1ab2a4f7f0f80" +
	"f763bf4d707bc8841d7ad9385ee2a4244469260b6f2bf085977af9074796048ecc2f9d48" +
	"a1d24ce16e41a9941568fec5b42771e118f16c106a54ccc339a4b02166445a167902e75e" +
	"6d8620b0825dcd18a069b90fd851d10fa8effd409deec02860d26d8d833f304b10669b42"
