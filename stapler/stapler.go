// package stapler implements OCSP stapling feature
package stapler

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"time"

	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"net/http"

	"github.com/mailgun/vulcand/engine"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/log"
)

type Stapler interface {
	Staple(host *engine.Host) (*tls.Certificate, error)
	Subscribe(chan *StapleUpdated, chan struct{})
	Close() error
}

type stapler struct {
	v map[string]*response
}

type response struct {
	host         *engine.Host
	lastResponse []byte
	timer        *time.Timer
	keyPair      *tls.Certificate
}

func (re *response) keyPairEquals(host *engine.Host) bool {
	return re.host.Settings.KeyPair.Equals(host.Settings.KeyPair)
}

func (re *response) stop() {
	re.timer.Stop()
}

func (s *stapler) Staple(host *engine.Host) (*tls.Certificate, error) {
	if host.Settings.KeyPair == nil {
		return nil, fmt.Errorf("%v has no key pair to staple", host)
	}
	re, ok := s.v[host.Name]
	if ok && re.keyPairEquals(host) {
		return re.keyPair, nil
	}
	if ok {
		re.stop()
		delete(s.v, host.Name)
	}
	re, err := newResponse(host)
	if err != nil {
		return nil, err
	}
	s.v[host.Name] = re
	return re.keyPair, nil
}

// StapleUpdated is generated whenever stapler reloads stapler response
type StapleUpdated struct {
	Status   int
	Response []byte
}

func newResponse(host *engine.Host) (*response, error) {
	keyPair, err := tls.X509KeyPair(host.Settings.KeyPair.Cert, host.Settings.KeyPair.Key)
	if err != nil {
		return nil, err
	}
	re := &response{
		host:    host,
		keyPair: &keyPair,
	}
	if err := re.update(); err != nil {
		return err
	}
	return re, nil
}

func (re *response) update() error {
	out := make([]byte, len(b))
	copy(b, out)
	re.lastResponse = out
}

func initCert(c *engine.KeyPair) (*tls.Certificate, error) {
	keyPair, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}
	if err := initStaple(&keyPair); err != nil {
		return nil, err
	}
	return &keyPair, nil
}

func getStaple(cert *tls.Certificate) (*ocsp.Response, []byte, error) {
	xc, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	xi, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return nil, nil, err
	}

	data, err := ocsp.CreateRequest(xc, xi, &ocsp.RequestOptions{})
	if err != nil {
		return nil, nil, err
	}

	log.Infof("Provided some servers: %v", xc.OCSPServer)
	var re *ocsp.Response
	var raw []byte
	if len(xc.OCSPServer) == 0 {
		return nil, nil, fmt.Errorf("No OCSP servers specified")
	}

	for _, s := range xc.OCSPServer {
		log.Infof("OCSP about to query: %v for OCSP", s)
		re, raw, err = getOCSPResponse(s, data, xi)
		if err != nil {
			log.Errorf("Failed to get OCSP response: %v", err)
			continue
		}
		break
	}
	log.Infof("OCSP Status: %v, next update: %v", re.Status, re.NextUpdate)
	if err := re.CheckSignatureFrom(xi); err != nil {
		log.Errorf("OCSP signature check failed for %v, err: %v", err)
		return nil, nil, err
	}
	return re, raw, nil
}

func getOCSPResponse(server string, request []byte, issuer *x509.Certificate) (*ocsp.Response, []byte, error) {
	client := &http.Client{}
	httpReq, err := http.NewRequest("POST", server, bytes.NewReader(request))
	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-response")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	re, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil, nil, err
	}
	return re, body, nil
}
