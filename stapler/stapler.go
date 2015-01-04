// package stapler implements OCSP stapling feature
package stapler

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"sync"
	"sync/atomic"
	"time"

	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"net/http"

	"github.com/mailgun/vulcand/engine"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/log"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/timetools"
)

type Stapler interface {
	Staple(host *engine.Host) ([]byte, error)
	Subscribe(chan *StapleUpdated, chan struct{})
	Close() error
}

type stapler struct {
	v            map[string]*hostStapler
	mtx          *sync.Mutex
	clock        timetools.TimeProvider
	eventsC      chan *stapleFetched
	cnt          int32
	closeC       chan struct{}
	subscribersC []chan *StapleUpdated
}

func (s *stapler) nextId() int32 {
	return atomic.AddInt32(&s.cnt, 1)
}

type hostStapler struct {
	id   int32
	host *engine.Host

	timer  *time.Timer
	s      *stapler
	stopC  chan struct{}
	period time.Duration

	response *StapleResponse
}

type StapleResponse struct {
	Staple   []byte
	Response *ocsp.Response
}

func (s *StapleResponse) IsValid() bool {
	return s.Response.Status == ocsp.Good
}

func (s *StapleResponse) String() string {
	return fmt.Sprintf("StapleResponse(status=%v)", s.Response.Status)
}

func (hs *hostStapler) sameTo(host *engine.Host) bool {
	if !hs.host.Settings.KeyPair.Equals(host.Settings.KeyPair) {
		log.Infof("%v key pair updated", hs)
		return false
	}
	if !hs.host.Settings.OCSP.Equals(host.Settings.OCSP) {
		log.Infof("%v ocsp settings updated", hs)
		return false
	}
	return true
}

func (s *stapler) getStapler(host *engine.Host) (*hostStapler, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	hs, ok := s.v[host.Name]
	if ok && hs.sameTo(host) {
		return hs, true
	}
	// delete the previous entry
	if ok {
		hs.stop()
		delete(s.v, host.Name)
	}
	return nil, false
}

func (s *stapler) setStapler(host *engine.Host, re *hostStapler) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	re, ok := s.v[host.Name]
	if ok {
		re.stop()
	}
	s.v[host.Name] = re
}

func (s *stapler) updateStaple(e *stapleFetched) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	hs, ok := s.v[e.hostName]
	if !ok || hs.id != e.id {
		// this means that it was replaced or removed
		return false
	}
	hs.response = e.re

	if e.err != nil {
		log.Errorf("Failed to fetch staple response for %v, error: %v", e.err)
		if hs.s.clock.UtcNow().After(hs.userUpdate(hs.response.Response.NextUpdate)) {
			log.Errorf("%v retry attempts exceeded, invalidating staple %v", s, hs)
			delete(s.v, e.hostName)
			return true
		}
		hs.schedule(hs.s.clock.UtcNow().Add(ErrRetryPeriod))
		return false
	}

	switch e.re.Response.Status {
	case ocsp.Good:
		log.Infof("%v got good status for %v", s, hs)
		hs.schedule(hs.userUpdate(e.re.Response.NextUpdate))
	case ocsp.Revoked:
		// no need to reschedule if it's revoked
		log.Warningf("%v revoked %v", s, hs)
	case ocsp.Unknown, ocsp.ServerFailed:
		log.Warningf("%v status: %v for %v", s, e.re.Response.Status, hs)
		hs.schedule(hs.s.clock.UtcNow().Add(hs.period))
	}
	return true
}

func (s *stapler) Staple(host *engine.Host) (*StapleResponse, error) {
	if host.Settings.KeyPair == nil {
		return nil, fmt.Errorf("%v has no key pair to staple", host)
	}
	hs, found := s.getStapler(host)
	if found {
		return hs.response, nil
	}
	hs, err := newHostStapler(s, host)
	if err != nil {
		return nil, err
	}
	s.setStapler(host, hs)
	return hs.response, nil
}

func (s *stapler) fanOut() {
	select {
	case e := <-s.eventsC:
		log.Infof("%v got event %v", s, e)
		if !s.updateStaple(e) {
			log.Infof("%v event discarded")
			return
		}
		u := &StapleUpdated{
			HostKey: engine.HostKey{Name: e.hostName},
			Staple:  e.re,
			Err:     e.err,
		}
		for _, c := range s.subscribersC {
			select {
			case c <- u:
			default:
				log.Infof("%v skipping blocked channel")
			}
		}
	}
}

// StapleUpdated is generated whenever stapler status gets updated
type StapleUpdated struct {
	HostKey engine.HostKey
	Staple  *StapleResponse
	Err     error
}

type stapleFetched struct {
	id       int32
	hostName string
	re       *StapleResponse
	err      error
}

func (s *StapleUpdated) String() string {
	return fmt.Sprintf("StapleUpdated(host=%v, response=%v, err=%v)", s.HostKey, s.Staple, s.Err)
}

func newHostStapler(s *stapler, host *engine.Host) (*hostStapler, error) {
	period, err := host.Settings.OCSP.RefreshPeriod()
	if err != nil {
		return nil, err
	}
	hs := &hostStapler{
		id:     s.nextId(),
		host:   host,
		s:      s,
		period: period,
	}

	re, err := getStaple(host.Settings.KeyPair)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	hs.response = re
	if err := hs.schedule(re.Response.NextUpdate); err != nil {
		return nil, err
	}
	return hs, nil
}

func (hs *hostStapler) stop() {
	hs.timer.Stop()
	close(hs.stopC)
}

func (hs *hostStapler) String() string {
	return fmt.Sprintf("hostStapler(%v, %v)", hs.id, hs.host)
}

func (hs *hostStapler) update() {
	log.Infof("%v about to update", hs)
	re, err := getStaple(hs.host.Settings.KeyPair)
	log.Infof("%v got %v %v", hs, re, err)
	hs.s.eventsC <- &stapleFetched{id: hs.id, hostName: hs.host.Name, re: re, err: err}
}

func (hs *hostStapler) userUpdate(nextUpdate time.Time) time.Time {
	now := hs.s.clock.UtcNow()
	userUpdate := now.Add(hs.period)
	if userUpdate.After(nextUpdate) {
		return nextUpdate
	}
	return userUpdate
}

func (hs *hostStapler) schedule(nextUpdate time.Time) error {
	log.Infof("%v schedule update for %v", nextUpdate)
	hs.timer = time.NewTimer(nextUpdate.Sub(hs.s.clock.UtcNow()))
	go func() {
		select {
		case <-hs.timer.C:
			hs.update()
		case <-hs.stopC:
			log.Infof("%v stopped", hs)
		}
	}()
	return nil
}

func getStaple(kp *engine.KeyPair) (*StapleResponse, error) {
	cert, err := tls.X509KeyPair(kp.Cert, kp.Key)
	if err != nil {
		return nil, err
	}

	xc, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	xi, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return nil, err
	}

	data, err := ocsp.CreateRequest(xc, xi, &ocsp.RequestOptions{})
	if err != nil {
		return nil, err
	}

	log.Infof("Provided some servers: %v", xc.OCSPServer)
	var re *ocsp.Response
	var raw []byte
	if len(xc.OCSPServer) == 0 {
		return nil, fmt.Errorf("No OCSP servers specified")
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
		return nil, err
	}
	return &StapleResponse{Response: re, Staple: raw}, nil
}

func getOCSPResponse(server string, request []byte, issuer *x509.Certificate) (*ocsp.Response, []byte, error) {
	client := &http.Client{}
	httpReq, err := http.NewRequest("POST", server, bytes.NewReader(request))
	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-hostStapler")
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

const ErrRetryPeriod = 60 * time.Second
