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
	StapleHost(host *engine.Host) (*StapleResponse, error)
	DeleteHost(host engine.HostKey)
	Subscribe(chan *StapleUpdated, chan struct{})
	Close()
}

type StaplerOption func(s *stapler) error

func Clock(clock timetools.TimeProvider) StaplerOption {
	return func(s *stapler) error {
		s.clock = clock
		return nil
	}
}

func New(opts ...StaplerOption) (Stapler, error) {
	s := &stapler{
		v:           make(map[string]*hostStapler),
		mtx:         &sync.Mutex{},
		eventsC:     make(chan *stapleFetched),
		closeC:      make(chan struct{}),
		subscribers: make(map[int32]chan *StapleUpdated),
	}
	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}
	if s.clock == nil {
		s.clock = &timetools.RealTime{}
	}
	return s, nil
}

type stapler struct {
	v           map[string]*hostStapler
	mtx         *sync.Mutex
	clock       timetools.TimeProvider
	eventsC     chan *stapleFetched
	cnt         int32
	closeC      chan struct{}
	subscribers map[int32]chan *StapleUpdated
}

func (s *stapler) StapleHost(host *engine.Host) (*StapleResponse, error) {
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

func (s *stapler) DeleteHost(hk engine.HostKey) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	hs, ok := s.v[hk.Name]
	if !ok {
		return
	}
	hs.stop()
	delete(s.v, hk.Name)
}

func (s *stapler) Subscribe(in chan *StapleUpdated, closeC chan struct{}) {
	myId := s.subscribe(in)
	select {
	case <-closeC:
		s.unsubscribe(myId)
	}
}

func (s *stapler) Close() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for key, hs := range s.v {
		hs.stop()
		delete(s.v, key)
	}
	close(s.eventsC)
}

func (s *stapler) subscribe(c chan *StapleUpdated) int32 {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	next := s.nextId()
	s.subscribers[next] = c

	return next
}

func (s *stapler) closeSubscribers() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for _, c := range s.subscribers {
		close(c)
	}
}

func (s *stapler) unsubscribe(id int32) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	delete(s.subscribers, id)
}

func (s *stapler) getSubscribers() []chan *StapleUpdated {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	out := make([]chan *StapleUpdated, 0, len(s.subscribers))
	for _, c := range s.subscribers {
		out = append(out, c)
	}
	return out
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

	other, ok := s.v[host.Name]
	if ok {
		other.stop()
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

func (s *stapler) fanOut() {
	select {
	case e := <-s.eventsC:
		log.Infof("%v got event %v", s, e)
		if e == nil {
			log.Infof("%v closed")
			s.closeSubscribers()
			return
		}
		if !s.updateStaple(e) {
			log.Infof("%v event discarded")
			return
		}
		u := &StapleUpdated{
			HostKey: engine.HostKey{Name: e.hostName},
			Staple:  e.re,
			Err:     e.err,
		}
		for _, c := range s.getSubscribers() {
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
		stopC:  make(chan struct{}),
	}

	re, err := getStaple(&host.Settings)
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
	log.Infof("Stopping %v", hs)
	hs.timer.Stop()
	close(hs.stopC)
}

func (hs *hostStapler) String() string {
	return fmt.Sprintf("hostStapler(%v, %v)", hs.id, hs.host)
}

func (hs *hostStapler) update() {
	log.Infof("%v about to update", hs)
	re, err := getStaple(&hs.host.Settings)
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

func getStaple(s *engine.HostSettings) (*StapleResponse, error) {
	kp := s.KeyPair
	cert, err := tls.X509KeyPair(kp.Cert, kp.Key)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) < 2 {
		return nil, fmt.Errorf("Need at least leaf and peer certificate")
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

	servers := xc.OCSPServer
	if s.OCSP.Responder != "" {
		servers = []string{s.OCSP.Responder}
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("No OCSP servers specified")
	}

	var re *ocsp.Response
	var raw []byte
	for _, srv := range servers {
		log.Infof("OCSP about to query: %v for OCSP", s)
		issuer := xi
		if s.OCSP.SkipSignatureCheck {
			log.Warningf("Bypassing signature check")
			// this will bypass signature check
			issuer = nil
		}
		re, raw, err = getOCSPResponse(srv, data, issuer)
		if err != nil {
			log.Errorf("Failed to get OCSP response: %v", err)
			continue
		}
		break
	}
	log.Infof("OCSP Status: %v, this update: %v, next update: %v", re.Status, re.ThisUpdate, re.NextUpdate)
	return &StapleResponse{Response: re, Staple: raw}, nil
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

const ErrRetryPeriod = 60 * time.Second
