package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/pkg/errors"
)

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

type ErrWrapFunc func(error, ...string) error

func subWrapper(w ErrWrapFunc, outerPrefix string) ErrWrapFunc {
	return func(err error, prefixes ...string) error {
		return w(err, append(prefixes, outerPrefix)...)
	}
}

func errWrapper(outerPrefix string) ErrWrapFunc {
	return func(err error, prefixes ...string) error {
		for _, v := range prefixes {
			err = errors.Wrap(err, v)
		}
		return errors.Wrap(err, outerPrefix)
	}
}

func orPanic(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var refToDomain sync.Map //Map of abc --> www.yyy.com, so that we can undo httpifying for different domains
var domainToRef sync.Map //Map of www.yyy.com --> abc

func getRef(domain string) string {
	var ref interface{} //fuck gos type system btw
	var exists bool
	if ref, exists = domainToRef.Load(domain); !exists {
		for {
			var b = make([]byte, 3)
			if _, err := rand.Read(b); err != nil {
				log.Println(err)
			} else {
				ref = base64.RawURLEncoding.EncodeToString(b)
				if _, exists = refToDomain.Load(b); !exists {
					refToDomain.Store(domain, ref)
					domainToRef.Store(ref, domain)
					break
				}
			}
		}
	}
	return ref.(string)
}

type DomainStatus struct {
	Best       string //Preferred domain + optional ref to replace this domain with transparently
	Resolvable bool   //Domain is resolvable
	Served     bool   //Domain has a web server
	HTTPS      bool   //Domain has an https web server
	HSTS       bool   //Doman has hsts
	Preload    bool   //Domain has hsts-preloaded
}

var domainStatusCache sync.Map

func getDomainStatus(domain string) DomainStatus {
	if _, exists := domainStatusCache.Load(domain); !exists {
		domain = strings.Split(domain, "/")[0]
		var ds DomainStatus
		ds.Best = domain
		if addrs, err := net.LookupHost(domain); err == nil && len(addrs) > 0 {
			ds.Resolvable = true
			if resp, err := http.Head(domain); err == nil {
				ds.Served = true
				ds.HTTPS = resp.Request.URL.Scheme == "https"
				if hsts := resp.Header.Get("strict-transport-security"); hsts != "" {
					ds.HSTS = true
					if ds2 := getDomainStatus("www." + domain); ds2.Resolvable == true && ds2.HSTS == false {
						ds.Best = ds2.Best
					} else {
						subs := strings.Split(ds2.Best, ".")
						for i := 1; i < len(subs)-1; i++ {
							if mitmDS2 := getDomainStatus(strings.Join(subs[i:], ".")); mitmDS2.Served && !mitmDS2.HSTS { //Causes a couple unnecessary recursions, but no network requests cuz cache, so no biggie
								ds.Best = mitmDS2.Best + getRef(mitmDS2.Best)
								break
							}
						}
					}
				}
			}
		}
		if ds.HTTPS {
			getHttpsCache.Store(ds.Best, domain)
		}
		domainStatusCache.Store(domain, ds)
	}
	status, _ := domainStatusCache.Load(domain)
	return status.(DomainStatus)
}

var getHttpsCache sync.Map

func getHttps(host string) string {
	if _, exists := getHttpsCache.Load(host); !exists {
		if _host := strings.Split(host, "/"); len(_host) != 1 {
			log.Fatal("host with unknown ref:" + _host[0])
		} else {
			getHttpsCache.Store(host, "")
			if resp, err := http.Head("https://" + host); err == nil {
				if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusPermanentRedirect {
					getHttpsCache.Store(host, host)
				} else if loc, err := resp.Location(); err == nil && loc != nil {
					log.Println("Checking redirect for reverse mitm: " + loc.Hostname())
					getHttpsCache.Store(host, getHttps(loc.Hostname()))
				}
			} else if !strings.HasPrefix(host, "www.") {
				getHttpsCache.Store(host, getHttps("www."+host))
			}
		}
	}
	rev_generic, _ := getHttpsCache.Load(host)
	return rev_generic.(string)
}

func main() {
	var err error
	if http.DefaultClient.Jar, err = cookiejar.New(nil); err != nil {
		log.Fatal(err)
	}
	http.DefaultClient.Timeout = time.Second * 10
	http.DefaultClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	proxy := goproxy.NewProxyHttpServer()
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})
	proxy.Tr = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" && addr[len(addr)-4:] == ":443" {
				if names, err := net.LookupAddr(addr); err != nil {
					return nil, err
				} else {
					var foundHSTS bool
					for _, name := range names {
						if ds := getDomainStatus(name); ds.HSTS != false {
							foundHSTS = true
							break
						}
					}
					if !foundHSTS {
						return nil, errors.New("I don't wanna")
					} else {
						return net.Dial(network, addr)
					}
				}
			} else {
				return net.Dial(network, addr)
			}
		},
	}
	proxy.KeepDestinationHeaders = true
	proxy.KeepHeader = true
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if b, err := ioutil.ReadAll(r.Body); err != nil {
			log.Println(err)
		} else {
			domainRegexMeat := `((?:[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(?:\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})+\.(?:com|net|org|edu|gov|mil)(?:/[a-zA-Z\-_0-9]{8})?)`
			forDomain := func(text *string, f func(domain string, mut *sync.Mutex)) *string {
				if domains := regexp.MustCompile(domainRegexMeat).FindAllStringSubmatch(*text, -1); len(domains) > 0 && len(domains[0]) > 1 {
					var wg sync.WaitGroup
					var mut sync.Mutex
					domains_filt := make(map[string]struct{})
					for _, v := range domains {
						v := v[1]
						if vspl := strings.Split(v, "/"); len(vspl) > 1 {
							if _, exists := refToDomain.Load(v[1]); !exists { //If the "ref" is not registered, we want to remove it, because most /[a-z]{3} paths are not actually refs we inserted
								v = vspl[0]
							}
						}
						domains_filt[v] = struct{}{}
					}
					for v := range domains_filt {
						wg.Add(1)
						go func(v string) {
							f(v, &mut)
							wg.Done()
						}(v)
					}
					wg.Wait()
				}
				return text
			}
			toSecure := func(strr string) string {
				str := new(string)
				*str = strr
				return *forDomain(str, func(domain string, mut *sync.Mutex) {
					if revDomain := getHttps(domain); revDomain != "" {
						mut.Lock()
						*str = strings.ReplaceAll(*str, "http://"+domain, "https://"+revDomain)
						*str = strings.ReplaceAll(*str, "http%3A%2F%2F"+domain, "https%3A%2F%2F"+revDomain)
						*str = strings.ReplaceAll(*str, `http:\/\/`+domain, `https:\/\/`+revDomain)
						mut.Unlock()
					}
				})
			}
			log.Println(r.URL.String())
			if rev := getHttps(r.URL.Hostname()); rev != "" {
				r.URL.Host = rev
				r.URL.Scheme = "https"
			}
			if r, err = http.NewRequest(r.Method, r.URL.String(), nopCloser{bytes.NewBufferString(toSecure(string(b)))}); err != nil {
				log.Println(err)
			} else {
				for k, v := range r.Header {
					r.Header.Del(k)
					for _, v2 := range v {
						v2 = toSecure(v2)
						r.Header.Add(k, toSecure(v2))
					}
				}
				http.DefaultClient.Jar.SetCookies(r.URL, r.Cookies())
				//Request
				for {
					if resp, err := http.DefaultClient.Do(r); err != nil {
						log.Println(err)
					} else {
						if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
							if loc, err := resp.Location(); err != nil {
								log.Println(err)
							} else if ds := getDomainStatus(loc.Hostname()); ds.HSTS { //If we can't MITM, transparently collect the redirect
								if resp2, err := http.Get(loc.String()); err != nil {
									//fook
									log.Println(err)
								} else {
									resp = resp2
								}
							}
						}
						toInsecure := func(strr string) string {
							strr = strings.ReplaceAll(strr, "https:", "http:")
							str := new(string)
							*str = strr
							return *forDomain(str, func(domain string, mut *sync.Mutex) {
								ds := getDomainStatus(domain)
								mut.Lock()
								*str = strings.ReplaceAll(*str, domain, ds.Best) //TODO: learn context w/ soup or smthn instead of global replace, so we know whether or not the ref makes sense here
								mut.Unlock()
							})
						}
						//Clean response
						ct := resp.Header.Get("Content-Type")
						if ct == "" ||
							strings.Contains(ct, "application") ||
							strings.Contains(ct, "html") ||
							strings.Contains(ct, "json") ||
							strings.Contains(ct, "text") ||
							strings.Contains(ct, "javascript") {
							b, err = ioutil.ReadAll(resp.Body)
							orPanic(err)
							respStr := toInsecure(string(b))
							resp.Body = nopCloser{bytes.NewBufferString(respStr)}
						}
						for k, v := range resp.Header {
							resp.Header.Del(k)
							if k = strings.ToLower(k); k != "strict-transport-security" &&
								k != "expect-ct" &&
								k != "x-content-type-options" &&
								k != "feature-policy" &&
								k != "content-security-policy" &&
								k != "referrer-policy" &&
								k != "x-xss-protection" &&
								k != "public-key-pins" {
								for _, v2 := range v {
									v2 = toInsecure(v2)
									if strings.Contains(strings.ToLower(k), "set-cookie") {
										v2 = strings.ReplaceAll(v2, "Secure;", "")
										v2 = strings.ReplaceAll(v2, "Secure", "")
										v2 = strings.ReplaceAll(v2, "secure;", "")
										v2 = strings.ReplaceAll(v2, "secure", "")
									}
									resp.Header.Add(k, v2)
								}
							}
						}
						resp.Header.Set("Access-Control-Allow-Origin", "*")
						/*
						   log.Println("Dumping Response:")
						   if b, err := httputil.DumpResponse(resp, true); err == nil {
						       log.Println(string(b))
						   }*/
						return nil, resp
					}
				}
			}
		}
		return r, nil
	})
	go func() {
		log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintln(w, "<html><head><meta http-equiv=\"refresh\" content=\"0; url='http://amazon.com'\" /></head></html>")
		})))
	}()
	log.Fatal(http.ListenAndServe(":80", proxy))
}
