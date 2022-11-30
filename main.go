package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const GATEWAY_COOKIE = "aap-gateway-session"
const GATEWAY_HEADER = "X-AAP-IDENTITY"

const NAV_INSERT = `
<div style="position: fixed; z-index: 100000000; left: 300px; top: 25px; color: white;">
<a style="color: white;" href="/galaxy/">Go to Galaxy</a>,
<a style="color: white;" href="/awx/">Go to AWX</a>, 
<a style="color: white;" href="/">Go to home page</a>, 
</div>`

type User struct {
	Username    string `json:"username"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Email       string `json:"email"`
	IsSuperuser bool   `json:"is_superuser"`
}

type MeResponse struct {
	Count   int    `json:"count"`
	Results []User `json:"results"`
}

type XAapIdentity struct {
	Identity User `json:"identity"`
}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:length]
}

func userToIdentityHeader(user User) string {

	data, _ := json.Marshal(XAapIdentity{
		Identity: user,
	})

	return base64.StdEncoding.EncodeToString([]byte(data))
}

func authenticateRequest(req *http.Request, client *http.Client, cfg Config) User {
	c, err := req.Cookie("awx_sessionid")

	if err != nil {
		return User{}
	}
	auth_url, _ := url.Parse(cfg.AwxURL)
	auth_url.Path = "/api/v2/me/"

	auth_request, _ := http.NewRequest(http.MethodGet, auth_url.String(), nil)

	auth_request.AddCookie(c)

	resp, err := client.Do(auth_request)

	if err != nil {
		return User{}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return User{}
	}

	var result MeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return User{}
	}

	req.Header.Set(GATEWAY_HEADER, userToIdentityHeader(result.Results[0]))

	return result.Results[0]
}

func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func getEnv(key string, fallback string) string {
	if key, ok := os.LookupEnv(key); ok {
		return key
	}
	return fallback
}

func formatRequest(r *http.Request) string {
	// Create return string
	var request []string // Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)                             // Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host)) // Loop through headers
	for name, headers := range r.Header {
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	} // Return the request as a string
	return strings.Join(request, "\n")
}

func formatResponse(r *http.Response) string {
	// Create return string
	var request []string // Add the request string
	for name, headers := range r.Header {
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}
	request = append(request, fmt.Sprintf("Code: %v, %v", r.Status, r.StatusCode))
	return strings.Join(request, "\n")
}

func requestUpstream(client *http.Client, urlToProxyTo url.URL, rw http.ResponseWriter, req *http.Request) (http.Response, error) {
	req.Host = urlToProxyTo.Host
	req.URL.Host = urlToProxyTo.Host
	req.URL.Scheme = urlToProxyTo.Scheme
	req.RequestURI = ""
	req.URL.Path = "/" + strings.ReplaceAll(req.URL.Path, "//", "/")

	fmt.Printf("Proxying request to: %s\n", req.URL.String())

	// save the response from the origin server
	upstreamServerResponse, err := client.Do(req)

	if err != nil {
		fmt.Println("ERROR")
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(rw, err)
		fmt.Println("")

		return http.Response{}, errors.New("Server error")
	}

	return *upstreamServerResponse, nil
}

func axwHandler(cfg Config, client *http.Client) http.HandlerFunc {
	urlToProxyTo, err := url.Parse(cfg.AwxURL)

	if err != nil {
		log.Fatal("invalid origin server URL")
	}

	fmt.Println("")

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		// Rewrite the url on the incoming request and resend it
		upstreamServerResponse, err := requestUpstream(client, *urlToProxyTo, rw, req)
		if err != nil {
			return
		}

		// handle redirects so they go to the proxied url
		if upstreamServerResponse.StatusCode == 302 {
			upstreamServerResponse.Header.Set("Location", "/awx"+upstreamServerResponse.Header.Get("Location"))
		}

		// Write the response
		for name, values := range upstreamServerResponse.Header {
			rw.Header()[name] = values
		}
		rw.WriteHeader(upstreamServerResponse.StatusCode)
		io.Copy(rw, upstreamServerResponse.Body)

		fmt.Println()
	})
}

func galaxyHandler(cfg Config, client *http.Client) http.HandlerFunc {

	// define origin server URL
	proxyPort := cfg.Port
	urlToProxyTo, err := url.Parse(cfg.GalaxyURL)

	downloadUrlReg := regexp.MustCompile("\"download_url\":\"(http|https)://[^/]+")
	replacementURL := []byte(fmt.Sprintf("\"download_url\":\"http://localhost:%s", proxyPort))

	if err != nil {
		log.Fatal("invalid origin server URL")
	}

	fmt.Println("")

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		authenticateRequest(req, client, cfg)

		// save the response from the origin server
		upstreamServerResponse, err := requestUpstream(client, *urlToProxyTo, rw, req)
		if err != nil {
			return
		}
		if upstreamServerResponse.StatusCode == 302 {
			upstreamServerResponse.Header.Set("Location", "/galaxy"+upstreamServerResponse.Header.Get("Location"))
		}

		// replace any download urls that are found on the response so that they
		// get redirected through the proxy
		data, _ := ioutil.ReadAll(upstreamServerResponse.Body)
		modified := downloadUrlReg.ReplaceAll(data, replacementURL)

		// Write the response
		for name, values := range upstreamServerResponse.Header {
			rw.Header()[name] = values
		}
		rw.WriteHeader(upstreamServerResponse.StatusCode)
		rw.Write(modified)

		fmt.Println()
	})
}

func staticProxy(targetUrl string, client *http.Client) http.HandlerFunc {
	urlToProxyTo, err := url.Parse(targetUrl)
	if err != nil {
		log.Fatal("invalid origin server URL")
	}

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// save the response from the origin server
		fmt.Println(urlToProxyTo)
		upstreamServerResponse, err := requestUpstream(client, *urlToProxyTo, rw, req)
		if err != nil {
			return
		}
		for name, values := range upstreamServerResponse.Header {
			rw.Header()[name] = values
		}
		rw.WriteHeader(upstreamServerResponse.StatusCode)
		io.Copy(rw, upstreamServerResponse.Body)
	})
}

func uiHandler(targetUrl string, client *http.Client) http.HandlerFunc {
	urlToProxyTo, err := url.Parse(targetUrl)
	if err != nil {
		log.Fatal("invalid origin server URL")
	}

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// save the response from the origin server
		upstreamServerResponse, err := requestUpstream(client, *urlToProxyTo, rw, req)
		if err != nil {
			return
		}

		auth_request, _ := http.NewRequest(http.MethodGet, targetUrl, nil)

		resp, _ := client.Do(auth_request)
		data, _ := ioutil.ReadAll(resp.Body)

		modified := bytes.Replace(data, []byte("{API_PATH}"), []byte("/galaxy/api/galaxy/"), -1)
		modified = bytes.Replace(modified, []byte("{BASE_PATH}"), []byte("/galaxy/"), -1)
		modified = bytes.Replace(modified, []byte("<!-- {NAV} -->"), []byte(NAV_INSERT), -1)

		// Write the response
		rw.WriteHeader(upstreamServerResponse.StatusCode)
		rw.Write(modified)

	})
}

func gatewayHandler(cfg Config, client *http.Client) http.HandlerFunc {
	tmpl := template.Must(template.ParseFiles("./static/gateway/index.html"))

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		user := authenticateRequest(req, client, cfg)
		tmpl.Execute(rw, user)

	})
}

type Config struct {
	GalaxyPath string
	AwxPath    string
	Port       string
	AwxURL     string
	GalaxyURL  string
}

func main() {

	var cfg = Config{

		GalaxyPath: "/galaxy/",
		AwxPath:    "/awx/",

		Port:      getEnv("PROXY_PORT", "8070"),
		AwxURL:    "https://localhost:8043",
		GalaxyURL: "http://localhost:8002",
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	redirectClient := &http.Client{
		Transport: tr,
	}

	fmt.Printf("Listening on: %s\n", cfg.Port)

	// galaxy
	http.Handle(cfg.GalaxyPath+"api/", http.StripPrefix(cfg.GalaxyPath, galaxyHandler(cfg, client)))
	http.Handle("/static/galaxy_ng/", http.StripPrefix("/", staticProxy(cfg.GalaxyURL, client)))
	http.Handle(cfg.GalaxyPath, http.StripPrefix(cfg.GalaxyPath, uiHandler(cfg.GalaxyURL, redirectClient)))

	// awx
	http.Handle(cfg.AwxPath+"api/", http.StripPrefix(cfg.AwxPath, axwHandler(cfg, client)))
	http.Handle(cfg.AwxPath+"static/", http.StripPrefix(cfg.AwxPath, staticProxy(cfg.AwxURL, client)))
	http.Handle(cfg.AwxPath, http.StripPrefix(cfg.AwxPath, uiHandler(cfg.AwxURL, redirectClient)))

	// gateway
	http.Handle("/", gatewayHandler(cfg, client))

	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("aap.gateway.local:%s", cfg.Port), "localhost.crt", "localhost.key", nil))
}
