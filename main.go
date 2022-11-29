package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// "username": "admin",
// "first_name": "",
// "last_name": "",
// "email": "admin@localhost",
// "is_superuser": true,
// "is_system_auditor": false,
// "ldap_dn": "",
// "last_login": "2022-11-23T16:07:07.958083Z",
// "external_account": null,

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

func authenticateRequest(req *http.Request, client *http.Client, cfg Config) {
	// c, err := req.Cookie(GATEWAY_COOKIE)
	// c.Name = "awx_sessionid"
	c, err := req.Cookie("awx_sessionid")

	if err != nil {
		return
	}
	auth_url, _ := url.Parse(cfg.AwxURL)
	auth_url.Path = "/api/v2/me/"

	auth_request, _ := http.NewRequest(http.MethodGet, auth_url.String(), nil)

	auth_request.AddCookie(c)

	resp, err := client.Do(auth_request)

	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("oopsie daisy")
		return
	}

	var result MeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	req.Header.Set(GATEWAY_HEADER, userToIdentityHeader(result.Results[0]))
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

	fmt.Printf("Proxying request to: %s\n", req.URL.RequestURI())

	// save the response from the origin server
	upstreamServerResponse, err := client.Do(req)

	if err != nil {
		fmt.Println("ERROR")
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(rw, err)
		fmt.Println("")

		return http.Response{}, errors.New("Server error")
	}

	// fmt.Println("REQUEST")
	// fmt.Println(formatRequest(req))

	// fmt.Println("RESPONSE")
	// fmt.Println(formatResponse(upstreamServerResponse))

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

type Config struct {
	GalaxyAPI string
	GalaxyUI  string
	AwxUI     string
	AwxAPI    string
	Port      string
	AwxURL    string
	GalaxyURL string
}

func main() {

	var cfg = Config{

		GalaxyAPI: "/galaxy/api/",
		GalaxyUI:  "/galaxy/",

		AwxAPI: "/awx/api/",
		AwxUI:  "/awx/",

		Port:      getEnv("PROXY_PORT", "8070"),
		AwxURL:    "https://localhost:8043",
		GalaxyURL: "http://localhost:5001",
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

	fmt.Printf("Listening on: %s\n", cfg.Port)

	// taken from https://dev.to/b0r/implement-reverse-proxy-in-gogolang-2cp4
	galaxyProxy := galaxyHandler(cfg, client)
	awxProxy := axwHandler(cfg, client)

	http.Handle(cfg.GalaxyAPI, http.StripPrefix(cfg.GalaxyUI, galaxyProxy))
	http.Handle(cfg.AwxAPI, http.StripPrefix(cfg.AwxUI, awxProxy))

	http.Handle(cfg.GalaxyUI, http.StripPrefix(cfg.GalaxyUI, http.FileServer(http.Dir("./static/galaxy/"))))
	http.Handle(cfg.AwxUI, http.StripPrefix(cfg.AwxUI, http.FileServer(http.Dir("./static/awx/"))))

	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("localhost:%s", cfg.Port), "localhost.crt", "localhost.key", nil))
}
