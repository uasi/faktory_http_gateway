package main

import (
	"encoding/json"
	"fmt"
	"github.com/rs/cors"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	mw "github.com/auth0/go-jwt-middleware"
	faktory "github.com/contribsys/faktory/client"
	"github.com/gorilla/mux"
)

type handler struct {
	Client *faktory.Client
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeError(w, "gateway_server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	job, err := newJob(body)
	if err != nil {
		writeError(w, "request_error", err.Error(), http.StatusBadRequest)
		return
	}

	if err = h.Client.Push(job); err != nil {
		if _, ok := err.(*faktory.ProtocolError); ok {
			writeError(w, "request_error", err.Error(), http.StatusBadRequest)
		} else {
			writeError(w, "faktory_server_error", err.Error(), http.StatusServiceUnavailable)
		}
		return
	}

	fmt.Fprintln(w, `{"status":200}`)
}

func newJob(body []byte) (job *faktory.Job, err error) {
	var req faktory.Job = faktory.Job{}
	err = json.Unmarshal(body, &req)
	if err != nil {
		return
	}

	if req.Jid == "" {
		req.Jid = faktory.RandomJid()
	}
	job = &req
	return
}

func writeError(w http.ResponseWriter, kind, message string, code int) {
	payload := map[string]interface{}{
		"status": code,
		"error": map[string]string{
			"kind":    kind,
			"message": message,
		},
	}
	body, _ := json.Marshal(payload)
	w.WriteHeader(code)
	fmt.Fprintln(w, string(body))
}

type authenticator struct {
	Token string
}

func (a authenticator) Middleware(next http.Handler) http.Handler {
	extractToken := mw.FromFirst(mw.FromParameter("_token"), mw.FromAuthHeader)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractToken(r)
		if err != nil {
			w.Header().Add("WWW-Authenticate", `Bearer realm="token_required"`)
			writeError(w, "request_error", "token required", http.StatusUnauthorized)
			return
		}

		if token != a.Token {
			w.Header().Add("WWW-Authenticate", `Bearer realm="token_required" error="invalid_token"`)
			writeError(w, "request_error", "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := "localhost:7409"
	if len(os.Args) > 1 {
		for _, h := range []string{"-?", "-h", "-help", "--help", "help"} {
			if os.Args[1] == h {
				fmt.Println("usage: AUTH_TOKEN=<token> [FAKTORY_PROVIDER=<name>|FAKTORY_URL=<url>] faktory_http_gateway [<addr>]")
				return
			}
		}
		addr = os.Args[1]
	}

	token := os.Getenv("AUTH_TOKEN")
	if token == "" {
		log.Fatalf("AUTH_TOKEN environment variable must be set\n")
	}
	auth := authenticator{Token: token}

	client, err := faktory.Open()
	if err != nil {
		log.Fatalf("Failed to connect to Faktory server: %v\n", err)
	}
	handler := handler{Client: client}

	r := mux.NewRouter()
	r.Use(auth.Middleware)
	r.PathPrefix("/").
		Handler(handler).
		Methods("POST")
	c := cors.New(cors.Options{
		AllowedHeaders: []string{"*", "Authorization"},
	})
	h := c.Handler(r)
	http.Handle("/", h)

	log.Printf("Listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
