package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	gohandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type claims struct {
	//UUID string
	jwt.StandardClaims
}

var jwtKey = []byte("my_secret_key")

func response(status int16, message string) map[string]interface{} {
	return map[string]interface{}{
		"status":  status,
		"message": message,
	}
}

func getRequestToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	authArr := strings.Split(authHeader, " ")
	if len(authArr) == 2 {
		return authArr[1]
	}
	return ""
}

func publicEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := response(1, "publicEndpoint")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func privateEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := response(2, "privateEndpoint")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func getToken(w http.ResponseWriter, r *http.Request) {

	// https://godoc.org/github.com/dgrijalva/jwt-go#StandardClaims
	expiresAt := time.Now().Add(20 * time.Minute).Unix()
	claims := &claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := response(3, "getToken")
	resp["token"] = tokenString

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func setHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, cache-control")

		next.ServeHTTP(w, r)
	})
}

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		publicEndpoints := []string{"/public", "/token"}
		path := r.URL.Path

		for _, endpoint := range publicEndpoints {
			if endpoint == path {
				next.ServeHTTP(w, r)
				return
			}
		}

		bearToken := getRequestToken(r)
		if bearToken == "" {
			resp := response(-1, "Token is missing")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(resp)
			return
		}

		claims := &claims{}

		token, err := jwt.ParseWithClaims(bearToken, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			log.Println(err)
			// Standard Claim validation errors
			//ValidationErrorAudience      // AUD validation failed
			//ValidationErrorExpired       // EXP validation failed
			//ValidationErrorIssuedAt      // IAT validation failed
			//ValidationErrorIssuer        // ISS validation failed
			//ValidationErrorNotValidYet   // NBF validation failed
			//ValidationErrorId            // JTI validation failed
			//ValidationErrorClaimsInvalid // Generic claims validation error
			switch {
			case strings.HasPrefix(err.Error(), "token is expired by"):
				resp := response(-1, "Token is expired")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(resp)
				return
			case strings.HasPrefix(err.Error(), "signature is invalid"):
				resp := response(-1, "Signature is invalid")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(resp)
				return
			default:
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		if !token.Valid {
			resp := response(-1, "Token is not valid")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(resp)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {

	router := mux.NewRouter()

	// router.HandleFunc("/public", publicEndpoint).Methods(http.MethodPost)
	postRouter := router.Methods(http.MethodPost).Subrouter()
	postRouter.HandleFunc("/public", publicEndpoint)
	postRouter.HandleFunc("/private", privateEndpoint)
	postRouter.HandleFunc("/token", getToken)

	// Middlewares
	router.Use(setHeadersMiddleware)
	router.Use(jwtMiddleware)

	// CORS
	corsMiddleware := gohandlers.CORS(gohandlers.AllowedOrigins([]string{"*"}))

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)

	server := &http.Server{
		Addr:           ":3000",
		Handler:        corsMiddleware(router),
		ErrorLog:       logger,
		ReadTimeout:    5 * time.Second,  // max time to read request from the client
		WriteTimeout:   10 * time.Second, // max time to write response to the client
		MaxHeaderBytes: 1 << 20,
		IdleTimeout:    120 * time.Second, // max time for connections using TCP Keep-Alive
	}

	go func() {
		log.Println("Starting server on port 3000")
		err := server.ListenAndServe()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	signal.Notify(sigChan, os.Kill)

	sig := <-sigChan
	log.Println("Got signal: ", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}
