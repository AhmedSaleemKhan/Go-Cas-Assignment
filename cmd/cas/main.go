package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"assignment-httpserver/pkg/cas"
)

func main() {
	handler, err := cas.New(os.Args[1], "sha256", "sha512-224", "sha512-256", "sha384", "sha512")
	if err != nil {
		log.Fatal(err)
	}

	serverMux := SetUpHandler(handler)

	server := &http.Server{
		Addr:    ":3333",
		Handler: serverMux,
	}

	errServer := server.ListenAndServe()
	if errors.Is(errServer, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if errServer != nil {
		fmt.Printf("error while starting server: %s\n", err)
		os.Exit(1)
	}
}

func SetUpHandler(casHandler *cas.ContentAddressedStorage) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			casHandler.ContentAddressedStorageFileUpload(w, r)
		} else {
			http.Error(w, "method is not supported", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/blob/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			casHandler.HandleGetFile(w, r)
		} else {
			http.Error(w, "method is not supported", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/stats/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			casHandler.ContentAddressedStorageStats(w, r)
		} else {
			http.Error(w, "method is not supported", http.StatusMethodNotAllowed)
		}
	})

	return mux
}
