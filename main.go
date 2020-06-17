package main

import (
	"log"
	"net/http"
)

func main()  {
	http.Handle("/jwt",http.HandlerFunc(jwt))
	log.Fatal(http.ListenAndServe(":6666",nil))
}

func jwt(w http.ResponseWriter, r *http.Request)  {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`welcome to jwt server`))
}