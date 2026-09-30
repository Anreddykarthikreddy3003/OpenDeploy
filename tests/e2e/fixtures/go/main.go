package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "hello from go") })
	_ = http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}
