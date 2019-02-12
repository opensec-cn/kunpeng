package main

//go:generate go run ../main.go -prefix ../testdata -o static.go ../testdata
import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// FS() is created by esc and returns a http.Filesystem.
	http.Handle("/", http.FileServer(FS(false)))
	fmt.Println("Open http://localhost:8080/ in browser")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
