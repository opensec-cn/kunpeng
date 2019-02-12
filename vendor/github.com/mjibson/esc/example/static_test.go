package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func Test_FileServer(t *testing.T) {
	s := httptest.NewServer(http.FileServer(FS(false)))

	tests := []struct {
		url        string
		httpStatus int
	}{
		{"/", 200},
		{"/index.html", 200},
		{"/index.php", 404},
		{"/assets/css/main.css", 200},
		{"/olololo", 404},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			resp, err := http.Get(s.URL + tt.url)
			if err != nil {
				t.Errorf("http.Get for %q. should not return err: %v", tt.url, err)
				return
			}
			if resp.StatusCode != tt.httpStatus {
				t.Errorf("Status code for %q. = %v, want %v", tt.url, resp.StatusCode, tt.httpStatus)
			}
		})
	}
}

func TestDir_escStatic(t *testing.T) {
	testDir(false, t)
}

func TestDir_escLocal(t *testing.T) {
	testDir(true, t)
}

func testDir(useLocal bool, t *testing.T) {
	s := httptest.NewServer(http.FileServer(Dir(useLocal, "/assets")))

	tests := []struct {
		url        string
		httpStatus int
	}{
		{"/", 200},
		{"/css/main.css", 200},
		{"/js/util.js", 200},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			resp, err := http.Get(s.URL + tt.url)
			if err != nil {
				t.Errorf("http.Get for %q. should not return err: %v", tt.url, err)
				return
			}
			if resp.StatusCode != tt.httpStatus {
				t.Errorf("Status code for %q. = %v, want %v", tt.url, resp.StatusCode, tt.httpStatus)
			}
		})
	}
}

func Benchmark_FileServer(b *testing.B) {
	benchmarksURLs := []string{
		"/",
		"/index.html",
		"/assets/css/main.css",
		"/ololo",
	}
	s := httptest.NewServer(http.FileServer(FS(false)))
	b.ResetTimer()
	for _, url := range benchmarksURLs {
		b.Run(url, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = http.Get(s.URL + url)
			}
		})
	}
}

func Test__escStatic_Open(t *testing.T) {
	testFSOpen(false, t)
}

func Test__escLocal_Open(t *testing.T) {
	testFSOpen(true, t)
}

func testFSOpen(useLocal bool, t *testing.T) {
	fs := FS(useLocal)
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"/index.html", false},
		{"/index.php", true},
		{"/assets/css/main.css", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:uselocal=%t", tt.name, useLocal), func(t *testing.T) {
			got, err := fs.Open(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("%q. _escLocalFS.Open() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			if tt.wantErr {
				// because all check after only for case when fs.Open return non-err
				return
			}
			raw, err := ioutil.ReadAll(got)
			if err != nil {
				t.Errorf("%q. _escLocalFS.Read should not return error. got error = %v,", tt.name, err)
				return
			}
			originalFileRaw, err := ioutil.ReadFile("../testdata" + tt.name)

			if !bytes.Equal(originalFileRaw, raw) {
				t.Errorf("%q. _escLocalFS.Open() = %s, want %s", tt.name, raw, originalFileRaw)
			}
		})
	}
}

func Test_escFile_Readdir(t *testing.T) {
	testFSReaddir(false, t)
}

func Test_escLocalFS_Readdir(t *testing.T) {
	testFSReaddir(true, t)
}

func testFSReaddir(useLocal bool, t *testing.T) {
	fs := FS(useLocal)
	tests := []struct {
		name          string
		count         int
		wantFileNames []string
		wantErr       bool
	}{
		{"/assets/css/main.css", -1, nil, true},
		{"/assets", -1, []string{"css", "js", "txt"}, false},
		{"/assets/css", -1, []string{"main.css", "noscript.css"}, false},
		{"/assets/js", 4, []string{"main.js", "jquery.min.js", "browser.min.js", "breakpoints.min.js"}, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%d:uselocal=%t", tt.name, tt.count, useLocal), func(t *testing.T) {
			f, err := fs.Open(tt.name)
			if err != nil {
				t.Errorf("%q. _escFile.Open() error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}

			got, err := f.Readdir(tt.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("%q. _escFile.Readdir() error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				// because all check after only for case when fs.Open return non-err
				return
			}
			fnames := make([]string, 0, len(got))
			for i := range got {
				fnames = append(fnames, got[i].Name())
			}
			sort.Strings(fnames)
			sort.Strings(tt.wantFileNames)

			if tt.count > -1 {
				//workaround for case when we have limit, because of different Readdir cannot return in the same order, and nobody garanty ordering for Readdir
				if len(fnames) != len(tt.wantFileNames) {
					t.Errorf("%q. _escLocalFS.Readdir() return different counts of res = %d, want %d", tt.name, len(fnames), len(tt.wantFileNames))
				}
				return
			}

			if !reflect.DeepEqual(fnames, tt.wantFileNames) {
				t.Errorf("%q. _escLocalFS.Readdir() = %#v, want %#v", tt.name, fnames, tt.wantFileNames)
			}
		})
	}
}

func TestFSMustString_escStatic(t *testing.T) {
	testFSMustString(false, t)
}

func TestFSMustString_escLocal(t *testing.T) {
	testFSMustString(true, t)
}

func testFSMustString(useLocal bool, t *testing.T) {
	tests := []struct {
		name string
	}{
		{"/assets/txt/1.txt"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:uselocal=%t", tt.name, useLocal), func(t *testing.T) {

			raw, _ := ioutil.ReadFile("../testdata" + tt.name)
			got := FSMustString(useLocal, tt.name)
			if strings.Compare(got, string(raw)) != 0 {
				t.Errorf("%q. FSMustString() = %s, want %s", tt.name, got, raw)
			}

			got2, err := FSString(useLocal, tt.name)
			if err != nil {
				t.Errorf("%q. FSString() error = %v, but we should not return error here", tt.name, err)
				return
			}

			if strings.Compare(got, got2) != 0 {
				t.Errorf("%q. FSString() must return the same as FSMustString, given = %v, must be = %v", tt.name, got2, got)
			}

		})
	}
}
