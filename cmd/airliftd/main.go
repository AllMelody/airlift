// Command airliftd is a small file-upload/sharing server: it accepts uploads
// (web UI and the lift CLI), stores them on disk, and serves them back under a
// short ID. It is a stdlib-only rewrite of the original gas-framework server;
// the on-disk layout, config file, and HTTP API are kept compatible.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ktkr.us/pkg/airlift/cache"
	"ktkr.us/pkg/airlift/config"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "devel"

const appDirName = ".airliftd"

var fileCache *cache.Cache

func main() {
	var (
		flagPort    = flag.Int("p", -1, "Override the configured port")
		flagVersion = flag.Bool("v", false, "Print version and exit")
		flagSetpass = flag.Bool("setpass", false, "Set the admin password and exit (reads $AIRLIFT_PASSWORD or stdin)")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("airlift server %s (%s)\n", version, runtime.Version())
		return
	}

	log.Println("this is airlift server", version)

	// appDir holds the config, session key, and uploads. It defaults to
	// ~/.airliftd but can be overridden with AIRLIFT_HOME (useful for running
	// multiple instances, or for tests, without touching the real home).
	appDir := os.Getenv("AIRLIFT_HOME")
	if appDir == "" {
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		appDir = filepath.Join(u.HomeDir, appDirName)
	}
	if err := os.MkdirAll(appDir, 0700); err != nil {
		log.Fatal(err)
	}

	config.Default = config.Config{
		Port:      60606,
		HashLen:   4,
		Directory: filepath.Join(appDir, "uploads"),
	}
	if err := config.Init(filepath.Join(appDir, "config")); err != nil {
		log.Fatal(err)
	}

	if *flagSetpass {
		if err := setPassword(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("password updated")
		return
	}

	if err := initSessionKey(filepath.Join(appDir, "session.key")); err != nil {
		log.Fatal("session key:", err)
	}

	conf := config.Get()
	var err error
	fileCache, err = cache.New(conf.Directory)
	if err != nil {
		log.Fatalln("file cache:", err)
	}
	config.OnSave = func(c *config.Config) { fileCache.SetDir(c.Directory) }

	parseTemplates()

	go fileCache.WatchAges(config.Get())
	go reloadOnSIGHUP()

	if !conf.HasPassword() {
		log.Print("WARNING: no admin password configured — all routes refuse until you run: airliftd -setpass")
	}

	port := conf.Port
	if *flagPort > 0 {
		port = *flagPort
	}
	addr := os.Getenv("AIRLIFT_LISTEN")
	if addr == "" {
		addr = ":" + strconv.Itoa(port)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           logRequests(routes()),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout/WriteTimeout are intentionally unset so large uploads
		// and downloads are not cut off mid-transfer; ReadHeaderTimeout still
		// defeats slow-header (slowloris) attacks.
	}
	log.Printf("listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /-/static/", staticHandler())

	mux.HandleFunc("GET /-/login", getLogin)
	mux.HandleFunc("POST /-/login", postLogin)
	mux.HandleFunc("GET /-/logout", getLogout)

	mux.HandleFunc("GET /-/config", requireLogin(getConfig))
	mux.HandleFunc("POST /-/config", requireLogin(postConfig))
	mux.HandleFunc("GET /-/config/overview", requireLogin(getConfigOverview))
	mux.HandleFunc("POST /-/config/size", requireLogin(sizeLimitPrune))
	mux.HandleFunc("POST /-/config/age", requireLogin(ageLimitPrune))

	mux.HandleFunc("GET /-/history", requireLogin(getHistory))
	mux.HandleFunc("GET /-/history/{page}", requireLogin(getHistoryPage))
	mux.HandleFunc("POST /-/delete/{id}", requireLogin(deleteFile))
	mux.HandleFunc("POST /purge/all", requireLogin(purgeAll))

	mux.HandleFunc("POST /upload/web", requireLogin(doUpload))
	mux.HandleFunc("POST /upload/file", requirePassword(doUpload))
	mux.HandleFunc("POST /oops", requirePassword(oops))
	mux.HandleFunc("GET /-/l", requirePassword(getList))
	mux.HandleFunc("DELETE /{id}", requirePassword(deleteFile))

	mux.HandleFunc("GET /{id}/{filename}", getFile)
	mux.HandleFunc("GET /{id}", getFile)
	mux.HandleFunc("GET /{$}", getIndex)

	return mux
}

// logRequests is a minimal access log.
func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		remote := r.Header.Get("X-Forwarded-For")
		if remote == "" {
			remote = r.RemoteAddr
		}
		h.ServeHTTP(w, r)
		log.Printf("%15s %s %s (%v)", remote, r.Method, r.URL.Path, time.Since(start))
	})
}

func reloadOnSIGHUP() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		log.Print("reloading config...")
		if err := config.Reload(); err != nil {
			log.Print(err)
		} else {
			log.Print("reloaded config")
		}
	}
}

func setPassword() error {
	conf := config.Get()
	pass := os.Getenv("AIRLIFT_PASSWORD")
	if pass == "" {
		fmt.Print("New password: ")
		s := bufio.NewScanner(os.Stdin)
		if !s.Scan() {
			return fmt.Errorf("no password provided")
		}
		pass = strings.TrimRight(s.Text(), "\r\n")
	}
	if pass == "" {
		return fmt.Errorf("refusing to set an empty password")
	}
	if err := conf.SetPass(pass); err != nil {
		return err
	}
	return config.Set(conf)
}
