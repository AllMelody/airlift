package main

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ktkr.us/pkg/airlift/config"
	"ktkr.us/pkg/airlift/contentdisposition"
)

// maxUpload caps a single upload to guard against a client filling the disk
// before the size-based pruning runs. Adjust if you routinely serve larger
// files.
const maxUpload int64 = 2 << 30 // 2 GiB

// resp is the JSON body returned by the API endpoints.
type resp struct {
	URL string `json:",omitempty"`
	Err string `json:",omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fileID extracts the cache id from a path value, dropping any trailing
// extension (e.g. "abcd.txt" -> "abcd").
func fileID(s string) string {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i]
	}
	return s
}

func host(r *http.Request) string {
	if h := config.Get().Host; h != "" {
		return h
	}
	return r.Host
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	if loggedIn(r) {
		render(w, 200, "index/layout-full", page(nil))
		return
	}
	render(w, 200, "default-index/layout-lite", page(nil))
}

func getFile(w http.ResponseWriter, r *http.Request) {
	id := fileID(r.PathValue("id"))
	file := fileCache.Get(id)
	if file == "" {
		http.Error(w, "ID not found", http.StatusNotFound)
		return
	}

	// When the URL carries no explicit filename, advertise the original
	// upload name via Content-Disposition.
	if r.PathValue("filename") == "" {
		contentdisposition.SetFilename(w, displayName(filepath.Base(file)))
	}

	w.Header().Set("Expires", time.Now().Add(threeMonths).Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "public")
	http.ServeFile(w, r, file)
}

func doUpload(w http.ResponseWriter, r *http.Request) {
	conf := config.Get()

	filename, err := url.QueryUnescape(r.Header.Get("X-Airlift-Filename"))
	if err != nil {
		writeJSON(w, 400, resp{Err: "bad format in filename header: " + err.Error()})
		return
	}
	// Strip directory components: an attacker-controlled filename must never
	// escape the uploads directory. (cache.Put re-checks defensively.)
	filename = filepath.Base(filename)
	if filename == "" || filename == "." || filename == ".." || filename == string(filepath.Separator) {
		writeJSON(w, 400, resp{Err: "missing or invalid filename header"})
		return
	}
	defer r.Body.Close()

	body := http.MaxBytesReader(w, r.Body, maxUpload)
	hash, err := fileCache.Put(body, filename, conf)
	if err != nil {
		log.Println("upload:", err)
		writeJSON(w, 500, resp{Err: err.Error()})
		return
	}

	if conf.AppendExt {
		hash += filepath.Ext(filename)
	}
	writeJSON(w, 201, resp{URL: path.Join(host(r), hash)})
}

func oops(w http.ResponseWriter, r *http.Request) {
	pruned, err := fileCache.RemoveNewest()
	if err != nil {
		log.Println("oops:", err)
		writeJSON(w, 500, resp{Err: err.Error()})
		return
	}
	writeJSON(w, 200, resp{URL: path.Join(host(r), pruned)})
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	id := fileID(r.PathValue("id"))
	if id == "" {
		writeJSON(w, 400, resp{Err: "file ID not specified"})
		return
	}
	if fileCache.Get(id) == "" {
		writeJSON(w, 404, resp{Err: "ID not found"})
		return
	}
	if err := fileCache.Remove(id); err != nil {
		log.Println("delete:", err)
		writeJSON(w, 500, resp{Err: err.Error()})
		return
	}
	w.WriteHeader(204)
}

func getList(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.FormValue("limit"))
	if err != nil {
		limit = 10
	}
	writeJSON(w, 200, getSortedList(0, limit))
}

const itemsPerPage = 50

type historyPage struct {
	List        []*File
	CurrentPage int
	NextPage    int
	PrevPage    int
	TotalPages  int
	AppendExt   bool
}

func getHistory(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/-/history/1", http.StatusSeeOther)
}

func getHistoryPage(w http.ResponseWriter, r *http.Request) {
	page1, err := strconv.Atoi(r.PathValue("page"))
	if err != nil || page1 < 1 {
		http.Redirect(w, r, "/-/history/1", http.StatusSeeOther)
		return
	}

	l := fileCache.Len()
	offset := (page1 - 1) * itemsPerPage
	if offset > l {
		http.Redirect(w, r, "/-/history/1", http.StatusSeeOther)
		return
	}
	limit := itemsPerPage
	if l < offset+limit {
		limit = l - offset
	}

	conf := config.Get()
	totalPages := int(math.Ceil(float64(l) / float64(itemsPerPage)))
	if totalPages == 0 {
		totalPages = 1
	}

	p := &historyPage{
		List:        getSortedList(offset, limit),
		CurrentPage: page1,
		TotalPages:  totalPages,
		AppendExt:   conf.AppendExt,
	}
	if page1 > 1 {
		p.PrevPage = page1 - 1
	}
	if l > offset+limit {
		p.NextPage = page1 + 1
	}

	render(w, 200, "history/layout-full", page(p))
}

func purgeAll(w http.ResponseWriter, r *http.Request) {
	if err := fileCache.RemoveAll(); err != nil {
		writeJSON(w, 500, resp{Err: err.Error()})
		return
	}
	w.WriteHeader(204)
}

// --- config ---------------------------------------------------------------

type overview struct {
	NumUploads  int
	UploadsSize byteSize
}

func overviewData() overview {
	return overview{
		NumUploads:  fileCache.Len(),
		UploadsSize: byteSize(fileCache.Size()),
	}
}

func getConfig(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Conf *config.Config
		overview
	}{config.Get(), overviewData()}
	render(w, 200, "config/layout-full", page(&data))
}

func getConfigOverview(w http.ResponseWriter, r *http.Request) {
	data := overviewData()
	render(w, 200, "config/%overview", page(&data))
}

func postConfig(w http.ResponseWriter, r *http.Request) {
	conf := config.Get()

	newpass := r.FormValue("newpass")
	if newpass != r.FormValue("newpass-confirm") {
		writeJSON(w, 400, resp{Err: "passwords do not match"})
		return
	}
	if newpass != "" {
		if err := conf.SetPass(newpass); err != nil {
			writeJSON(w, 500, resp{Err: err.Error()})
			return
		}
	}

	conf.Host = strings.TrimSpace(r.FormValue("host"))
	conf.Directory = filepath.Clean(r.FormValue("directory"))
	conf.AppendExt = formBool(r, "append-ext")
	conf.MaxAgeEnable = formBool(r, "enable-age-prune")
	conf.MaxSizeEnable = formBool(r, "enable-size-prune")
	conf.Age = formInt(r, "max-age", conf.Age)
	conf.Size = int64(formInt(r, "max-size", int(conf.Size)))

	conf.HashLen = formInt(r, "id-size", conf.HashLen)
	if conf.HashLen < 1 {
		conf.HashLen = 1
	} else if conf.HashLen > 64 {
		conf.HashLen = 64
	}

	if err := config.Set(conf); err != nil {
		log.Println("postConfig:", err)
		writeJSON(w, 500, resp{Err: err.Error()})
		return
	}

	if conf.MaxSizeEnable {
		if _, err := fileCache.CutToSize(conf.Size * 1024 * 1024); err != nil {
			log.Print(err)
		}
	}
	if conf.MaxAgeEnable {
		cutoff := time.Now().Add(-time.Duration(conf.Age) * 24 * time.Hour)
		if _, err := fileCache.RemoveOlderThan(cutoff); err != nil {
			log.Print(err)
		}
	}
	w.WriteHeader(204)
}

func sizeLimitPrune(w http.ResponseWriter, r *http.Request) {
	n := formInt(r, "N", 0)
	m := fileCache.MaybeCutToSize(int64(n) * 1024 * 1024)
	writeJSON(w, 200, struct{ N int }{m})
}

func ageLimitPrune(w http.ResponseWriter, r *http.Request) {
	n := formInt(r, "N", 0)
	t := time.Now().Add(-time.Duration(n) * 24 * time.Hour)
	m := fileCache.MaybeRemoveOlderThan(t)
	writeJSON(w, 200, struct{ N int }{m})
}

// --- auth pages ------------------------------------------------------------

type loginData struct {
	Failed bool
	Return string
}

func sanitizeReturn(s string) string {
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return s
	}
	return "/"
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	if loggedIn(r) {
		http.Redirect(w, r, sanitizeReturn(r.FormValue("return")), http.StatusSeeOther)
		return
	}
	render(w, 200, "login/layout-lite", raw(loginData{Return: sanitizeReturn(r.FormValue("return"))}))
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if config.Get().VerifyPass(r.FormValue("pass")) {
		signIn(w, r)
		http.Redirect(w, r, sanitizeReturn(r.FormValue("return")), http.StatusSeeOther)
		return
	}
	render(w, 200, "login/layout-lite", raw(loginData{Failed: true, Return: sanitizeReturn(r.FormValue("return"))}))
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	signOut(w, r)
	http.Redirect(w, r, "/-/login", http.StatusSeeOther)
}

func formBool(r *http.Request, key string) bool { return r.FormValue(key) != "" }

func formInt(r *http.Request, key string, def int) int {
	if n, err := strconv.Atoi(r.FormValue(key)); err == nil {
		return n
	}
	return def
}
