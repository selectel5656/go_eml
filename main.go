package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

//go:embed web/templates/*.html
var templateFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

var staticFiles fs.FS

var (
	templates = map[string]*template.Template{}
	loginTmpl *template.Template
	db        *sql.DB
)

func init() {
	pages := []string{"dashboard", "emails", "macros", "attachments", "api-rules", "proxies", "accounts", "settings"}
	for _, p := range pages {
		templates[p] = template.Must(template.ParseFS(templateFS, "web/templates/layout.html", "web/templates/"+p+".html"))
	}
	loginTmpl = template.Must(template.ParseFS(templateFS, "web/templates/login.html"))

	staticFiles, _ = fs.Sub(staticFS, "web/static")
	rand.Seed(time.Now().UnixNano())
}

type App struct {
	Domain    string
	UserAgent string
	AdminPass string
	TestEmail string
	TestEvery int
	TotalSent int

	Emails      []EmailEntry
	Macros      []Macro
	Attachments []Attachment
	Proxies     []Proxy
	Accounts    []Account
	APIRules    string

	SendPerAccount int
	CycleAccounts  bool
	CurrentAccount int

	Threads int
	Sending bool
	Stop    bool

	LastLog string
}

var app = &App{
	Domain:         "domen.ru",
	UserAgent:      "MyUserAgent",
	AdminPass:      "admin",
	SendPerAccount: 1,
	CycleAccounts:  true,
	Threads:        1,
	TestEvery:      0,
}

var (
	accountMu sync.Mutex
	emailMu   sync.Mutex
	proxyMu   sync.Mutex
)

type EmailEntry struct {
	Name       string
	Email      string
	Sent       bool
	Processing bool
}

type Attachment struct {
	Name        string
	Macro       string
	Path        string
	Inline      bool
	InlineMacro string
	Mime        string
}

type Macro struct {
	Name       string
	Type       string
	Counter    int
	Step       int
	Chars      string
	Min        int
	Max        int
	Every      int
	Used       int
	Last       string
	Values     []string
	Sequential bool
	Index      int
}

type Proxy struct {
	Address string
	Alive   bool
	Used    bool
}

type Account struct {
	Login     string
	Password  string
	FirstName string
	LastName  string
	APIKey    string
	UUID      string
	Sent      int
	Proxy     string
	InUse     bool
}

func initDB() {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		dsn = "root:password@tcp(127.0.0.1:3306)/go_eml?parseTime=true"
	}
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS settings (key VARCHAR(255) PRIMARY KEY, value TEXT)`,
		`CREATE TABLE IF NOT EXISTS emails (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255), sent TINYINT(1))`,
		`CREATE TABLE IF NOT EXISTS macros (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), type VARCHAR(50), counter INT, step INT, chars TEXT, min INT, max INT, every INT, used INT, last TEXT, values TEXT, sequential TINYINT(1), idx INT)`,
		`CREATE TABLE IF NOT EXISTS attachments (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), macro VARCHAR(255), path TEXT, inline TINYINT(1), inline_macro VARCHAR(255), mime VARCHAR(100))`,
		`CREATE TABLE IF NOT EXISTS proxies (address VARCHAR(255) PRIMARY KEY, alive TINYINT(1), used TINYINT(1))`,
		`CREATE TABLE IF NOT EXISTS accounts (login VARCHAR(255) PRIMARY KEY, password VARCHAR(255), first_name VARCHAR(255), last_name VARCHAR(255), api_key TEXT, uuid VARCHAR(255), sent INT, proxy VARCHAR(255))`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			panic(err)
		}
	}
	loadSettings()
	loadEmails()
	loadMacros()
	loadAttachments()
	loadProxies()
	loadAccounts()
}

func loadSettings() {
	rows, err := db.Query("SELECT key, value FROM settings")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		switch k {
		case "domain":
			app.Domain = v
		case "user_agent":
			app.UserAgent = v
		case "admin_pass":
			app.AdminPass = v
		case "send_per_account":
			if n, err := strconv.Atoi(v); err == nil {
				app.SendPerAccount = n
			}
		case "cycle_accounts":
			app.CycleAccounts = v == "1"
		case "threads":
			if n, err := strconv.Atoi(v); err == nil {
				app.Threads = n
			}
		case "api_rules":
			app.APIRules = v
		case "test_email":
			app.TestEmail = v
		case "test_every":
			if n, err := strconv.Atoi(v); err == nil {
				app.TestEvery = n
			}
		case "total_sent":
			if n, err := strconv.Atoi(v); err == nil {
				app.TotalSent = n
			}
		}
	}
	if app.AdminPass == "" {
		app.AdminPass = "admin"
	}
}

func saveSetting(k, v string) {
	db.Exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, v)
}

func saveSettings() {
	saveSetting("domain", app.Domain)
	saveSetting("user_agent", app.UserAgent)
	saveSetting("admin_pass", app.AdminPass)
	saveSetting("send_per_account", strconv.Itoa(app.SendPerAccount))
	if app.CycleAccounts {
		saveSetting("cycle_accounts", "1")
	} else {
		saveSetting("cycle_accounts", "0")
	}
	saveSetting("threads", strconv.Itoa(app.Threads))
	saveSetting("api_rules", app.APIRules)
	saveSetting("test_email", app.TestEmail)
	saveSetting("test_every", strconv.Itoa(app.TestEvery))
	saveSetting("total_sent", strconv.Itoa(app.TotalSent))
}

func loadEmails() {
	rows, err := db.Query("SELECT name,email,sent FROM emails")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e EmailEntry
		var sent int
		rows.Scan(&e.Name, &e.Email, &sent)
		e.Sent = sent == 1
		app.Emails = append(app.Emails, e)
	}
}

func loadMacros() {
	rows, err := db.Query("SELECT name,type,counter,step,chars,min,max,every,used,last,values,sequential,idx FROM macros")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var m Macro
		var values string
		var seq, idx int
		rows.Scan(&m.Name, &m.Type, &m.Counter, &m.Step, &m.Chars, &m.Min, &m.Max, &m.Every, &m.Used, &m.Last, &values, &seq, &idx)
		json.Unmarshal([]byte(values), &m.Values)
		m.Sequential = seq == 1
		m.Index = idx
		app.Macros = append(app.Macros, m)
	}
}

func loadAttachments() {
	rows, err := db.Query("SELECT name,macro,path,inline,inline_macro,mime FROM attachments")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var att Attachment
		var inline int
		rows.Scan(&att.Name, &att.Macro, &att.Path, &inline, &att.InlineMacro, &att.Mime)
		att.Inline = inline == 1
		app.Attachments = append(app.Attachments, att)
	}
}

func loadProxies() {
	rows, err := db.Query("SELECT address,alive,used FROM proxies")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var p Proxy
		var alive, used int
		rows.Scan(&p.Address, &alive, &used)
		p.Alive = alive == 1
		p.Used = used == 1
		app.Proxies = append(app.Proxies, p)
	}
}

func loadAccounts() {
	rows, err := db.Query("SELECT login,password,first_name,last_name,api_key,uuid,sent,proxy FROM accounts")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var a Account
		rows.Scan(&a.Login, &a.Password, &a.FirstName, &a.LastName, &a.APIKey, &a.UUID, &a.Sent, &a.Proxy)
		app.Accounts = append(app.Accounts, a)
	}
}

func checkProxy(addr string) bool {
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		return false
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func getProxy() string {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	for i := range app.Proxies {
		if app.Proxies[i].Alive && !app.Proxies[i].Used {
			app.Proxies[i].Used = true
			db.Exec("UPDATE proxies SET used=1 WHERE address=?", app.Proxies[i].Address)
			return app.Proxies[i].Address
		}
	}
	for i := range app.Proxies {
		app.Proxies[i].Used = false
		db.Exec("UPDATE proxies SET used=0 WHERE address=?", app.Proxies[i].Address)
	}
	for i := range app.Proxies {
		if app.Proxies[i].Alive {
			app.Proxies[i].Used = true
			db.Exec("UPDATE proxies SET used=1 WHERE address=?", app.Proxies[i].Address)
			return app.Proxies[i].Address
		}
	}
	return ""
}

func doLoggedRequest(log *strings.Builder, req *http.Request, body []byte, proxy string) (int, []byte, error) {
	log.WriteString(fmt.Sprintf("%s %s\n", req.Method, req.URL.String()))
	for k, v := range req.Header {
		log.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ",")))
	}
	if len(body) > 0 {
		log.WriteString("Body:\n" + string(body) + "\n")
	}
	tr := &http.Transport{}
	if proxy != "" {
		if purl, err := url.Parse("http://" + proxy); err == nil {
			tr.Proxy = http.ProxyURL(purl)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.WriteString("Error: " + err.Error() + "\n")
		return 0, nil, err
	}
	defer resp.Body.Close()

	reader := resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		if gr, err := gzip.NewReader(resp.Body); err == nil {
			defer gr.Close()
			reader = gr
		}
	case "deflate":
		if zr, err := zlib.NewReader(resp.Body); err == nil {
			defer zr.Close()
			reader = zr
		}
	}

	respBody, _ := io.ReadAll(reader)
	log.WriteString(fmt.Sprintf("Response %d\n%s\n", resp.StatusCode, string(respBody)))
	return resp.StatusCode, respBody, nil
}

func cloneRequest(req *http.Request, body []byte) *http.Request {
	r := req.Clone(context.Background())
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return r
}

func doAccountRequest(acc *Account, log *strings.Builder, req *http.Request, body []byte) (int, []byte, error) {
	for i := 0; i < 3; i++ {
		r := cloneRequest(req, body)
		status, resp, err := doLoggedRequest(log, r, body, acc.Proxy)
		if err == nil {
			return status, resp, nil
		}
		log.WriteString("proxy failed, switching\n")
		acc.Proxy = getProxy()
		db.Exec("UPDATE accounts SET proxy=? WHERE login=?", acc.Proxy, acc.Login)
		if acc.Proxy == "" {
			break
		}
	}
	return 0, nil, fmt.Errorf("proxy error")
}

func main() {
	initDB()
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/dashboard", requireAuth(handleDashboard))
	http.HandleFunc("/send", requireAuth(handleSend))
	http.HandleFunc("/send/stop", requireAuth(handleSendStop))
	http.HandleFunc("/emails", requireAuth(handleEmails))
	http.HandleFunc("/emails/add", requireAuth(handleEmailsAdd))
	http.HandleFunc("/emails/upload", requireAuth(handleEmailsUpload))
	http.HandleFunc("/emails/delete", requireAuth(handleEmailsDelete))
	http.HandleFunc("/emails/reset", requireAuth(handleEmailsReset))
	http.HandleFunc("/macros", requireAuth(handleMacros))
	http.HandleFunc("/macros/add", requireAuth(handleMacrosAdd))
	http.HandleFunc("/macros/delete", requireAuth(handleMacrosDelete))
	http.HandleFunc("/attachments", requireAuth(handleAttachments))
	http.HandleFunc("/attachments/add", requireAuth(handleAttachmentsAdd))
	http.HandleFunc("/attachments/delete", requireAuth(handleAttachmentsDelete))
	http.HandleFunc("/proxies", requireAuth(handleProxies))
	http.HandleFunc("/proxies/add", requireAuth(handleProxiesAdd))
	http.HandleFunc("/proxies/upload", requireAuth(handleProxiesUpload))
	http.HandleFunc("/proxies/delete", requireAuth(handleProxiesDelete))
	http.HandleFunc("/accounts", requireAuth(handleAccounts))
	http.HandleFunc("/accounts/add", requireAuth(handleAccountsAdd))
	http.HandleFunc("/accounts/upload", requireAuth(handleAccountsUpload))
	http.HandleFunc("/accounts/delete", requireAuth(handleAccountsDelete))
	http.HandleFunc("/accounts/reset", requireAuth(handleAccountsReset))
	http.HandleFunc("/api-rules", requireAuth(handleAPIRules))
	http.HandleFunc("/api-rules/save", requireAuth(handleAPIRulesSave))
	http.HandleFunc("/settings", requireAuth(handleSettings))
	http.HandleFunc("/settings/save", requireAuth(handleSettingsSave))

	http.ListenAndServe(":8080", nil)
}

func render(w http.ResponseWriter, name string, data any) {
	if t, ok := templates[name]; ok {
		t.ExecuteTemplate(w, "layout", data)
		return
	}
	http.Error(w, "template not found", http.StatusInternalServerError)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if user == "admin" && pass == app.AdminPass {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "1", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		loginTmpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": "Неверные данные"})
		return
	}
	loginTmpl.ExecuteTemplate(w, "login.html", nil)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func requireAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || c.Value != "1" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fn(w, r)
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":       "Письмо",
		"Attachments": app.Attachments,
		"Log":         app.LastLog,
		"Sending":     app.Sending,
	}
	if msg := r.URL.Query().Get("msg"); msg != "" {
		data["Message"] = msg
	}
	if errMsg := r.URL.Query().Get("err"); errMsg != "" {
		data["Error"] = errMsg
	}
	render(w, "dashboard", data)
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	if app.Sending {
		http.Redirect(w, r, "/dashboard?err="+url.QueryEscape("Уже выполняется отправка"), http.StatusFound)
		return
	}
	subject := r.FormValue("subject")
	body := r.FormValue("body")
	rcount := 1
	if v := r.FormValue("rcount"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			rcount = n
		}
	}
	rmethod := r.FormValue("rmethod")
	if rmethod == "" {
		rmethod = "to"
	}
	firstSep := r.FormValue("firstsep") == "on"
	var atts []Attachment
	for _, v := range r.Form["attach"] {
		if i, err := strconv.Atoi(v); err == nil {
			if i >= 0 && i < len(app.Attachments) {
				atts = append(atts, app.Attachments[i])
			}
		}
	}
	app.Stop = false
	app.Sending = true
	go massSend(subject, body, atts, rcount, rmethod, firstSep)
	http.Redirect(w, r, "/dashboard?msg="+url.QueryEscape("Отправка запущена"), http.StatusFound)
}

func handleSendStop(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		app.Stop = true
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func nextBatch(rcount int) []int {
	emailMu.Lock()
	defer emailMu.Unlock()
	idxs := []int{}
	for i := range app.Emails {
		if !app.Emails[i].Sent && !app.Emails[i].Processing {
			app.Emails[i].Processing = true
			idxs = append(idxs, i)
			if len(idxs) == rcount {
				break
			}
		}
	}
	return idxs
}

func worker(subject, body string, atts []Attachment, rcount int, method string, firstSep bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		if app.Stop {
			return
		}
		idxs := nextBatch(rcount)
		if len(idxs) == 0 {
			return
		}
		emailMu.Lock()
		batch := make([]EmailEntry, len(idxs))
		for i, idx := range idxs {
			batch[i] = app.Emails[idx]
		}
		emailMu.Unlock()
		logs, err := sendEmail(subject, body, atts, batch, method, firstSep)
		emailMu.Lock()
		app.LastLog = logs
		if err == nil {
			for _, idx := range idxs {
				app.Emails[idx].Sent = true
				app.Emails[idx].Processing = false
				db.Exec("UPDATE emails SET sent=1 WHERE email=?", app.Emails[idx].Email)
			}
			app.TotalSent++
			saveSetting("total_sent", strconv.Itoa(app.TotalSent))
			if app.TestEvery > 0 && app.TestEmail != "" && app.TotalSent%app.TestEvery == 0 {
				testRecipient := []EmailEntry{{Name: "test", Email: app.TestEmail}}
				logs, _ := sendEmail(subject, body, atts, testRecipient, "to", false)
				app.LastLog += "\n--- test ---\n" + logs
			}
		} else {
			for _, idx := range idxs {
				app.Emails[idx].Processing = false
			}
		}
		emailMu.Unlock()
	}
}

func massSend(subject, body string, atts []Attachment, rcount int, method string, firstSep bool) {
	var wg sync.WaitGroup
	for i := 0; i < app.Threads; i++ {
		wg.Add(1)
		go worker(subject, body, atts, rcount, method, firstSep, &wg)
	}
	wg.Wait()
	app.Sending = false
}

func handleEmails(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":  "База e-mail",
		"Emails": app.Emails,
	}
	render(w, "emails", data)
}

func handleEmailsAdd(w http.ResponseWriter, r *http.Request) {
	if e, ok := parseEmail(r.FormValue("email")); ok {
		app.Emails = append(app.Emails, e)
		db.Exec("INSERT INTO emails(name,email,sent) VALUES(?,?,0)", e.Name, e.Email)
	}
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleEmailsUpload(w http.ResponseWriter, r *http.Request) {
	format := r.FormValue("format")
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if e, ok := parseEmailFormat(scanner.Text(), format); ok {
				app.Emails = append(app.Emails, e)
				db.Exec("INSERT INTO emails(name,email,sent) VALUES(?,?,0)", e.Name, e.Email)
			}
		}
	}
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleEmailsDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Emails) {
			db.Exec("DELETE FROM emails WHERE email=?", app.Emails[i].Email)
			app.Emails = append(app.Emails[:i], app.Emails[i+1:]...)
		}
	}
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleEmailsReset(w http.ResponseWriter, r *http.Request) {
	for i := range app.Emails {
		app.Emails[i].Sent = false
		app.Emails[i].Processing = false
	}
	db.Exec("UPDATE emails SET sent=0")
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleMacros(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Макросы", "Macros": app.Macros}
	render(w, "macros", data)
}

func handleMacrosAdd(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	mtype := r.FormValue("type")
	if name == "" || mtype == "" {
		http.Redirect(w, r, "/macros", http.StatusFound)
		return
	}
	mac := Macro{Name: name, Type: mtype, Every: 1}
	if v := r.FormValue("every"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			mac.Every = n
		}
	}
	switch mtype {
	case "counter":
		start, _ := strconv.Atoi(r.FormValue("start"))
		step, _ := strconv.Atoi(r.FormValue("step"))
		if step == 0 {
			step = 1
		}
		mac.Counter = start
		mac.Step = step
		mac.Last = strconv.Itoa(start)
	case "random":
		mac.Chars = r.FormValue("chars")
		mac.Min, _ = strconv.Atoi(r.FormValue("min"))
		mac.Max, _ = strconv.Atoi(r.FormValue("max"))
		if mac.Min <= 0 {
			mac.Min = 1
		}
		if mac.Max < mac.Min {
			mac.Max = mac.Min
		}
	case "list":
		seq := r.FormValue("seq") == "on"
		file, _, err := r.FormFile("file")
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				mac.Values = append(mac.Values, scanner.Text())
			}
		}
		mac.Sequential = seq
	}
	app.Macros = append(app.Macros, mac)
	vals, _ := json.Marshal(mac.Values)
	seq := 0
	if mac.Sequential {
		seq = 1
	}
	db.Exec("INSERT INTO macros(name,type,counter,step,chars,min,max,every,used,last,values,sequential,idx) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
		mac.Name, mac.Type, mac.Counter, mac.Step, mac.Chars, mac.Min, mac.Max, mac.Every, mac.Used, mac.Last, string(vals), seq, mac.Index)
	http.Redirect(w, r, "/macros", http.StatusFound)
}

func handleMacrosDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Macros) {
			db.Exec("DELETE FROM macros WHERE name=?", app.Macros[i].Name)
			app.Macros = append(app.Macros[:i], app.Macros[i+1:]...)
		}
	}
	http.Redirect(w, r, "/macros", http.StatusFound)
}

func handleAttachments(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Аттачи", "Attachments": app.Attachments}
	render(w, "attachments", data)
}

func handleAttachmentsAdd(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		data, _ := io.ReadAll(file)
		os.MkdirAll("uploads", 0755)
		id := len(app.Attachments) + 1
		filename := fmt.Sprintf("%d_%s", id, header.Filename)
		path := "uploads/" + filename
		os.WriteFile(path, data, 0644)
		macro := fmt.Sprintf("{{$attach_%d}}", id)
		inline := r.FormValue("inline") == "on"
		ext := strings.ToLower(filepath.Ext(header.Filename))
		mime := ""
		switch ext {
		case ".png":
			mime = "image/png"
		case ".jpg", ".jpeg":
			mime = "image/jpeg"
		case ".gif":
			mime = "image/gif"
		}
		att := Attachment{Name: header.Filename, Macro: macro, Path: path}
		if inline && mime != "" {
			att.Inline = true
			att.Mime = mime
			att.InlineMacro = fmt.Sprintf("{{$attach_img_%d_base64}}", id)
		}
		app.Attachments = append(app.Attachments, att)
		in := 0
		if att.Inline {
			in = 1
		}
		db.Exec("INSERT INTO attachments(name,macro,path,inline,inline_macro,mime) VALUES(?,?,?,?,?,?)", att.Name, att.Macro, att.Path, in, att.InlineMacro, att.Mime)
	}
	http.Redirect(w, r, "/attachments", http.StatusFound)
}

func handleAttachmentsDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Attachments) {
			os.Remove(app.Attachments[i].Path)
			db.Exec("DELETE FROM attachments WHERE macro=?", app.Attachments[i].Macro)
			app.Attachments = append(app.Attachments[:i], app.Attachments[i+1:]...)
		}
	}
	http.Redirect(w, r, "/attachments", http.StatusFound)
}

func handleProxies(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Прокси", "Proxies": app.Proxies}
	render(w, "proxies", data)
}

func handleProxiesAdd(w http.ResponseWriter, r *http.Request) {
	if p := r.FormValue("proxy"); p != "" {
		alive := checkProxy(p)
		app.Proxies = append(app.Proxies, Proxy{Address: p, Alive: alive})
		a := 0
		if alive {
			a = 1
		}
		db.Exec("INSERT INTO proxies(address,alive,used) VALUES(?,?,0)", p, a)
	}
	http.Redirect(w, r, "/proxies", http.StatusFound)
}

func handleProxiesUpload(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				alive := checkProxy(line)
				app.Proxies = append(app.Proxies, Proxy{Address: line, Alive: alive})
				a := 0
				if alive {
					a = 1
				}
				db.Exec("INSERT INTO proxies(address,alive,used) VALUES(?,?,0)", line, a)
			}
		}
	}
	http.Redirect(w, r, "/proxies", http.StatusFound)
}

func handleProxiesDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Proxies) {
			db.Exec("DELETE FROM proxies WHERE address=?", app.Proxies[i].Address)
			app.Proxies = append(app.Proxies[:i], app.Proxies[i+1:]...)
		}
	}
	http.Redirect(w, r, "/proxies", http.StatusFound)
}

func handleAccounts(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Аккаунты API", "Accounts": app.Accounts}
	render(w, "accounts", data)
}

func handleAccountsAdd(w http.ResponseWriter, r *http.Request) {
	if a, ok := parseAccount(r.FormValue("account")); ok {
		app.Accounts = append(app.Accounts, a)
		db.Exec("INSERT INTO accounts(login,password,first_name,last_name,api_key,uuid,sent,proxy) VALUES(?,?,?,?,?,?,?,?)", a.Login, a.Password, a.FirstName, a.LastName, a.APIKey, a.UUID, a.Sent, a.Proxy)
	}
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleAccountsUpload(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if a, ok := parseAccount(scanner.Text()); ok {
				app.Accounts = append(app.Accounts, a)
				db.Exec("INSERT INTO accounts(login,password,first_name,last_name,api_key,uuid,sent,proxy) VALUES(?,?,?,?,?,?,?,?)", a.Login, a.Password, a.FirstName, a.LastName, a.APIKey, a.UUID, a.Sent, a.Proxy)
			}
		}
	}
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleAccountsDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Accounts) {
			db.Exec("DELETE FROM accounts WHERE login=?", app.Accounts[i].Login)
			app.Accounts = append(app.Accounts[:i], app.Accounts[i+1:]...)
		}
	}
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleAccountsReset(w http.ResponseWriter, r *http.Request) {
	for i := range app.Accounts {
		app.Accounts[i].Sent = 0
	}
	app.CurrentAccount = 0
	db.Exec("UPDATE accounts SET sent=0")
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleAPIRules(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "API правила", "APIRules": app.APIRules}
	render(w, "api-rules", data)
}

func handleAPIRulesSave(w http.ResponseWriter, r *http.Request) {
	app.APIRules = r.FormValue("rules")
	saveSettings()
	http.Redirect(w, r, "/api-rules", http.StatusFound)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":          "Настройки",
		"Domain":         app.Domain,
		"UserAgent":      app.UserAgent,
		"SendPerAccount": app.SendPerAccount,
		"CycleAccounts":  app.CycleAccounts,
		"Threads":        app.Threads,
		"TestEmail":      app.TestEmail,
		"TestEvery":      app.TestEvery,
	}
	render(w, "settings", data)
}

func handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if d := r.FormValue("domain"); d != "" {
		app.Domain = d
	}
	if ua := r.FormValue("useragent"); ua != "" {
		app.UserAgent = ua
	}
	if n := r.FormValue("sendlimit"); n != "" {
		if v, err := strconv.Atoi(n); err == nil && v > 0 {
			app.SendPerAccount = v
		}
	}
	if t := r.FormValue("threads"); t != "" {
		if v, err := strconv.Atoi(t); err == nil && v > 0 {
			app.Threads = v
		}
	}
	if te := r.FormValue("testemail"); te != "" {
		app.TestEmail = te
	}
	if n := r.FormValue("testevery"); n != "" {
		if v, err := strconv.Atoi(n); err == nil && v > 0 {
			app.TestEvery = v
		} else {
			app.TestEvery = 0
		}
	}
	app.CycleAccounts = r.FormValue("cycle") == "on"
	if p := r.FormValue("password"); p != "" {
		app.AdminPass = p
	}
	saveSettings()
	data := map[string]any{
		"Title":          "Настройки",
		"Domain":         app.Domain,
		"UserAgent":      app.UserAgent,
		"SendPerAccount": app.SendPerAccount,
		"CycleAccounts":  app.CycleAccounts,
		"Threads":        app.Threads,
		"TestEmail":      app.TestEmail,
		"TestEvery":      app.TestEvery,
		"Message":        "Сохранено",
	}
	render(w, "settings", data)
}

func parseEmailFormat(line, format string) (EmailEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return EmailEntry{}, false
	}
	switch format {
	case "name_angle", "name_angle_semicolon":
		line = strings.TrimSuffix(line, ";")
		var name, email string
		if i := strings.Index(line, "<"); i >= 0 {
			if j := strings.Index(line, ">"); j > i {
				email = strings.TrimSpace(line[i+1 : j])
				name = strings.TrimSpace(line[:i])
			}
		}
		if email == "" {
			email = line
		}
		if name == "" {
			if at := strings.Index(email, "@"); at > 0 {
				name = email[:at]
			}
		}
		return EmailEntry{Name: name, Email: email}, true
	case "email":
		line = strings.TrimSuffix(line, ";")
		email := line
		name := email
		if at := strings.Index(email, "@"); at > 0 {
			name = email[:at]
		}
		return EmailEntry{Name: name, Email: email}, true
	default:
		return parseEmail(line)
	}
}

func parseEmail(line string) (EmailEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return EmailEntry{}, false
	}
	line = strings.TrimSuffix(line, ";")
	var name, email string
	if i := strings.Index(line, "<"); i >= 0 {
		if j := strings.Index(line, ">"); j > i {
			email = strings.TrimSpace(line[i+1 : j])
			name = strings.TrimSpace(line[:i])
		}
	}
	if email == "" {
		email = line
	}
	if name == "" {
		if at := strings.Index(email, "@"); at > 0 {
			name = email[:at]
		}
	}
	return EmailEntry{Name: name, Email: email}, true
}

func parseAccount(line string) (Account, bool) {
	parts := strings.Split(strings.TrimSpace(line), ":")
	if len(parts) < 6 {
		return Account{}, false
	}
	return Account{
		Login:     parts[0],
		Password:  parts[1],
		FirstName: parts[2],
		LastName:  parts[3],
		APIKey:    parts[4],
		UUID:      parts[5],
		Sent:      0,
	}, true
}

func getMacro(name string) *Macro {
	for i := range app.Macros {
		if app.Macros[i].Name == name {
			return &app.Macros[i]
		}
	}
	return nil
}

func macroValue(m *Macro) string {
	if m.Every <= 0 {
		m.Every = 1
	}
	if m.Used%m.Every == 0 {
		switch m.Type {
		case "counter":
			m.Last = strconv.Itoa(m.Counter)
			m.Counter += m.Step
		case "random":
			n := m.Min
			if m.Max > m.Min {
				n = m.Min + rand.Intn(m.Max-m.Min+1)
			}
			var b strings.Builder
			for i := 0; i < n; i++ {
				if len(m.Chars) == 0 {
					m.Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
				}
				b.WriteByte(m.Chars[rand.Intn(len(m.Chars))])
			}
			m.Last = b.String()
		case "list":
			if len(m.Values) > 0 {
				if m.Sequential {
					m.Last = m.Values[m.Index%len(m.Values)]
					m.Index++
				} else {
					m.Last = m.Values[rand.Intn(len(m.Values))]
				}
			} else {
				m.Last = ""
			}
		}
	}
	m.Used++
	vals, _ := json.Marshal(m.Values)
	seq := 0
	if m.Sequential {
		seq = 1
	}
	db.Exec("UPDATE macros SET counter=?,step=?,chars=?,min=?,max=?,every=?,used=?,last=?,values=?,sequential=?,idx=? WHERE name=?",
		m.Counter, m.Step, m.Chars, m.Min, m.Max, m.Every, m.Used, m.Last, string(vals), seq, m.Index, m.Name)
	return m.Last
}

func replaceMacros(text string) string {
	for {
		start := strings.Index(text, "{{$")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], "}}")
		if end == -1 {
			break
		}
		end += start
		name := text[start+3 : end]
		if m := getMacro(name); m != nil {
			val := macroValue(m)
			text = text[:start] + val + text[end+2:]
		} else {
			text = text[:start] + text[end+2:]
		}
	}
	return text
}

func replaceInline(body string, atts []Attachment) (string, error) {
	for _, a := range atts {
		if a.Inline {
			data, err := os.ReadFile(a.Path)
			if err != nil {
				return body, err
			}
			enc := base64.StdEncoding.EncodeToString(data)
			body = strings.ReplaceAll(body, a.InlineMacro, enc)
		}
	}
	return body, nil
}

func checkAccount(acc *Account, log *strings.Builder) error {
	url := fmt.Sprintf("https://%s/api/mobile/v1/reset_fresh?app_state=active&uuid=%s", app.Domain, acc.UUID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Host", app.Domain)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Language", "ru-RU;q=1, en-RU;q=0.9")
	status, body, err := doAccountRequest(acc, log, req, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("код %d", status)
	}
	var res struct {
		Status struct {
			Status int `json:"status"`
		} `json:"status"`
	}
	json.Unmarshal(body, &res)
	if res.Status.Status != 1 {
		return fmt.Errorf("аккаунт не активен")
	}
	return nil
}

func generateOperationID(acc *Account, log *strings.Builder) (string, error) {
	url := fmt.Sprintf("https://%s/api/mobile/v2/generate_operation_id?app_state=foreground&uuid=%s&client=iphone", app.Domain, acc.UUID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Host", app.Domain)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Language", "ru-RU;q=1")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Connection", "close")
	status, body, err := doAccountRequest(acc, log, req, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("код %d", status)
	}
	var res struct {
		OperationID string `json:"operation_id"`
	}
	json.Unmarshal(body, &res)
	if res.OperationID == "" {
		return "", fmt.Errorf("нет operation_id")
	}
	return res.OperationID, nil
}

func sendEmail(subject, body string, atts []Attachment, recipients []EmailEntry, method string, firstSep bool) (string, error) {
	var log strings.Builder
	if len(app.Accounts) == 0 {
		return log.String(), fmt.Errorf("нет аккаунтов")
	}
	if len(recipients) == 0 {
		return log.String(), fmt.Errorf("нет получателей")
	}

	var recipientStrs []string
	for _, e := range recipients {
		recipientStrs = append(recipientStrs, fmt.Sprintf("\"%s\" <%s>", e.Name, e.Email))
	}

	// choose account considering send limits
	accountMu.Lock()
	var acc *Account
	for i := 0; i < len(app.Accounts); i++ {
		idx := (app.CurrentAccount + i) % len(app.Accounts)
		a := &app.Accounts[idx]
		if a.Sent < app.SendPerAccount && !a.InUse {
			acc = a
			a.InUse = true
			app.CurrentAccount = idx
			break
		}
	}
	if acc == nil {
		accountMu.Unlock()
		return log.String(), fmt.Errorf("аккаунты закончились")
	}
	if acc.Proxy == "" {
		acc.Proxy = getProxy()
		db.Exec("UPDATE accounts SET proxy=? WHERE login=?", acc.Proxy, acc.Login)
	}
	accountMu.Unlock()
	defer func() {
		accountMu.Lock()
		acc.InUse = false
		accountMu.Unlock()
	}()

	if err := checkAccount(acc, &log); err != nil {
		return log.String(), err
	}
	opID, err := generateOperationID(acc, &log)
	if err != nil {
		return log.String(), err
	}

	body, err = replaceInline(body, atts)
	if err != nil {
		return log.String(), err
	}
	body = replaceMacros(body)
	subject = replaceMacros(subject)

	var attIDs []string
	for _, a := range atts {
		_, url, err := uploadAttachment(acc, a.Path, &log)
		if err != nil {
			return log.String(), err
		}
		attIDs = append(attIDs, url)
	}
	payload := map[string]any{
		"att_ids":       attIDs,
		"attachesCount": len(attIDs),
		"send":          body,
		"ttype":         "html",
		"subj":          subject,
		"operation_id":  opID,
		"compose_check": "1",
		"from_mailbox":  acc.Login,
		"from_name":     acc.FirstName,
	}
	switch method {
	case "cc":
		if firstSep && len(recipientStrs) > 0 {
			payload["to"] = recipientStrs[0]
			if len(recipientStrs) > 1 {
				payload["cc"] = strings.Join(recipientStrs[1:], ";")
			}
		} else {
			payload["cc"] = strings.Join(recipientStrs, ";")
		}
	case "bcc":
		if firstSep && len(recipientStrs) > 0 {
			payload["to"] = recipientStrs[0]
			if len(recipientStrs) > 1 {
				payload["bcc"] = strings.Join(recipientStrs[1:], ";")
			}
		} else {
			payload["bcc"] = strings.Join(recipientStrs, ";")
		}
	default:
		payload["to"] = strings.Join(recipientStrs, ";")
	}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://%s/api/mobile/v1/send?app_state=foreground&uuid=%s", app.Domain, acc.UUID)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Host", app.Domain)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "ru-RU;q=1")
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("X-Request-Timeout", "180000")
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "close")
	status, respBody, err := doAccountRequest(acc, &log, req, b)
	if err != nil {
		return log.String(), err
	}
	if status != http.StatusOK {
		return log.String(), fmt.Errorf("код %d", status)
	}
	var res struct {
		Status struct {
			Status int `json:"status"`
		} `json:"status"`
	}
	json.Unmarshal(respBody, &res)
	if res.Status.Status != 1 {
		return log.String(), fmt.Errorf("отправка не удалась")
	}
	accountMu.Lock()
	acc.Sent++
	db.Exec("UPDATE accounts SET sent=?, proxy=? WHERE login=?", acc.Sent, acc.Proxy, acc.Login)
	if acc.Sent >= app.SendPerAccount {
		app.CurrentAccount = (app.CurrentAccount + 1) % len(app.Accounts)
	}
	accountMu.Unlock()
	return log.String(), nil
}

func uploadAttachment(acc *Account, path string, log *strings.Builder) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("filename", filepath.Base(path))
	part, err := writer.CreateFormFile("attachment", filepath.Base(path))
	if err != nil {
		return "", "", err
	}
	io.Copy(part, file)
	writer.Close()

	bodyBytes := buf.Bytes()
	url := fmt.Sprintf("https://%s/api/mobile/v1/upload?app_state=foreground&uuid=%s&client=iphone", app.Domain, acc.UUID)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	status, respBody, err := doAccountRequest(acc, log, req, bodyBytes)
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", fmt.Errorf("код %d", status)
	}
	var res struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	json.Unmarshal(respBody, &res)
	return res.ID, res.URL, nil
}
