package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
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
	"time"
)

//go:embed web/templates/*.html
var templateFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

var staticFiles fs.FS

var (
	templates = map[string]*template.Template{}
	loginTmpl *template.Template
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
}

type EmailEntry struct {
	Name  string
	Email string
	Sent  bool
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
	for i := range app.Proxies {
		if app.Proxies[i].Alive && !app.Proxies[i].Used {
			app.Proxies[i].Used = true
			return app.Proxies[i].Address
		}
	}
	for i := range app.Proxies {
		app.Proxies[i].Used = false
	}
	for i := range app.Proxies {
		if app.Proxies[i].Alive {
			app.Proxies[i].Used = true
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

func main() {
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

func massSend(subject, body string, atts []Attachment, rcount int, method string, firstSep bool) {
	for {
		if app.Stop {
			break
		}
		idxs := []int{}
		for i, e := range app.Emails {
			if !e.Sent {
				idxs = append(idxs, i)
				if len(idxs) == rcount {
					break
				}
			}
		}
		if len(idxs) == 0 {
			break
		}
		var batch []EmailEntry
		for _, idx := range idxs {
			batch = append(batch, app.Emails[idx])
		}
		logs, err := sendEmail(subject, body, atts, batch, method, firstSep)
		app.LastLog = logs
		if err == nil {
			for _, idx := range idxs {
				app.Emails[idx].Sent = true
			}
		} else {
			break
		}
	}
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
	}
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleEmailsUpload(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if e, ok := parseEmail(scanner.Text()); ok {
				app.Emails = append(app.Emails, e)
			}
		}
	}
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleEmailsDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Emails) {
			app.Emails = append(app.Emails[:i], app.Emails[i+1:]...)
		}
	}
	http.Redirect(w, r, "/emails", http.StatusFound)
}

func handleEmailsReset(w http.ResponseWriter, r *http.Request) {
	for i := range app.Emails {
		app.Emails[i].Sent = false
	}
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
	http.Redirect(w, r, "/macros", http.StatusFound)
}

func handleMacrosDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Macros) {
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
	}
	http.Redirect(w, r, "/attachments", http.StatusFound)
}

func handleAttachmentsDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Attachments) {
			os.Remove(app.Attachments[i].Path)
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
		app.Proxies = append(app.Proxies, Proxy{Address: p, Alive: checkProxy(p)})
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
				app.Proxies = append(app.Proxies, Proxy{Address: line, Alive: checkProxy(line)})
			}
		}
	}
	http.Redirect(w, r, "/proxies", http.StatusFound)
}

func handleProxiesDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Proxies) {
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
			}
		}
	}
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleAccountsDelete(w http.ResponseWriter, r *http.Request) {
	if i, err := strconv.Atoi(r.URL.Query().Get("i")); err == nil {
		if i >= 0 && i < len(app.Accounts) {
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
	http.Redirect(w, r, "/accounts", http.StatusFound)
}

func handleAPIRules(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "API правила", "APIRules": app.APIRules}
	render(w, "api-rules", data)
}

func handleAPIRulesSave(w http.ResponseWriter, r *http.Request) {
	app.APIRules = r.FormValue("rules")
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
	app.CycleAccounts = r.FormValue("cycle") == "on"
	if p := r.FormValue("password"); p != "" {
		app.AdminPass = p
	}
	data := map[string]any{
		"Title":          "Настройки",
		"Domain":         app.Domain,
		"UserAgent":      app.UserAgent,
		"SendPerAccount": app.SendPerAccount,
		"CycleAccounts":  app.CycleAccounts,
		"Threads":        app.Threads,
		"Message":        "Сохранено",
	}
	render(w, "settings", data)
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

func checkAccount(acc Account, log *strings.Builder) error {
	url := fmt.Sprintf("https://%s/api/mobile/v1/reset_fresh?app_state=active&uuid=%s", app.Domain, acc.UUID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Host", app.Domain)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Language", "ru-RU;q=1, en-RU;q=0.9")
	status, body, err := doLoggedRequest(log, req, nil, acc.Proxy)
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

func generateOperationID(acc Account, log *strings.Builder) (string, error) {
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
	status, body, err := doLoggedRequest(log, req, nil, acc.Proxy)
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
	idx := app.CurrentAccount
	if idx >= len(app.Accounts) {
		return log.String(), fmt.Errorf("аккаунты закончились")
	}
	if app.Accounts[idx].Sent >= app.SendPerAccount {
		idx++
		if idx >= len(app.Accounts) {
			if app.CycleAccounts {
				idx = 0
			} else {
				return log.String(), fmt.Errorf("аккаунты закончились")
			}
		}
		app.CurrentAccount = idx
	}
	acc := &app.Accounts[app.CurrentAccount]
	if acc.Proxy == "" {
		acc.Proxy = getProxy()
	}

	if err := checkAccount(*acc, &log); err != nil {
		return log.String(), err
	}
	opID, err := generateOperationID(*acc, &log)
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
		_, url, err := uploadAttachment(*acc, a.Path, &log)
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
	status, respBody, err := doLoggedRequest(&log, req, b, acc.Proxy)
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
	acc.Sent++
	if acc.Sent >= app.SendPerAccount {
		app.CurrentAccount++
		if app.CurrentAccount >= len(app.Accounts) {
			if app.CycleAccounts {
				app.CurrentAccount = 0
			}
		}
	}
	return log.String(), nil
}

func uploadAttachment(acc Account, path string, log *strings.Builder) (string, string, error) {
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
	status, respBody, err := doLoggedRequest(log, req, bodyBytes, acc.Proxy)
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
