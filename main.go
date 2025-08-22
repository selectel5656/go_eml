package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
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
}

type App struct {
	Domain    string
	UserAgent string
	AdminPass string

	Emails      []EmailEntry
	Macros      []string
	Attachments []Attachment
	Proxies     []string
	Accounts    []Account
	APIRules    string

	SendPerAccount int
	CycleAccounts  bool
	CurrentAccount int
}

var app = &App{
	Domain:         "domen.ru",
	UserAgent:      "MyUserAgent",
	AdminPass:      "admin",
	SendPerAccount: 1,
	CycleAccounts:  true,
}

type EmailEntry struct {
	Name  string
	Email string
}

type Attachment struct {
	Name        string
	Macro       string
	Path        string
	Inline      bool
	InlineMacro string
	Mime        string
}

type Account struct {
	Login     string
	Password  string
	FirstName string
	LastName  string
	APIKey    string
	UUID      string
	Sent      int
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/dashboard", requireAuth(handleDashboard))
	http.HandleFunc("/send", requireAuth(handleSend))
	http.HandleFunc("/emails", requireAuth(handleEmails))
	http.HandleFunc("/emails/add", requireAuth(handleEmailsAdd))
	http.HandleFunc("/emails/upload", requireAuth(handleEmailsUpload))
	http.HandleFunc("/emails/delete", requireAuth(handleEmailsDelete))
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
	subject := r.FormValue("subject")
	body := r.FormValue("body")
	var atts []Attachment
	for _, v := range r.Form["attach"] {
		if i, err := strconv.Atoi(v); err == nil {
			if i >= 0 && i < len(app.Attachments) {
				atts = append(atts, app.Attachments[i])
			}
		}
	}
	if err := sendEmail(subject, body, atts); err != nil {
		http.Redirect(w, r, "/dashboard?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/dashboard?msg="+url.QueryEscape("Письмо отправлено"), http.StatusFound)
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

func handleMacros(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Макросы", "Macros": app.Macros}
	render(w, "macros", data)
}

func handleMacrosAdd(w http.ResponseWriter, r *http.Request) {
	if m := r.FormValue("macro"); m != "" {
		app.Macros = append(app.Macros, m)
	}
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
		app.Proxies = append(app.Proxies, p)
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
				app.Proxies = append(app.Proxies, line)
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

func checkAccount(acc Account) error {
	url := fmt.Sprintf("https://%s/api/mobile/v1/reset_fresh?app_state=active&uuid=%s", app.Domain, acc.UUID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Host", app.Domain)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Language", "ru-RU;q=1, en-RU;q=0.9")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("код %d", resp.StatusCode)
	}
	var res struct {
		Status struct {
			Status int `json:"status"`
		} `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	if res.Status.Status != 1 {
		return fmt.Errorf("аккаунт не активен")
	}
	return nil
}

func generateOperationID(acc Account) (string, error) {
	url := fmt.Sprintf("https://%s/api/mobile/v2/generate_operation_id?app_state=foreground&uuid=%s&client=iphone", app.Domain, acc.UUID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Host", app.Domain)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Accept-Language", "ru-RU;q=1")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Connection", "close")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("код %d", resp.StatusCode)
	}
	var res struct {
		OperationID string `json:"operation_id"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	if res.OperationID == "" {
		return "", fmt.Errorf("нет operation_id")
	}
	return res.OperationID, nil
}

func sendEmail(subject, body string, atts []Attachment) error {
	if len(app.Accounts) == 0 {
		return fmt.Errorf("нет аккаунтов")
	}
	if len(app.Emails) == 0 {
		return fmt.Errorf("нет получателей")
	}

	// choose account considering send limits
	idx := app.CurrentAccount
	if idx >= len(app.Accounts) {
		return fmt.Errorf("аккаунты закончились")
	}
	if app.Accounts[idx].Sent >= app.SendPerAccount {
		idx++
		if idx >= len(app.Accounts) {
			if app.CycleAccounts {
				idx = 0
			} else {
				return fmt.Errorf("аккаунты закончились")
			}
		}
		app.CurrentAccount = idx
	}
	acc := &app.Accounts[app.CurrentAccount]
	to := app.Emails[0].Email

	if err := checkAccount(*acc); err != nil {
		return err
	}
	opID, err := generateOperationID(*acc)
	if err != nil {
		return err
	}

	var attIDs []string
	for _, a := range atts {
		_, url, err := uploadAttachment(*acc, a.Path)
		if err != nil {
			return err
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
		"to":            to,
		"from_name":     acc.FirstName,
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
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("код %d", resp.StatusCode)
	}
	var res struct {
		Status struct {
			Status int `json:"status"`
		} `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	if res.Status.Status != 1 {
		return fmt.Errorf("отправка не удалась")
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
	return nil
}

func uploadAttachment(acc Account, path string) (string, string, error) {
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

	url := fmt.Sprintf("https://%s/api/mobile/v1/upload?app_state=foreground&uuid=%s&client=iphone", app.Domain, acc.UUID)
	req, _ := http.NewRequest("POST", url, &buf)
	req.Header.Set("Authorization", "OAuth "+acc.APIKey)
	req.Header.Set("User-Agent", app.UserAgent)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var res struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	return res.ID, res.URL, nil
}
