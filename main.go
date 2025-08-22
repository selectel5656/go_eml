package main

import (
	"bufio"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

//go:embed web/templates/*.html
var templateFS embed.FS

var tmpl = template.Must(template.ParseFS(templateFS, "web/templates/*.html"))

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
}

var app = &App{
	Domain:    "domen.ru",
	UserAgent: "MyUserAgent",
	AdminPass: "admin",
}

type EmailEntry struct {
	Name  string
	Email string
}

type Attachment struct {
	Name  string
	Macro string
	Path  string
}

type Account struct {
	Login     string
	Password  string
	FirstName string
	LastName  string
	APIKey    string
	UUID      string
}

func main() {
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
	http.HandleFunc("/api-rules", requireAuth(handleAPIRules))
	http.HandleFunc("/api-rules/save", requireAuth(handleAPIRulesSave))
	http.HandleFunc("/settings", requireAuth(handleSettings))
	http.HandleFunc("/settings/save", requireAuth(handleSettingsSave))

	http.ListenAndServe(":8080", nil)
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
		tmpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": "Неверные данные"})
		return
	}
	tmpl.ExecuteTemplate(w, "login.html", nil)
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
	tmpl.ExecuteTemplate(w, "layout.html", data)
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleEmails(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":  "База e-mail",
		"Emails": app.Emails,
	}
	tmpl.ExecuteTemplate(w, "layout.html", data)
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
	tmpl.ExecuteTemplate(w, "layout.html", data)
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
	tmpl.ExecuteTemplate(w, "layout.html", data)
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
		app.Attachments = append(app.Attachments, Attachment{Name: header.Filename, Macro: macro, Path: path})
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
	tmpl.ExecuteTemplate(w, "layout.html", data)
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
	tmpl.ExecuteTemplate(w, "layout.html", data)
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

func handleAPIRules(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "API правила", "APIRules": app.APIRules}
	tmpl.ExecuteTemplate(w, "layout.html", data)
}

func handleAPIRulesSave(w http.ResponseWriter, r *http.Request) {
	app.APIRules = r.FormValue("rules")
	http.Redirect(w, r, "/api-rules", http.StatusFound)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"Title":     "Настройки",
		"Domain":    app.Domain,
		"UserAgent": app.UserAgent,
	}
	tmpl.ExecuteTemplate(w, "layout.html", data)
}

func handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if d := r.FormValue("domain"); d != "" {
		app.Domain = d
	}
	if ua := r.FormValue("useragent"); ua != "" {
		app.UserAgent = ua
	}
	if p := r.FormValue("password"); p != "" {
		app.AdminPass = p
	}
	data := map[string]any{
		"Title":     "Настройки",
		"Domain":    app.Domain,
		"UserAgent": app.UserAgent,
		"Message":   "Сохранено",
	}
	tmpl.ExecuteTemplate(w, "layout.html", data)
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
	}, true
}
