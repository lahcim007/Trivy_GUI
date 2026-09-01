const $ = id => document.getElementById(id);
let token = localStorage.getItem("token");
let pollTimer = null, logsPollTimer = null;
let currentScanId = null;
let currentVulns = [];
let currentSecrets = [];
let currentScanMeta = null;
let vulnSort = "exploit";
let vulnFilter = "all";
let vulnQuery = "";
let me = null;
let canManage = false;
let statsDays = 30;
let statsCharts = {};
let statsChartDefaults = false;
let statsCache = null;
let healthCache = null;
let auditCache = null;
let auditPage = 1;
let historyDoneIds = [];
let scanStatusFilter = "all";
let containerStatusFilter = "all";
let lang = localStorage.getItem("lang") || "pl";
let diffData = null;
let diffTab = "new";

const SEV = {
  CRITICAL: "bg-red-600", HIGH: "bg-orange-600",
  MEDIUM: "bg-amber-600", LOW: "bg-lime-600", UNKNOWN: "bg-slate-600",
};

const I18N = {
  pl: {
    title: "Trivy GUI 🛡️",
    subtitle: "Skaner podatności obrazów Docker",
    login: "Login",
    password: "Hasło",
    sign_in: "Zaloguj się",
    login_error: "Błędny login lub hasło",
    logout: "Wyloguj ⏻",
    tab_scans: "🔍 Skany",
    tab_stats: "📈 Statystyki",
    tab_containers: "🐋 Kontenery",
    tab_admin: "⚙️ Administracja",
    new_scan: "🔍 Nowy skan",
    new_scan_hint: "Obraz z Docker Hub, prywatnego rejestru albo lokalny tag z hosta",
    image_ph: "np. nginx:latest lub registry.firma.pl/app:1.0",
    scan_btn: "Skanuj ▶",
    scan_secrets: "🔐 Skanuj również sekrety (klucze API, hasła, tokeny) — wydłuża czas skanowania",
    scan_secrets_short: "🔐 skanuj też sekrety",
    private_registry: "🔑 Prywatny rejestr (opcjonalnie)",
    reg_user: "Login rejestru",
    reg_pass: "Hasło / token",
    readonly_notice: "👁️ Masz dostęp tylko do przeglądania i pobierania raportów. Uruchamianie i usuwanie skanów wymaga roli manager lub admin.",
    scan_history: "📊 Historia skanów",
    scan_history_hint: "Zaznacz dwa zakończone skany tego samego obrazu, aby porównać CVE",
    filter_image: "Filtruj obraz…",
    compare: "⚖️ Porównaj",
    compare_last: "⚖️ Porównaj ostatnie dwa",
    delete_selected: "🗑 Usuń zaznaczone",
    col_image: "Obraz",
    col_date: "Data",
    col_author: "Autor",
    col_status: "Status",
    col_vulns: "Podatności",
    col_secrets: "Sekrety",
    col_actions: "Akcje",
    col_pkg: "Pakiet",
    col_count: "Wystąpień",
    col_images: "Obrazy",
    col_total: "Razem",
    col_trend: "Trend",
    col_scans: "Skanów",
    col_name: "Nazwa",
    col_created: "Utworzono",
    col_ip: "Adres IP",
    col_ports: "Porty",
    col_size: "Rozmiar",
    col_owner: "Właściciel",
    col_role: "Rola",
    col_user: "Użytkownik",
    col_action: "Akcja",
    col_target: "Cel",
    col_details: "Szczegóły",
    filter_all: "Wszystkie",
    filter: "Filtruj",
    filter_container: "Filtruj nazwę, obraz, stack…",
    filter_user: "Użytkownik…",
    st_pending: "⏳ oczekuje",
    st_running: "🔄 skanowanie…",
    st_done: "✅ gotowe",
    st_error: "❌ błąd",
    clean: "✨ czysto",
    secrets_off: "nie skanowano",
    secrets_none: "✨ brak",
    no_scans: "Brak skanów",
    no_filter: "Brak wyników filtra",
    selected: "Zaznaczono",
    queue: "Kolejka",
    kpi_total: "Skanów (widok)",
    kpi_running: "W toku",
    kpi_done: "Gotowe",
    kpi_error: "Błędy",
    kpi_images: "Unikalne obrazy",
    stats_title: "📈 Statystyki i trendy",
    range_all: "Całość",
    refresh: "🔄 Odśwież",
    stats_empty: "Brak skanów w wybranym okresie.",
    stats_loading: "Ładowanie statystyk…",
    no_data: "Brak danych",
    no_vulns: "✨ Brak podatności",
    chart_timeline: "📉 Podatności w czasie",
    chart_posture: "🎯 Aktualna postawa",
    chart_posture_hint: "Suma z ostatniego skanu każdego obrazu",
    top_vuln_images: "⚠️ Najbardziej podatne obrazy",
    most_scanned: "🔁 Najczęściej skanowane",
    image_trends: "📊 Trend obrazów (CRITICAL + HIGH)",
    image_trends_hint: "Obrazy zeskanowane co najmniej dwukrotnie w okresie — czy jest lepiej, czy gorzej",
    top_cves: "🐞 Najczęstsze CVE",
    cve_sort_hint: "Sortowanie: CISA KEV → EPSS → severity",
    top_pkgs: "📦 Pakiety z największą liczbą CVE",
    image_rank: "🏷️ Ranking obrazów (ostatni skan)",
    period_all: "Cała historia skanów · daty w UTC",
    period_days: "Ostatnie {n} dni · daty w UTC",
    cve_sample: "na podstawie {n} ost. skanów",
    kpi_scans: "Skanów",
    kpi_scan_sub: "{e} błędów · {r}% sukcesu",
    kpi_images_n: "Obrazów",
    kpi_images_sub: "{n} z zakończonym skanem",
    kpi_clean: "Czyste obrazy",
    kpi_clean_sub: "{n} czystych skanów",
    kpi_crit_sub: "suma ostatnich skanów · śr. {n}/skan",
    kpi_sum_last: "suma ostatnich skanów",
    kpi_secrets: "Sekrety",
    kpi_secrets_sub: "{n} skanów z włączonymi sekretami",
    kpi_risk: "Risk score",
    kpi_risk_sub: "C×10 + H×5 + M×2 + L",
    trend_down: "↓ poprawa",
    trend_up: "↑ pogorszenie",
    trend_stable: "→ bez zmian",
    trend_new: "✦ nowy",
    last_scan: "Ostatni skan",
    image_hist: "Historia obrazu",
    history: "Historia",
    containers_title: "🐋 Kontenery na hoście",
    containers_hint: "Lista z docker.sock — skanuj obraz bez przepisywania tagu",
    scan_selected: "🔍 Skanuj zaznaczone",
    c_running: "Uruchomione",
    c_other: "Zatrzymane",
    c_stacks: "Stacki",
    c_total: "Kontenery",
    check_size: "sprawdź",
    sizing: "liczenie…",
    size_err: "błąd",
    no_containers: "Brak kontenerów",
    confirm_scan_n: "Uruchomić skan dla {n} obraz(ów)? Będą kolejkowane i skanowane jeden po drugim.",
    scan_queued: "Zlecono {ok} skanów (będą przetwarzane po kolei).",
    scan_fail: "Błędy zlecenia dla: {list}",
    scan_err: "Błąd uruchamiania skanu {img}: {err}",
    my_account: "👤 Moje konto",
    my_account_hint: "Zmiana hasła jest zapisywana w dzienniku audytu",
    new_password: "Nowe hasło",
    change_password: "Zmień moje hasło",
    password_changed: "Hasło zmienione ✅",
    new_user: "➕ Nowy użytkownik",
    new_user_hint: "user czyta raporty · manager skanuje · admin zarządza",
    role_user: "user — tylko przegląda i pobiera raporty",
    role_manager: "manager — może uruchamiać i usuwać skany",
    role_admin: "admin — pełny dostęp + zarządzanie użytkownikami",
    add: "Dodaj",
    users: "👥 Użytkownicy",
    you: "to Ty",
    protected: "chronione",
    del_user: "usuń",
    set_pass: "hasło",
    confirm_del_user: "Usunąć użytkownika?",
    prompt_new_pass: "Nowe hasło (min. 6 znaków):",
    health: "🩺 Healthcheck",
    maintenance: "🧹 Maintenance",
    maintenance_hint: "EPSS i CISA KEV odświeżają się same co ~24 h; tu możesz wymusić",
    maint_db: "📥 Aktualizuj bazę CVE (Trivy DB)",
    maint_feeds: "📡 Aktualizuj EPSS / CISA KEV",
    maint_cleanup: "🗑 Usuń skany starsze niż (dni)",
    maint_vacuum: "🧼 VACUUM bazy SQLite",
    vacuum_ok: "VACUUM wykonany ✅",
    deleted_n: "Usunięto {n} skanów",
    audit_title: "🧾 Dziennik audytu",
    audit_hint: "Logowania, skany, usunięcia, hasła, eksporty",
    prev: "←",
    next: "→",
    page: "Strona {p} / {n} · {t} wpisów",
    no_audit: "Brak wpisów",
    scan_logs: "📜 Logi skanu",
    logs_scan: "Logi skanu #{id}",
    logs_container: "Logi kontenera: {name}",
    no_logs: "(brak logów)",
    no_vulns_bang: "✨ Brak podatności!",
    secrets_found: "🔐 Wykryte sekrety",
    no_secrets: "✨ Nie znaleziono sekretów!",
    sort_by: "Sortuj",
    sort_exploit: "KEV + EPSS",
    sort_severity: "Severity",
    sort_epss: "EPSS",
    sort_pkg: "Pakiet",
    filter_kev: "Tylko KEV",
    filter_epss: "EPSS ≥ 1%",
    filter_cve: "CVE / pakiet…",
    package: "Pakiet",
    fixed_in: "Naprawiono w",
    none: "brak",
    published: "Opublikowano",
    modified: "Zmodyfikowano",
    description: "Opis",
    no_description: "Brak opisu",
    references: "Odnośniki",
    no_cvss: "Brak danych CVSS",
    no_refs: "Brak",
    epss: "EPSS",
    percentile: "percentyl",
    kev_catalog: "CISA KEV",
    ransomware: "Ransomware",
    due: "termin",
    added: "dodano",
    confirm_del_scan: "Usunąć skan?",
    confirm_del_n: "Usunąć {n} zaznaczonych skanów? Tej operacji nie da się cofnąć.",
    diff_need_two: "Zaznacz dokładnie dwa zakończone skany tego samego obrazu.",
    diff_title: "Porównanie: {img}",
    diff_from_to: "#{a} → #{b}",
    diff_new: "Nowe",
    diff_fixed: "Naprawione",
    diff_unchanged: "Bez zmian",
    diff_empty: "Brak pozycji w tej kategorii",
    not_scanned: "nie skanowano",
    session: "Sesja wygasła",
    error: "Błąd",
    days: "dni",
    ok: "OK",
    fail: "błąd",
    h_trivy: "Trivy",
    h_docker: "Docker",
    h_db: "Baza",
    h_disk: "Dysk /data",
    h_cache: "Cache Trivy",
    h_epss: "EPSS",
    h_kev: "CISA KEV",
    never: "nigdy",
    rows: "wierszy",
    scans_n: "skanów",
    running_n: "w toku",
    act_login: "logowanie",
    act_login_failed: "błąd logowania",
    act_scan_start: "start skanu",
    act_scan_delete: "usunięcie skanu",
    act_scan_bulk_delete: "masowe usunięcie",
    act_password_change: "zmiana hasła",
    act_user_create: "nowy użytkownik",
    act_user_password_set: "reset hasła",
    act_user_delete: "usunięcie użytkownika",
    act_db_update: "aktualizacja Trivy DB",
    act_feeds_update: "aktualizacja EPSS/KEV",
    act_scans_cleanup: "czyszczenie skanów",
    act_db_vacuum: "VACUUM",
    act_export_zip: "eksport ZIP",
    act_export_json: "eksport JSON",
    act_export_csv: "eksport CSV",
    act_export_pdf: "eksport PDF",
    act_export_audit_csv: "eksport audytu CSV",
    act_export_audit_json: "eksport audytu JSON",
    chart_scans: "Liczba skanów",
    rescan: "Skanuj ponownie",
    details: "Szczegóły",
    ct_running: "running",
    ct_exited: "exited",
    ct_other: "inne",
  },
  en: {
    title: "Trivy GUI 🛡️",
    subtitle: "Docker image vulnerability scanner",
    login: "Username",
    password: "Password",
    sign_in: "Sign in",
    login_error: "Invalid username or password",
    logout: "Log out ⏻",
    tab_scans: "🔍 Scans",
    tab_stats: "📈 Statistics",
    tab_containers: "🐋 Containers",
    tab_admin: "⚙️ Administration",
    new_scan: "🔍 New scan",
    new_scan_hint: "Image from Docker Hub, a private registry, or a local host tag",
    image_ph: "e.g. nginx:latest or registry.example.com/app:1.0",
    scan_btn: "Scan ▶",
    scan_secrets: "🔐 Also scan for secrets (API keys, passwords, tokens) — takes longer",
    scan_secrets_short: "🔐 scan secrets too",
    private_registry: "🔑 Private registry (optional)",
    reg_user: "Registry username",
    reg_pass: "Password / token",
    readonly_notice: "👁️ Read-only access. Starting and deleting scans requires manager or admin.",
    scan_history: "📊 Scan history",
    scan_history_hint: "Select two finished scans of the same image to diff CVEs",
    filter_image: "Filter image…",
    compare: "⚖️ Compare",
    compare_last: "⚖️ Compare last two",
    delete_selected: "🗑 Delete selected",
    col_image: "Image",
    col_date: "Date",
    col_author: "Author",
    col_status: "Status",
    col_vulns: "Vulnerabilities",
    col_secrets: "Secrets",
    col_actions: "Actions",
    col_pkg: "Package",
    col_count: "Hits",
    col_images: "Images",
    col_total: "Total",
    col_trend: "Trend",
    col_scans: "Scans",
    col_name: "Name",
    col_created: "Created",
    col_ip: "IP address",
    col_ports: "Ports",
    col_size: "Size",
    col_owner: "Owner",
    col_role: "Role",
    col_user: "User",
    col_action: "Action",
    col_target: "Target",
    col_details: "Details",
    filter_all: "All",
    filter: "Filter",
    filter_container: "Filter name, image, stack…",
    filter_user: "User…",
    st_pending: "⏳ pending",
    st_running: "🔄 scanning…",
    st_done: "✅ done",
    st_error: "❌ error",
    clean: "✨ clean",
    secrets_off: "not scanned",
    secrets_none: "✨ none",
    no_scans: "No scans",
    no_filter: "No filter matches",
    selected: "Selected",
    queue: "Queue",
    kpi_total: "Scans (view)",
    kpi_running: "Running",
    kpi_done: "Done",
    kpi_error: "Errors",
    kpi_images: "Unique images",
    stats_title: "📈 Statistics and trends",
    range_all: "All time",
    refresh: "🔄 Refresh",
    stats_empty: "No scans in the selected period.",
    stats_loading: "Loading statistics…",
    no_data: "No data",
    no_vulns: "✨ No vulnerabilities",
    chart_timeline: "📉 Vulnerabilities over time",
    chart_posture: "🎯 Current posture",
    chart_posture_hint: "Sum of each image's latest scan",
    top_vuln_images: "⚠️ Most vulnerable images",
    most_scanned: "🔁 Most scanned",
    image_trends: "📊 Image trend (CRITICAL + HIGH)",
    image_trends_hint: "Images scanned at least twice in the period",
    top_cves: "🐞 Top CVEs",
    cve_sort_hint: "Sort: CISA KEV → EPSS → severity",
    top_pkgs: "📦 Packages with the most CVEs",
    image_rank: "🏷️ Image ranking (latest scan)",
    period_all: "Full scan history · dates in UTC",
    period_days: "Last {n} days · dates in UTC",
    cve_sample: "based on {n} latest scans",
    kpi_scans: "Scans",
    kpi_scan_sub: "{e} errors · {r}% success",
    kpi_images_n: "Images",
    kpi_images_sub: "{n} with a finished scan",
    kpi_clean: "Clean images",
    kpi_clean_sub: "{n} clean scans",
    kpi_crit_sub: "sum of latest scans · avg {n}/scan",
    kpi_sum_last: "sum of latest scans",
    kpi_secrets: "Secrets",
    kpi_secrets_sub: "{n} scans with secrets enabled",
    kpi_risk: "Risk score",
    kpi_risk_sub: "C×10 + H×5 + M×2 + L",
    trend_down: "↓ improved",
    trend_up: "↑ worse",
    trend_stable: "→ stable",
    trend_new: "✦ new",
    last_scan: "Latest scan",
    image_hist: "Image history",
    history: "History",
    containers_title: "🐋 Host containers",
    containers_hint: "From docker.sock — scan an image without retyping the tag",
    scan_selected: "🔍 Scan selected",
    c_running: "Running",
    c_other: "Stopped",
    c_stacks: "Stacks",
    c_total: "Containers",
    check_size: "check",
    sizing: "counting…",
    size_err: "error",
    no_containers: "No containers",
    confirm_scan_n: "Start a scan for {n} image(s)? They will be queued one after another.",
    scan_queued: "Queued {ok} scans (processed sequentially).",
    scan_fail: "Failed to queue: {list}",
    scan_err: "Failed to start scan {img}: {err}",
    my_account: "👤 My account",
    my_account_hint: "Password changes are written to the audit log",
    new_password: "New password",
    change_password: "Change my password",
    password_changed: "Password changed ✅",
    new_user: "➕ New user",
    new_user_hint: "user reads reports · manager scans · admin manages",
    role_user: "user — view and download reports only",
    role_manager: "manager — can start and delete scans",
    role_admin: "admin — full access + user management",
    add: "Add",
    users: "👥 Users",
    you: "you",
    protected: "protected",
    del_user: "delete",
    set_pass: "password",
    confirm_del_user: "Delete this user?",
    prompt_new_pass: "New password (min. 6 characters):",
    health: "🩺 Healthcheck",
    maintenance: "🧹 Maintenance",
    maintenance_hint: "EPSS and CISA KEV refresh about every 24 h; you can force it here",
    maint_db: "📥 Update CVE database (Trivy DB)",
    maint_feeds: "📡 Update EPSS / CISA KEV",
    maint_cleanup: "🗑 Delete scans older than (days)",
    maint_vacuum: "🧼 VACUUM SQLite database",
    vacuum_ok: "VACUUM completed ✅",
    deleted_n: "Deleted {n} scans",
    audit_title: "🧾 Audit log",
    audit_hint: "Logins, scans, deletions, passwords, exports",
    prev: "←",
    next: "→",
    page: "Page {p} / {n} · {t} entries",
    no_audit: "No entries",
    scan_logs: "📜 Scan logs",
    logs_scan: "Scan logs #{id}",
    logs_container: "Container logs: {name}",
    no_logs: "(no logs)",
    no_vulns_bang: "✨ No vulnerabilities!",
    secrets_found: "🔐 Detected secrets",
    no_secrets: "✨ No secrets found!",
    sort_by: "Sort",
    sort_exploit: "KEV + EPSS",
    sort_severity: "Severity",
    sort_epss: "EPSS",
    sort_pkg: "Package",
    filter_kev: "KEV only",
    filter_epss: "EPSS ≥ 1%",
    filter_cve: "CVE / package…",
    package: "Package",
    fixed_in: "Fixed in",
    none: "none",
    published: "Published",
    modified: "Modified",
    description: "Description",
    no_description: "No description",
    references: "References",
    no_cvss: "No CVSS data",
    no_refs: "None",
    epss: "EPSS",
    percentile: "percentile",
    kev_catalog: "CISA KEV",
    ransomware: "Ransomware",
    due: "due",
    added: "added",
    confirm_del_scan: "Delete this scan?",
    confirm_del_n: "Delete {n} selected scans? This cannot be undone.",
    diff_need_two: "Select exactly two finished scans of the same image.",
    diff_title: "Compare: {img}",
    diff_from_to: "#{a} → #{b}",
    diff_new: "New",
    diff_fixed: "Fixed",
    diff_unchanged: "Unchanged",
    diff_empty: "Nothing in this category",
    not_scanned: "not scanned",
    session: "Session expired",
    error: "Error",
    days: "days",
    ok: "OK",
    fail: "error",
    h_trivy: "Trivy",
    h_docker: "Docker",
    h_db: "Database",
    h_disk: "Disk /data",
    h_cache: "Trivy cache",
    h_epss: "EPSS",
    h_kev: "CISA KEV",
    never: "never",
    rows: "rows",
    scans_n: "scans",
    running_n: "running",
    act_login: "login",
    act_login_failed: "login failed",
    act_scan_start: "scan start",
    act_scan_delete: "scan delete",
    act_scan_bulk_delete: "bulk delete",
    act_password_change: "password change",
    act_user_create: "user create",
    act_user_password_set: "password reset",
    act_user_delete: "user delete",
    act_db_update: "Trivy DB update",
    act_feeds_update: "EPSS/KEV update",
    act_scans_cleanup: "scan cleanup",
    act_db_vacuum: "VACUUM",
    act_export_zip: "ZIP export",
    act_export_json: "JSON export",
    act_export_csv: "CSV export",
    act_export_pdf: "PDF export",
    act_export_audit_csv: "audit CSV export",
    act_export_audit_json: "audit JSON export",
    chart_scans: "Scan count",
    rescan: "Scan again",
    details: "Details",
    ct_running: "running",
    ct_exited: "exited",
    ct_other: "other",
  },
};

const AUDIT_ACTIONS = [
  "login", "login_failed", "scan_start", "scan_delete", "scan_bulk_delete",
  "password_change", "user_create", "user_password_set", "user_delete",
  "db_update", "feeds_update", "scans_cleanup", "db_vacuum",
  "export_zip", "export_json", "export_csv", "export_pdf", "export_audit_csv", "export_audit_json",
];

function t(key, vars) {
  const dict = I18N[lang] || I18N.pl;
  let s = dict[key] ?? I18N.pl[key] ?? key;
  if (vars) Object.entries(vars).forEach(([k, v]) => { s = s.replaceAll("{" + k + "}", v); });
  return s;
}

function applyI18n() {
  document.documentElement.lang = lang;
  document.title = t("title");
  document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
  document.querySelectorAll("[data-i18n-title]").forEach(el => { el.title = t(el.dataset.i18nTitle); });
  document.querySelectorAll(".lang-btn").forEach(b => {
    b.classList.toggle("bg-sky-600", b.dataset.lang === lang);
    b.classList.toggle("text-white", b.dataset.lang === lang);
    b.classList.toggle("text-slate-400", b.dataset.lang !== lang);
  });
  fillAuditActions();
  renderScanStatusFilters();
  renderContainerStatusFilters();
}

function setLang(l) {
  lang = l === "en" ? "en" : "pl";
  localStorage.setItem("lang", lang);
  applyI18n();
  if (scansCache.length) renderScans();
  if (containersCache.length) renderContainers();
  if (statsCache) {
    $("stats-period-label").textContent = periodLabel(statsCache.period_days);
    renderKpis(statsCache);
    renderStatsTables(statsCache);
    requestAnimationFrame(() => renderStatsCharts(statsCache));
  }
  if (healthCache) renderHealth(healthCache);
  if (auditCache) renderAudit(auditCache);
  if (currentScanMeta) renderScanDetailBody();
  if (diffData) renderDiff();
  updateScanSelectedBar();
  updateSelectedBar();
}

function headers() { return { "Authorization": "Bearer " + token }; }

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...headers(), ...(opts.headers || {}) },
    cache: "no-store",
  });
  if (res.status === 401) { logout(); throw new Error(t("session")); }
  if (!res.ok) {
    let detail = t("error");
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  return res;
}

async function login() {
  const body = new URLSearchParams({ username: $("login-user").value, password: $("login-pass").value });
  const res = await fetch("/api/login", { method: "POST", body });
  if (!res.ok) {
    $("login-error").textContent = t("login_error");
    $("login-error").classList.remove("hidden");
    return;
  }
  token = (await res.json()).access_token;
  localStorage.setItem("token", token);
  showApp();
}

function logout() {
  localStorage.removeItem("token");
  token = null;
  me = null;
  canManage = false;
  clearInterval(pollTimer);
  clearInterval(logsPollTimer);
  $("app-view").classList.add("hidden");
  $("login-view").classList.remove("hidden");
}

async function showApp() {
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  me = await (await api("/api/me")).json();
  canManage = (me.role === "admin" || me.role === "manager");
  $("me-label").textContent = `${me.username} (${me.role})`;
  $("btn-admin").classList.toggle("hidden", me.role !== "admin");
  $("new-scan-card").classList.toggle("hidden", !canManage);
  $("readonly-notice").classList.toggle("hidden", canManage);
  $("th-scan-check").classList.toggle("hidden", !canManage);
  $("th-container-check").classList.toggle("hidden", !canManage);
  $("containers-mgr-toolbar").classList.toggle("hidden", !canManage);
  applyI18n();
  loadScans();
  clearInterval(pollTimer);
  pollTimer = setInterval(loadScans, 4000);
}

function showTab(name) {
  document.querySelectorAll(".tab-panel").forEach(el => el.classList.add("hidden"));
  document.querySelectorAll(".tab-btn").forEach(el => {
    el.classList.remove("border-sky-400", "text-sky-400", "font-semibold");
    el.classList.add("border-transparent", "text-slate-400");
  });
  $("tab-" + name).classList.remove("hidden");
  const activeBtn = $("btn-" + name);
  activeBtn.classList.remove("border-transparent", "text-slate-400");
  activeBtn.classList.add("border-sky-400", "text-sky-400", "font-semibold");
  if (name === "containers") loadContainers();
  if (name === "stats") loadStats();
  if (name === "admin" && me.role === "admin") { loadUsers(); loadHealth(); loadAudit(1); }
}

async function startScan() {
  if (!canManage) return;
  const image = $("scan-image").value.trim();
  if (!image) return;
  try {
    await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        image,
        registry_user: $("reg-user").value || null,
        registry_password: $("reg-pass").value || null,
        scan_secrets: $("scan-secrets-checkbox").checked,
      }),
    });
    $("scan-image").value = "";
    $("scan-secrets-checkbox").checked = false;
    loadScans();
  } catch (e) { alert(e.message); }
}

let scansCache = [];
let selectedScanIds = new Set();

async function loadScans() {
  scansCache = await (await api("/api/scans")).json();
  const existingIds = new Set(scansCache.map(s => s.id));
  [...selectedScanIds].forEach(id => { if (!existingIds.has(id)) selectedScanIds.delete(id); });
  try {
    const q = await (await api("/api/queue")).json();
    $("queue-badge").textContent = `${t("queue")}: ${q.pending_jobs}`;
  } catch {}
  renderScans();
  updateScanSelectedBar();
}

function renderScanStatusFilters() {
  const box = $("scan-status-filters");
  if (!box) return;
  const items = [
    ["all", t("filter_all")],
    ["running", t("st_running")],
    ["done", t("st_done")],
    ["error", t("st_error")],
    ["pending", t("st_pending")],
  ];
  box.innerHTML = items.map(([st, lab]) => `
    <button onclick="setScanStatusFilter('${st}')"
            class="px-3 py-1 rounded-full text-xs ${scanStatusFilter === st ? "bg-sky-600 text-white" : "bg-slate-700 text-slate-300 hover:bg-slate-600"}">${lab}</button>
  `).join("");
}

function setScanStatusFilter(st) {
  scanStatusFilter = st;
  renderScanStatusFilters();
  renderScans();
}

function kpiMini(label, value, color) {
  return `<div class="bg-slate-800 rounded-2xl p-4 border border-slate-700">
    <div class="text-xs text-slate-400 mb-1">${label}</div>
    <div class="text-2xl font-bold ${color || "text-slate-100"}">${value}</div>
  </div>`;
}

function renderScans() {
  const q = ($("scan-filter")?.value || "").trim().toLowerCase();
  let rows = q ? scansCache.filter(s => (s.image || "").toLowerCase().includes(q)) : scansCache.slice();
  if (scanStatusFilter !== "all") rows = rows.filter(s => s.status === scanStatusFilter);
  const running = scansCache.filter(s => s.status === "running").length;
  const done = scansCache.filter(s => s.status === "done").length;
  const err = scansCache.filter(s => s.status === "error").length;
  const imgs = new Set(scansCache.map(s => s.image)).size;
  $("scan-kpis").innerHTML = [
    kpiMini(t("kpi_total"), fmtNum(scansCache.length), "text-sky-400"),
    kpiMini(t("kpi_running"), fmtNum(running), "text-sky-300"),
    kpiMini(t("kpi_done"), fmtNum(done), "text-emerald-400"),
    kpiMini(t("kpi_error"), fmtNum(err), "text-red-400"),
    kpiMini(t("kpi_images"), fmtNum(imgs)),
  ].join("");
  const cols = canManage ? 8 : 7;
  if (!rows.length) {
    $("scan-table").innerHTML = `<tr><td colspan="${cols}" class="py-6 text-center text-slate-500">${scansCache.length ? t("no_filter") : t("no_scans")}</td></tr>`;
    return;
  }
  $("scan-table").innerHTML = rows.map(s => `
    <tr class="border-b border-slate-700/50 hover:bg-slate-700/30">
      ${canManage ? `<td class="py-2 px-2">
        <input type="checkbox" class="scan-checkbox" data-id="${s.id}"
               onchange="onScanCheck(this)" ${selectedScanIds.has(s.id) ? "checked" : ""}>
      </td>` : ""}
      <td class="px-2 font-mono text-xs">${esc(s.image)}</td>
      <td class="px-2 text-slate-400 whitespace-nowrap">${new Date(s.created_at + "Z").toLocaleString(lang === "en" ? "en-GB" : "pl-PL")}</td>
      <td class="px-2 text-xs text-slate-400">${esc(s.created_by || "—")}</td>
      <td class="px-2">${statusBadge(s)}</td>
      <td class="px-2">${s.status === "done" ? sevBadges(s) : "—"}</td>
      <td class="px-2">${secretsBadge(s)}</td>
      <td class="px-2 text-right whitespace-nowrap">
        ${s.status === "done" ? `
          <button onclick="showDetail(${s.id})" title="${t("details")}" class="hover:text-sky-400">🔎</button>
          <button onclick="dl(${s.id},'json')" title="JSON" class="hover:text-sky-400 ml-1">📄</button>
          <button onclick="dl(${s.id},'csv')" title="CSV" class="hover:text-sky-400 ml-1">📊</button>
          <button onclick="dl(${s.id},'pdf')" title="PDF" class="hover:text-sky-400 ml-1">📕</button>` : ""}
        ${s.status === "running" || s.status === "error" || s.status === "pending" ? `
          <button onclick="showScanLogs(${s.id})" title="${t("scan_logs")}" class="hover:text-amber-400 ml-1">📜</button>` : ""}
        ${canManage ? `<button onclick="scanImageNow('${esc(s.image)}')" title="${t("rescan")}" class="hover:text-emerald-400 ml-1">🔁</button>
          <button onclick="delScan(${s.id})" title="${t("del_user")}" class="hover:text-red-400 ml-1">🗑</button>` : ""}
      </td>
    </tr>`).join("");
}

function onScanCheck(el) {
  const id = parseInt(el.dataset.id, 10);
  if (el.checked) selectedScanIds.add(id); else selectedScanIds.delete(id);
  updateScanSelectedBar();
}

function toggleSelectAllScans(headerCheckbox) {
  document.querySelectorAll(".scan-checkbox").forEach(cb => {
    cb.checked = headerCheckbox.checked;
    onScanCheck(cb);
  });
}

function updateScanSelectedBar() {
  const n = selectedScanIds.size;
  $("scan-selected-count").textContent = n > 0 ? `${t("selected")}: ${n}` : "";
  $("scan-bulk-actions").classList.toggle("hidden", n === 0 || !canManage);
  const ids = [...selectedScanIds];
  let canDiff = false;
  if (ids.length === 2) {
    const a = scansCache.find(s => s.id === ids[0]);
    const b = scansCache.find(s => s.id === ids[1]);
    canDiff = !!(a && b && a.image === b.image && a.status === "done" && b.status === "done");
  }
  $("btn-diff-scans").classList.toggle("hidden", !canDiff);
}

async function compareSelectedScans() {
  const ids = [...selectedScanIds];
  if (ids.length !== 2) { alert(t("diff_need_two")); return; }
  await showDiff(ids[0], ids[1]);
}

async function showDiff(a, b) {
  try {
    diffData = await (await api(`/api/scans/diff?a=${a}&b=${b}`)).json();
    diffTab = "new";
    $("diff-modal").classList.remove("hidden");
    renderDiff();
  } catch (e) { alert(e.message); }
}

function closeDiffModal() {
  $("diff-modal").classList.add("hidden");
  diffData = null;
}

function renderDiff() {
  if (!diffData) return;
  const img = diffData.to?.image || diffData.from?.image || "";
  $("diff-title").textContent = `${t("diff_title", { img })} · ${t("diff_from_to", { a: diffData.from.id, b: diffData.to.id })}`;
  const s = diffData.summary || {};
  const cards = [
    ["new", t("diff_new"), s.new, "text-red-400", s.new_severities],
    ["fixed", t("diff_fixed"), s.fixed, "text-emerald-400", s.fixed_severities],
    ["unchanged", t("diff_unchanged"), s.unchanged, "text-slate-300", null],
  ];
  $("diff-summary").innerHTML = cards.map(([k, lab, n, col]) => `
    <button onclick="diffTab='${k}';renderDiff()" class="rounded-2xl p-4 border ${diffTab === k ? "border-sky-400 bg-slate-700/50" : "border-slate-700 bg-slate-900/40"} text-left">
      <div class="text-xs text-slate-400">${lab}</div>
      <div class="text-2xl font-bold ${col}">${fmtNum(n)}</div>
    </button>`).join("");
  $("diff-tabs").innerHTML = cards.map(([k, lab]) => `
    <button onclick="diffTab='${k}';renderDiff()" class="px-3 py-1.5 rounded-lg text-sm ${diffTab === k ? "bg-sky-600 text-white" : "bg-slate-700 text-slate-300"}">${lab}</button>
  `).join("");
  const items = diffData[diffTab] || [];
  if (!items.length) {
    $("diff-body").innerHTML = `<p class="text-center text-slate-500 py-8">${t("diff_empty")}</p>`;
    return;
  }
  $("diff-body").innerHTML = `
    <table class="w-full text-xs">
      <thead class="text-slate-400 border-b border-slate-700">
        <tr>
          <th class="text-left py-2">Sev</th><th class="text-left">CVE</th>
          <th class="text-left">CVSS</th><th class="text-left">EPSS</th><th class="text-left">KEV</th>
          <th class="text-left">${t("col_pkg")}</th><th class="text-left">${t("fixed_in")}</th>
          <th class="text-left">${t("col_details")}</th>
        </tr>
      </thead>
      <tbody>
        ${items.map(v => `
          <tr class="border-b border-slate-700/40">
            <td class="py-1.5"><span class="${SEV[v.severity] || SEV.UNKNOWN} px-2 py-0.5 rounded-full">${esc(v.severity)}</span></td>
            <td class="text-sky-400 font-mono">${esc(v.id)}</td>
            <td>${v.cvss ?? "—"}</td>
            <td>${epssCell(v)}</td>
            <td>${kevBadge(v)}</td>
            <td class="font-mono">${esc(v.pkg)} <span class="text-slate-500">${esc(v.installed || "")}</span></td>
            <td class="font-mono text-emerald-400">${esc(v.fixed_version || "—")}</td>
            <td class="text-slate-300">${esc((v.title || "").slice(0, 100))}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

async function bulkDeleteScans() {
  if (!canManage || selectedScanIds.size === 0) return;
  if (!confirm(t("confirm_del_n", { n: selectedScanIds.size }))) return;
  try {
    await api("/api/scans/bulk-delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: [...selectedScanIds] }),
    });
    selectedScanIds.clear();
    loadScans();
  } catch (e) { alert(e.message); }
}

async function bulkExportZip() {
  if (selectedScanIds.size === 0) return;
  try {
    const res = await api("/api/scans/export/zip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: [...selectedScanIds] }),
    });
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "trivy_scans_export.zip";
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { alert(e.message); }
}

function statusBadge(s) {
  const map = {
    pending: [t("st_pending"), "text-slate-400"],
    running: [t("st_running"), "text-sky-400 animate-pulse"],
    done: [t("st_done"), "text-emerald-400"],
    error: [t("st_error"), "text-red-400"],
  };
  const [label, cls] = map[s.status] || [s.status, "text-slate-400"];
  return `<span class="${cls}" ${s.error ? `title="${esc(s.error)}"` : ""}>${label}</span>`;
}

function sevBadges(s) {
  return ["critical", "high", "medium", "low"].filter(k => s[k] > 0)
    .map(k => `<span class="${SEV[k.toUpperCase()]} text-xs px-2 py-0.5 rounded-full mr-1">${k[0].toUpperCase()} ${s[k]}</span>`)
    .join("") || `<span class="text-emerald-400 text-xs">${t("clean")}</span>`;
}

function secretsBadge(s) {
  if (!s.secrets_enabled) return `<span class="text-slate-600 text-xs">${t("secrets_off")}</span>`;
  if (s.status !== "done") return "—";
  return s.secrets_found > 0
    ? `<span class="bg-rose-600 text-xs px-2 py-0.5 rounded-full">🔑 ${s.secrets_found}</span>`
    : `<span class="text-emerald-400 text-xs">${t("secrets_none")}</span>`;
}

function epssCell(v) {
  const e = v.epss;
  if (e == null || e === undefined) return `<span class="text-slate-600">—</span>`;
  const pct = (e * 100).toFixed(1) + "%";
  const color = e >= 0.1 ? "text-red-400" : e >= 0.01 ? "text-amber-400" : "text-slate-400";
  return `<span class="${color} font-mono">${pct}</span>`;
}

function kevBadge(v) {
  if (!v.kev) return `<span class="text-slate-600">—</span>`;
  const tip = [v.kev_name, v.ransomware].filter(Boolean).join(" · ");
  return `<span class="bg-red-700 text-xs px-1.5 py-0.5 rounded font-semibold" title="${esc(tip)}">KEV</span>`;
}

function getCvss(v) {
  const src = v.CVSS || {};
  for (const s of ["nvd", "redhat", "ghsa", "bitnami"]) {
    if (src[s]?.V3Score != null) return src[s].V3Score;
  }
  for (const k in src) {
    if (src[k].V3Score != null) return src[k].V3Score;
    if (src[k].V2Score != null) return src[k].V2Score;
  }
  return null;
}

async function showDetail(id) {
  currentScanId = id;
  const data = await (await api(`/api/scans/${id}`)).json();
  const report = JSON.parse(data.report || "{}");
  const extra = data.epss || {};
  currentVulns = (report.Results || []).flatMap(r =>
    (r.Vulnerabilities || []).map(v => {
      const inf = extra[v.VulnerabilityID] || {};
      return {
        ...v, Target: r.Target,
        epss: inf.epss, percentile: inf.percentile, kev: inf.kev,
        ransomware: inf.ransomware, kev_name: inf.kev_name,
        vendor: inf.vendor, product: inf.product,
        date_added: inf.date_added, due_date: inf.due_date,
      };
    }));
  currentSecrets = (report.Results || []).flatMap(r =>
    (r.Secrets || []).map(s => ({ ...s, Target: r.Target })));
  currentScanMeta = data;
  vulnSort = "exploit";
  vulnFilter = "all";
  vulnQuery = "";
  $("modal-title").textContent = data.image;
  $("modal").classList.remove("hidden");
  renderScanDetailBody();
}

function closeModal() { $("modal").classList.add("hidden"); currentScanMeta = null; }

function sortCurrentVulns() {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
  currentVulns.sort((a, b) => {
    if (vulnSort === "pkg") return (a.PkgName || "").localeCompare(b.PkgName || "") || (a.VulnerabilityID || "").localeCompare(b.VulnerabilityID || "");
    if (vulnSort === "epss") return (b.epss || 0) - (a.epss || 0) || order[a.Severity] - order[b.Severity];
    if (vulnSort === "severity") return order[a.Severity] - order[b.Severity] || (b.epss || 0) - (a.epss || 0);
    const kev = (b.kev ? 1 : 0) - (a.kev ? 1 : 0);
    if (kev) return kev;
    const ep = (b.epss || 0) - (a.epss || 0);
    if (ep) return ep;
    return order[a.Severity] - order[b.Severity];
  });
}

function filteredVulns() {
  const q = (vulnQuery || "").trim().toLowerCase();
  return currentVulns.filter(v => {
    if (vulnFilter === "kev" && !v.kev) return false;
    if (vulnFilter === "epss" && !(v.epss >= 0.01)) return false;
    if (!q) return true;
    return (v.VulnerabilityID || "").toLowerCase().includes(q)
      || (v.PkgName || "").toLowerCase().includes(q)
      || (v.Title || "").toLowerCase().includes(q);
  });
}

function renderScanDetailBody() {
  if (!currentScanMeta) return;
  sortCurrentVulns();
  const list = filteredVulns();
  const vulnsHtml = currentVulns.length ? `
    <div class="flex flex-wrap gap-2 items-center mb-3">
      <label class="text-xs text-slate-400">${t("sort_by")}
        <select onchange="vulnSort=this.value;renderScanDetailBody()" class="ml-1 px-2 py-1 rounded bg-slate-700 border border-slate-600 text-xs">
          <option value="exploit" ${vulnSort === "exploit" ? "selected" : ""}>${t("sort_exploit")}</option>
          <option value="severity" ${vulnSort === "severity" ? "selected" : ""}>${t("sort_severity")}</option>
          <option value="epss" ${vulnSort === "epss" ? "selected" : ""}>${t("sort_epss")}</option>
          <option value="pkg" ${vulnSort === "pkg" ? "selected" : ""}>${t("sort_pkg")}</option>
        </select>
      </label>
      <button onclick="vulnFilter='all';renderScanDetailBody()" class="px-2 py-1 rounded-full text-xs ${vulnFilter === "all" ? "bg-sky-600" : "bg-slate-700"}">${t("filter_all")}</button>
      <button onclick="vulnFilter='kev';renderScanDetailBody()" class="px-2 py-1 rounded-full text-xs ${vulnFilter === "kev" ? "bg-red-700" : "bg-slate-700"}">${t("filter_kev")}</button>
      <button onclick="vulnFilter='epss';renderScanDetailBody()" class="px-2 py-1 rounded-full text-xs ${vulnFilter === "epss" ? "bg-amber-700" : "bg-slate-700"}">${t("filter_epss")}</button>
      <input value="${esc(vulnQuery)}" oninput="vulnQuery=this.value;renderScanDetailBody()" placeholder="${t("filter_cve")}"
             class="px-2 py-1 rounded bg-slate-700 border border-slate-600 text-xs w-44">
      <span class="text-xs text-slate-500">${list.length}/${currentVulns.length}</span>
    </div>
    <table class="w-full text-xs mb-2">
      <thead class="text-slate-400 border-b border-slate-700">
        <tr><th class="text-left py-2">Severity</th><th class="text-left">CVE</th>
        <th class="text-left">CVSS</th><th class="text-left">EPSS</th><th class="text-left">KEV</th>
        <th class="text-left">CWE</th>
        <th class="text-left">${t("col_pkg")}</th><th class="text-left">${t("col_details")}</th></tr>
      </thead><tbody>
      ${list.map(v => {
        const i = currentVulns.indexOf(v);
        return `<tr class="border-b border-slate-700/40 hover:bg-slate-700/40 cursor-pointer" onclick="showVulnDetail(${i})">
        <td class="py-1.5"><span class="${SEV[v.Severity] || SEV.UNKNOWN} px-2 py-0.5 rounded-full">${v.Severity}</span></td>
        <td class="text-sky-400">${esc(v.VulnerabilityID)}</td>
        <td>${getCvss(v) ?? "—"}</td>
        <td>${epssCell(v)}</td>
        <td>${kevBadge(v)}</td>
        <td class="text-slate-400">${esc((v.CweIDs || []).join(", ") || "—")}</td>
        <td class="font-mono">${esc(v.PkgName)} <span class="text-slate-500">${esc(v.InstalledVersion || "")}</span></td>
        <td class="text-slate-300">${esc((v.Title || "").slice(0, 90))}</td>
      </tr>`;
      }).join("")}
      </tbody></table>`
    : `<p class="text-emerald-400 text-center py-4">${t("no_vulns_bang")}</p>`;

  let secretsHtml = "";
  if (currentScanMeta.secrets_enabled) {
    secretsHtml = `
      <h4 class="font-semibold mb-2 mt-4 border-t border-slate-700 pt-4">${t("secrets_found")} ${currentSecrets.length ? `(${currentSecrets.length})` : ""}</h4>
      ${currentSecrets.length ? `
      <table class="w-full text-xs">
        <thead class="text-slate-400 border-b border-slate-700">
          <tr><th class="text-left py-2">Severity</th><th class="text-left">${t("col_details")}</th>
          <th class="text-left">${t("col_image")}</th><th class="text-left">${t("col_details")}</th></tr>
        </thead><tbody>
        ${currentSecrets.map(s => `<tr class="border-b border-slate-700/40">
          <td class="py-1.5"><span class="${SEV[s.Severity] || SEV.UNKNOWN} px-2 py-0.5 rounded-full">${esc(s.Severity || "UNKNOWN")}</span></td>
          <td>${esc(s.Category || "—")}</td>
          <td class="text-slate-300">${esc(s.Title || "")}</td>
          <td class="font-mono text-slate-400">${esc(s.Target || "")}:${s.StartLine ?? "—"}</td>
        </tr>`).join("")}
        </tbody></table>`
        : `<p class="text-emerald-400 text-center py-4">${t("no_secrets")}</p>`}
    `;
  }
  $("modal-body").innerHTML = vulnsHtml + secretsHtml;
}

function showVulnDetail(i) {
  const v = currentVulns[i];
  const cvss = v.CVSS || {};
  const cvssRows = Object.entries(cvss).map(([src, val]) => `
    <div class="flex justify-between border-b border-slate-700/40 py-1">
      <span class="text-slate-400">${esc(src)}</span>
      <span>${val.V3Score != null ? "V3: " + val.V3Score : ""} ${val.V2Score != null ? "V2: " + val.V2Score : ""}
      <span class="text-slate-500 text-xs block">${esc(val.V3Vector || val.V2Vector || "")}</span></span>
    </div>`).join("") || `<p class="text-slate-500">${t("no_cvss")}</p>`;
  const refs = (v.References || []).slice(0, 15).map(r =>
    `<a href="${esc(r)}" target="_blank" rel="noopener" class="text-sky-400 hover:underline block truncate">${esc(r)}</a>`).join("");
  const epssLine = v.epss != null
    ? `${(v.epss * 100).toFixed(2)}% · ${t("percentile")} ${v.percentile != null ? (v.percentile * 100).toFixed(1) + "%" : "—"}`
    : "—";
  const kevLine = v.kev
    ? `${v.kev_name || "KEV"}${v.vendor ? " · " + v.vendor : ""}${v.product ? " / " + v.product : ""}${v.date_added ? " · " + t("added") + " " + v.date_added : ""}${v.due_date ? " · " + t("due") + " " + v.due_date : ""}${v.ransomware ? " · " + t("ransomware") + ": " + v.ransomware : ""}`
    : "—";
  $("vuln-title").innerHTML = `<span class="${SEV[v.Severity] || SEV.UNKNOWN} px-2 py-0.5 rounded-full mr-2">${v.Severity}</span>${esc(v.VulnerabilityID)} ${v.kev ? kevBadge(v) : ""}`;
  $("vuln-body").innerHTML = `
    <div><span class="text-slate-400">${t("package")}:</span> <span class="font-mono">${esc(v.PkgName)} ${esc(v.InstalledVersion || "")}</span></div>
    <div><span class="text-slate-400">${t("fixed_in")}:</span> <span class="font-mono text-emerald-400">${esc(v.FixedVersion || t("none"))}</span></div>
    <div><span class="text-slate-400">CWE:</span> ${(v.CweIDs || []).map(c => `<a class="text-sky-400 hover:underline" target="_blank" rel="noopener" href="https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html">${esc(c)}</a>`).join(", ") || "—"}</div>
    <div><span class="text-slate-400">${t("epss")}:</span> <span class="font-mono">${epssLine}</span></div>
    <div><span class="text-slate-400">${t("kev_catalog")}:</span> ${esc(kevLine)}</div>
    <div><span class="text-slate-400">${t("published")}:</span> ${v.PublishedDate ? new Date(v.PublishedDate).toLocaleDateString(lang === "en" ? "en-GB" : "pl-PL") : "—"}
      &nbsp;|&nbsp; <span class="text-slate-400">${t("modified")}:</span> ${v.LastModifiedDate ? new Date(v.LastModifiedDate).toLocaleDateString(lang === "en" ? "en-GB" : "pl-PL") : "—"}</div>
    <div class="pt-2 border-t border-slate-700">
      <div class="text-slate-400 mb-1">CVSS:</div>${cvssRows}
    </div>
    <div class="pt-2 border-t border-slate-700">
      <div class="text-slate-400 mb-1">${t("description")}:</div>
      <p class="text-slate-200 leading-relaxed">${esc(v.Description || t("no_description"))}</p>
    </div>
    <div class="pt-2 border-t border-slate-700">
      <div class="text-slate-400 mb-1">${t("references")}:</div>
      ${refs || `<p class="text-slate-500">${t("no_refs")}</p>`}
    </div>`;
  $("vuln-modal").classList.remove("hidden");
}
function closeVulnModal() { $("vuln-modal").classList.add("hidden"); }

async function showScanLogs(id) {
  $("logs-title").textContent = t("logs_scan", { id });
  $("logs-modal").classList.remove("hidden");
  await refreshScanLogs(id);
  clearInterval(logsPollTimer);
  logsPollTimer = setInterval(async () => {
    const stillOpen = !$("logs-modal").classList.contains("hidden");
    if (!stillOpen) { clearInterval(logsPollTimer); return; }
    const done = await refreshScanLogs(id);
    if (done) clearInterval(logsPollTimer);
  }, 2000);
}
async function refreshScanLogs(id) {
  const data = await (await api(`/api/scans/${id}/logs`)).json();
  $("logs-body").textContent = data.logs || t("no_logs");
  $("logs-body").scrollTop = $("logs-body").scrollHeight;
  return data.status !== "running" && data.status !== "pending";
}
function closeLogsModal() { $("logs-modal").classList.add("hidden"); clearInterval(logsPollTimer); }

let containersCache = [];
let selectedImages = new Set();

async function loadContainers() {
  containersCache = await (await api("/api/containers")).json();
  selectedImages.clear();
  renderContainerStatusFilters();
  renderContainers();
  updateSelectedBar();
}

function renderContainerStatusFilters() {
  const box = $("container-status-filters");
  if (!box) return;
  const items = [
    ["all", t("filter_all")],
    ["running", t("ct_running")],
    ["exited", t("ct_exited")],
    ["other", t("ct_other")],
  ];
  box.innerHTML = items.map(([st, lab]) => `
    <button onclick="setContainerStatusFilter('${st}')"
            class="px-3 py-1 rounded-full text-xs ${containerStatusFilter === st ? "bg-sky-600 text-white" : "bg-slate-700 text-slate-300 hover:bg-slate-600"}">${lab}</button>
  `).join("");
}

function setContainerStatusFilter(st) {
  containerStatusFilter = st;
  renderContainerStatusFilters();
  renderContainers();
}

function containerStatusClass(st) {
  if (st === "running") return "bg-emerald-700/40 text-emerald-300";
  if (st === "exited") return "bg-slate-700 text-slate-400";
  if (st === "paused") return "bg-amber-700/40 text-amber-300";
  return "bg-slate-700 text-slate-300";
}

function renderContainers() {
  const q = ($("container-filter")?.value || "").trim().toLowerCase();
  let rows = containersCache.slice();
  if (q) rows = rows.filter(c =>
    (c.name || "").toLowerCase().includes(q)
    || (c.image || "").toLowerCase().includes(q)
    || (c.stack || "").toLowerCase().includes(q));
  if (containerStatusFilter === "running") rows = rows.filter(c => c.status === "running");
  else if (containerStatusFilter === "exited") rows = rows.filter(c => c.status === "exited");
  else if (containerStatusFilter === "other") rows = rows.filter(c => c.status !== "running" && c.status !== "exited");
  const running = containersCache.filter(c => c.status === "running").length;
  const stacks = new Set(containersCache.map(c => c.stack).filter(s => s && s !== "—")).size;
  $("container-kpis").innerHTML = [
    kpiMini(t("c_total"), fmtNum(containersCache.length), "text-sky-400"),
    kpiMini(t("c_running"), fmtNum(running), "text-emerald-400"),
    kpiMini(t("c_other"), fmtNum(containersCache.length - running), "text-slate-300"),
    kpiMini(t("c_stacks"), fmtNum(stacks)),
  ].join("");
  const cols = canManage ? 11 : 10;
  $("container-table").innerHTML = rows.map(c => `
    <tr class="border-b border-slate-700/50 hover:bg-slate-700/30">
      ${canManage ? `<td class="py-2 px-2">
        <input type="checkbox" class="container-checkbox" data-image="${esc(c.image)}"
               onchange="onContainerCheck(this)" ${selectedImages.has(c.image) ? "checked" : ""}>
      </td>` : ""}
      <td class="px-2 font-mono text-xs">${esc(c.name)}</td>
      <td class="px-2 font-mono text-xs text-slate-400">${esc(c.image)}</td>
      <td class="px-2 text-xs">${esc(c.stack)}</td>
      <td class="px-2"><span class="text-xs px-2 py-0.5 rounded-full ${containerStatusClass(c.status)}">${esc(c.status)}</span></td>
      <td class="px-2 text-xs text-slate-400 whitespace-nowrap">${formatDate(c.created)}</td>
      <td class="px-2 text-xs font-mono">${esc(c.ip_address)}</td>
      <td class="px-2 text-xs font-mono">${esc(c.ports)}</td>
      <td class="px-2 text-xs font-mono" id="size-${c.id}">
        <button onclick="loadContainerSize('${c.id}')" class="text-sky-400 hover:underline">${t("check_size")}</button>
      </td>
      <td class="px-2 text-xs">${esc(c.ownership)}</td>
      <td class="px-2 text-right whitespace-nowrap">
        <button onclick="showContainerLogs('${c.id}','${esc(c.name)}')" title="${t("scan_logs")}" class="hover:text-sky-400">📜</button>
        ${canManage ? `<button onclick="scanImageNow('${esc(c.image)}')" title="${t("scan_btn")}" class="hover:text-emerald-400 ml-2">🔍</button>` : ""}
      </td>
    </tr>`).join("") || `<tr><td colspan="${cols}" class="py-6 text-center text-slate-500">${containersCache.length ? t("no_filter") : t("no_containers")}</td></tr>`;
}

function formatDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(lang === "en" ? "en-GB" : "pl-PL"); } catch { return iso; }
}

async function loadContainerSize(id) {
  const cell = $(`size-${id}`);
  cell.innerHTML = `<span class="text-slate-500">${t("sizing")}</span>`;
  try {
    const data = await (await api(`/api/containers/${id}/size`)).json();
    cell.textContent = data.size_root_fs
      ? `${data.size_rw} (virtual ${data.size_root_fs})`
      : data.size_rw;
  } catch (e) {
    cell.innerHTML = `<span class="text-red-400">${t("size_err")}</span>`;
  }
}

function onContainerCheck(el) {
  const image = el.dataset.image;
  if (el.checked) selectedImages.add(image); else selectedImages.delete(image);
  updateSelectedBar();
}

function toggleSelectAllContainers(headerCheckbox) {
  document.querySelectorAll(".container-checkbox").forEach(cb => {
    cb.checked = headerCheckbox.checked;
    onContainerCheck(cb);
  });
}

function updateSelectedBar() {
  const n = selectedImages.size;
  if ($("selected-count")) $("selected-count").textContent = n > 0 ? `${t("selected")}: ${n}` : "";
  if ($("btn-scan-selected")) {
    $("btn-scan-selected").classList.toggle("hidden", n === 0 || !canManage);
    $("btn-scan-selected").textContent = n > 0 ? `${t("scan_selected")} (${n})` : t("scan_selected");
  }
}

async function scanImageNow(image) {
  if (!canManage) return;
  const secretsOn = !!(
    ($("secrets-checkbox-containers") && !$("tab-containers").classList.contains("hidden") && $("secrets-checkbox-containers").checked)
    || ($("scan-secrets-checkbox") && $("scan-secrets-checkbox").checked)
  );
  try {
    await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        image,
        registry_user: null,
        registry_password: null,
        scan_secrets: secretsOn,
      }),
    });
    showTab("scans");
    loadScans();
  } catch (e) { alert(t("scan_err", { img: image, err: e.message })); }
}

async function scanSelectedContainers() {
  if (!canManage) return;
  const images = [...selectedImages];
  if (images.length === 0) return;
  if (!confirm(t("confirm_scan_n", { n: images.length }))) return;
  const secretsOn = $("secrets-checkbox-containers").checked;
  let ok = 0, failed = [];
  for (const image of images) {
    try {
      await api("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image, registry_user: null, registry_password: null, scan_secrets: secretsOn }),
      });
      ok++;
    } catch (e) {
      failed.push(image);
    }
  }
  selectedImages.clear();
  renderContainers();
  updateSelectedBar();
  showTab("scans");
  loadScans();
  if (failed.length) {
    alert(`${t("scan_queued", { ok })}\n${t("scan_fail", { list: failed.join(", ") })}`);
  }
}

async function showContainerLogs(id, name) {
  $("logs-title").textContent = t("logs_container", { name });
  $("logs-modal").classList.remove("hidden");
  clearInterval(logsPollTimer);
  const data = await (await api(`/api/containers/${id}/logs?tail=300`)).json();
  $("logs-body").textContent = data.logs || t("no_logs");
}

const CHART_SEV = {
  critical: "#dc2626", high: "#ea580c", medium: "#d97706",
  low: "#65a30d", unknown: "#64748b",
};

function fmtNum(n) { return Number(n || 0).toLocaleString(lang === "en" ? "en-GB" : "pl-PL"); }

function initChartDefaults() {
  if (statsChartDefaults || typeof Chart === "undefined") return;
  Chart.defaults.color = "#94a3b8";
  Chart.defaults.borderColor = "#334155";
  Chart.defaults.font.family = "ui-sans-serif, system-ui, sans-serif";
  statsChartDefaults = true;
}

function upsertChart(id, config) {
  if (statsCharts[id]) { statsCharts[id].destroy(); delete statsCharts[id]; }
  const el = $(id);
  if (!el || typeof Chart === "undefined") return;
  statsCharts[id] = new Chart(el, config);
}

function setChartEmpty(canvasId, emptyId, empty) {
  const c = $(canvasId), e = $(emptyId);
  if (c) c.style.display = empty ? "none" : "block";
  if (e) e.classList.toggle("hidden", !empty);
  if (empty && statsCharts[canvasId]) {
    statsCharts[canvasId].destroy();
    delete statsCharts[canvasId];
  }
}

function kpiCard(label, value, sub, color) {
  return `<div class="bg-slate-800 rounded-2xl p-4 border border-slate-700">
    <div class="text-xs text-slate-400 mb-1">${label}</div>
    <div class="text-2xl font-bold ${color || "text-slate-100"}">${value}</div>
    ${sub ? `<div class="text-xs text-slate-500 mt-1">${sub}</div>` : ""}
  </div>`;
}

function markRangeButtons() {
  document.querySelectorAll(".range-btn").forEach(b => {
    const active = parseInt(b.dataset.days, 10) === statsDays;
    b.classList.toggle("bg-sky-600", active);
    b.classList.toggle("text-white", active);
    b.classList.toggle("bg-slate-700", !active);
  });
}

async function loadStats(days) {
  if (days !== undefined) statsDays = days;
  markRangeButtons();
  $("stats-loading").classList.remove("hidden");
  $("stats-empty").classList.add("hidden");
  $("stats-content").classList.add("hidden");
  $("stats-loading").textContent = t("stats_loading");
  try {
    const data = await (await api(`/api/stats?days=${statsDays}`)).json();
    statsCache = data;
    $("stats-loading").classList.add("hidden");
    if (!data.kpis.scans_total) {
      $("stats-empty").classList.remove("hidden");
      $("stats-period-label").textContent = periodLabel(data.period_days);
      return;
    }
    $("stats-content").classList.remove("hidden");
    $("stats-period-label").textContent = periodLabel(data.period_days);
    renderKpis(data);
    renderStatsTables(data);
    requestAnimationFrame(() => renderStatsCharts(data));
  } catch (e) {
    $("stats-loading").textContent = t("error") + ": " + e.message;
  }
}

function periodLabel(days) {
  if (!days) return t("period_all");
  return t("period_days", { n: days });
}

function renderKpis(data) {
  const k = data.kpis, p = data.posture;
  $("stats-kpis").innerHTML = [
    kpiCard(t("kpi_scans"), fmtNum(k.scans_total),
      t("kpi_scan_sub", { e: k.scans_error, r: k.success_rate }), "text-sky-400"),
    kpiCard(t("kpi_images_n"), fmtNum(k.images_unique),
      t("kpi_images_sub", { n: fmtNum(p.images) })),
    kpiCard(t("kpi_clean"), fmtNum(p.clean_images),
      t("kpi_clean_sub", { n: fmtNum(k.clean_scans) }), "text-emerald-400"),
    kpiCard("CRITICAL", fmtNum(p.critical),
      t("kpi_crit_sub", { n: k.avg_critical }), "text-red-400"),
    kpiCard("HIGH", fmtNum(p.high),
      t("kpi_crit_sub", { n: k.avg_high }), "text-orange-400"),
    kpiCard("MEDIUM", fmtNum(p.medium), t("kpi_sum_last"), "text-amber-400"),
    kpiCard(t("kpi_secrets"), fmtNum(p.secrets_found),
      t("kpi_secrets_sub", { n: fmtNum(k.secrets_scans) }), "text-rose-400"),
    kpiCard(t("kpi_risk"), fmtNum(p.risk_score),
      t("kpi_risk_sub"), "text-slate-100"),
  ].join("");
}

function stackedSev(labels, rows, indexAxis = "x") {
  const isH = indexAxis === "y";
  return {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "CRITICAL", data: rows.map(r => r.critical || 0), backgroundColor: CHART_SEV.critical, stack: "s" },
        { label: "HIGH",     data: rows.map(r => r.high || 0),     backgroundColor: CHART_SEV.high,     stack: "s" },
        { label: "MEDIUM",   data: rows.map(r => r.medium || 0),   backgroundColor: CHART_SEV.medium,   stack: "s" },
        { label: "LOW",      data: rows.map(r => r.low || 0),      backgroundColor: CHART_SEV.low,      stack: "s" },
      ],
    },
    options: {
      indexAxis,
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { boxWidth: 12 } },
        tooltip: {
          callbacks: {
            title: items => {
              const i = items[0]?.dataIndex ?? 0;
              return rows[i]?.image || labels[i] || "";
            },
          },
        },
      },
      scales: {
        x: {
          stacked: true, beginAtZero: true, grid: { color: "#1e293b" },
          ticks: isH ? { precision: 0 } : { maxRotation: 45, autoSkip: true, maxTicksLimit: 16 },
        },
        y: {
          stacked: true, beginAtZero: true, grid: { color: "#1e293b" },
          ticks: isH ? {
            precision: 0,
            callback(val) {
              const l = this.getLabelForValue(val);
              return l.length > 34 ? l.slice(0, 32) + "…" : l;
            },
          } : { precision: 0 },
        },
      },
    },
  };
}

function renderStatsCharts(data) {
  initChartDefaults();
  const tl = data.timeline || [];
  const tlHas = tl.some(d => d.scans > 0);
  setChartEmpty("chart-timeline", "chart-timeline-empty", !tlHas);
  if (tlHas) {
    const cfg = stackedSev(tl.map(d => d.date.slice(5)), tl);
    cfg.data.datasets.push({
      type: "line",
      label: t("chart_scans"),
      data: tl.map(d => d.scans),
      borderColor: "#38bdf8",
      backgroundColor: "transparent",
      tension: 0.25,
      pointRadius: 2,
      stack: "none",
      yAxisID: "y2",
      order: 0,
    });
    cfg.options.scales.y2 = {
      position: "right", beginAtZero: true, grid: { drawOnChartArea: false },
      ticks: { precision: 0, color: "#38bdf8" },
    };
    upsertChart("chart-timeline", cfg);
  }

  const p = data.posture;
  const slices = [
    ["CRITICAL", p.critical, CHART_SEV.critical],
    ["HIGH", p.high, CHART_SEV.high],
    ["MEDIUM", p.medium, CHART_SEV.medium],
    ["LOW", p.low, CHART_SEV.low],
    ["UNKNOWN", p.unknown, CHART_SEV.unknown],
  ].filter(x => x[1] > 0);
  setChartEmpty("chart-posture", "chart-posture-empty", !slices.length);
  if (slices.length) {
    upsertChart("chart-posture", {
      type: "doughnut",
      data: {
        labels: slices.map(s => s[0]),
        datasets: [{ data: slices.map(s => s[1]), backgroundColor: slices.map(s => s[2]), borderWidth: 0 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "62%",
        plugins: { legend: { position: "bottom", labels: { boxWidth: 12, padding: 14 } } },
      },
    });
  }

  const vulns = data.top_vulnerable || [];
  setChartEmpty("chart-top-vuln", "chart-top-vuln-empty", !vulns.length);
  if (vulns.length) {
    const labels = vulns.map(v => v.image).slice().reverse();
    const rows = vulns.slice().reverse();
    upsertChart("chart-top-vuln", stackedSev(labels, rows, "y"));
  }

  const ms = data.most_scanned || [];
  setChartEmpty("chart-most-scanned", "chart-most-scanned-empty", !ms.length);
  if (ms.length) {
    const rows = ms.slice().reverse();
    upsertChart("chart-most-scanned", {
      type: "bar",
      data: {
        labels: rows.map(r => r.image),
        datasets: [{ label: t("col_scans"), data: rows.map(r => r.scans), backgroundColor: "#0ea5e9" }],
      },
      options: {
        indexAxis: "y", responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, grid: { color: "#1e293b" }, ticks: { precision: 0 } },
          y: {
            grid: { color: "#1e293b" },
            ticks: {
              callback(val) {
                const l = this.getLabelForValue(val);
                return l.length > 34 ? l.slice(0, 32) + "…" : l;
              },
            },
          },
        },
      },
    });
  }

  const trends = data.image_trends || [];
  $("trends-card").classList.toggle("hidden", !trends.length);
  if (trends.length) {
    const palette = ["#38bdf8", "#34d399", "#fbbf24", "#f87171", "#c084fc", "#fb7185"];
    const allTs = [...new Set(trends.flatMap(tr => tr.points.map(p => p.t.slice(0, 10))))].sort();
    upsertChart("chart-trends", {
      type: "line",
      data: {
        labels: allTs.map(d => d.slice(5)),
        datasets: trends.map((tr, i) => {
          const byDay = {};
          tr.points.forEach(p => { byDay[p.t.slice(0, 10)] = (p.c || 0) + (p.h || 0); });
          return {
            label: tr.image.length > 28 ? tr.image.slice(0, 26) + "…" : tr.image,
            data: allTs.map(d => byDay[d] ?? null),
            borderColor: palette[i % palette.length],
            backgroundColor: "transparent",
            tension: 0.25, pointRadius: 3, spanGaps: true,
          };
        }),
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "nearest", intersect: false },
        plugins: { legend: { labels: { boxWidth: 12 } } },
        scales: {
          x: { grid: { color: "#1e293b" } },
          y: { beginAtZero: true, grid: { color: "#1e293b" }, ticks: { precision: 0 } },
        },
      },
    });
  }
}

function trendPair(trend) {
  const map = {
    down: ["trend_down", "text-emerald-400"],
    up: ["trend_up", "text-red-400"],
    stable: ["trend_stable", "text-slate-400"],
    new: ["trend_new", "text-sky-400"],
  };
  const [k, cls] = map[trend] || map.new;
  return [t(k), cls];
}

function renderStatsTables(data) {
  $("cve-sample-note").textContent = data.cves_sampled_scans
    ? t("cve_sample", { n: data.cves_sampled_scans })
    : "";
  $("stats-cve-table").innerHTML = (data.top_cves || []).map(v => `
    <tr class="border-b border-slate-700/40">
      <td class="py-1.5"><span class="${SEV[v.severity] || SEV.UNKNOWN} px-2 py-0.5 rounded-full">${esc(v.severity)}</span></td>
      <td><a class="text-sky-400 hover:underline font-mono" target="_blank" rel="noopener"
            href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}">${esc(v.id)}</a></td>
      <td>${epssCell(v)}</td>
      <td>${kevBadge(v)}</td>
      <td class="font-mono text-slate-400">${esc(v.pkg)}</td>
      <td class="text-right">${fmtNum(v.count)}</td>
      <td class="text-right">${fmtNum(v.images)}</td>
    </tr>`).join("") || `<tr><td colspan="7" class="py-6 text-center text-slate-500">${t("no_data")}</td></tr>`;

  $("stats-pkg-table").innerHTML = (data.top_packages || []).map(p => `
    <tr class="border-b border-slate-700/40">
      <td class="py-1.5 font-mono">${esc(p.name)}</td>
      <td class="text-red-400">${p.critical || ""}</td>
      <td class="text-orange-400">${p.high || ""}</td>
      <td class="text-amber-400">${p.medium || ""}</td>
      <td class="text-right">${fmtNum(p.count)}</td>
    </tr>`).join("") || `<tr><td colspan="5" class="py-6 text-center text-slate-500">${t("no_data")}</td></tr>`;

  $("stats-image-table").innerHTML = (data.top_vulnerable || []).map(v => {
    const [lab, cls] = trendPair(v.trend);
    return `<tr class="border-b border-slate-700/40 hover:bg-slate-700/30">
      <td class="py-2 px-2 font-mono text-xs">
        <button class="text-sky-400 hover:underline text-left" data-image="${esc(v.image)}"
                onclick="showImageHistory(this.dataset.image)">${esc(v.image)}</button>
      </td>
      <td class="px-2 ${cls} text-xs whitespace-nowrap">${lab}</td>
      <td class="px-2">${sevBadges(v)}</td>
      <td class="px-2 text-slate-400">${fmtNum(v.scans)}</td>
      <td class="px-2 text-right whitespace-nowrap">
        <button onclick="showDetail(${v.last_id})" title="${t("last_scan")}" class="hover:text-sky-400">🔎</button>
        <button data-image="${esc(v.image)}" onclick="showImageHistory(this.dataset.image)"
                title="${t("image_hist")}" class="hover:text-sky-400 ml-1">📈</button>
      </td>
    </tr>`;
  }).join("") || `<tr><td colspan="5" class="py-6 text-center text-slate-500">${t("no_data")}</td></tr>`;
}

async function showImageHistory(image) {
  $("image-history-card").classList.remove("hidden");
  $("image-history-title").textContent = t("history") + ": " + image;
  $("image-history-table").innerHTML = `<tr><td colspan="5" class="py-4 text-slate-500">${t("stats_loading")}</td></tr>`;
  $("image-history-card").scrollIntoView({ behavior: "smooth", block: "start" });
  try {
    const data = await (await api(`/api/stats/image?name=${encodeURIComponent(image)}`)).json();
    const done = data.scans.filter(s => s.status === "done");
    historyDoneIds = done.map(s => s.id);
    $("btn-hist-diff").classList.toggle("hidden", historyDoneIds.length < 2);
    initChartDefaults();
    upsertChart("chart-image-history", {
      type: "line",
      data: {
        labels: done.map(s => new Date(s.created_at + "Z").toLocaleString(lang === "en" ? "en-GB" : "pl-PL")),
        datasets: [
          { label: "CRITICAL", data: done.map(s => s.critical), borderColor: CHART_SEV.critical, backgroundColor: "transparent", tension: 0.2, pointRadius: 3 },
          { label: "HIGH",     data: done.map(s => s.high),     borderColor: CHART_SEV.high,     backgroundColor: "transparent", tension: 0.2, pointRadius: 3 },
          { label: "MEDIUM",   data: done.map(s => s.medium),   borderColor: CHART_SEV.medium,   backgroundColor: "transparent", tension: 0.2, pointRadius: 3 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { labels: { boxWidth: 12 } } },
        scales: {
          x: { grid: { color: "#1e293b" }, ticks: { maxRotation: 30, autoSkip: true, maxTicksLimit: 8 } },
          y: { beginAtZero: true, grid: { color: "#1e293b" }, ticks: { precision: 0 } },
        },
      },
    });
    $("image-history-table").innerHTML = data.scans.slice().reverse().map(s => `
      <tr class="border-b border-slate-700/40">
        <td class="py-1.5 text-slate-400">${new Date(s.created_at + "Z").toLocaleString(lang === "en" ? "en-GB" : "pl-PL")}</td>
        <td>${statusBadge(s)}</td>
        <td>${s.status === "done" ? sevBadges(s) : "—"}</td>
        <td>${secretsBadge(s)}</td>
        <td class="text-right">
          ${s.status === "done" ? `<button onclick="showDetail(${s.id})" class="hover:text-sky-400">🔎</button>` : ""}
        </td>
      </tr>`).join("");
  } catch (e) {
    $("image-history-table").innerHTML = `<tr><td colspan="5" class="py-4 text-red-400">${esc(e.message)}</td></tr>`;
  }
}

function compareHistoryScans() {
  if (historyDoneIds.length < 2) return;
  const a = historyDoneIds[historyDoneIds.length - 2];
  const b = historyDoneIds[historyDoneIds.length - 1];
  showDiff(a, b);
}

function closeImageHistory() {
  $("image-history-card").classList.add("hidden");
  if (statsCharts["chart-image-history"]) {
    statsCharts["chart-image-history"].destroy();
    delete statsCharts["chart-image-history"];
  }
}

async function changeMyPassword() {
  const password = $("my-new-pass").value;
  if (!password) return;
  try {
    await api("/api/me/password", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) });
    $("my-new-pass").value = "";
    alert(t("password_changed"));
  } catch (e) { alert(e.message); }
}

async function createUser() {
  const username = $("nu-user").value.trim();
  const password = $("nu-pass").value;
  const role = $("nu-role").value;
  if (!username || !password) return;
  try {
    await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password, role }) });
    $("nu-user").value = ""; $("nu-pass").value = "";
    loadUsers();
  } catch (e) { alert(e.message); }
}

function roleBadge(role) {
  const cls = role === "admin" ? "bg-violet-700/50 text-violet-200" : role === "manager" ? "bg-sky-700/50 text-sky-200" : "bg-slate-700 text-slate-300";
  return `<span class="text-xs px-2 py-0.5 rounded-full ${cls}">${esc(role)}</span>`;
}

async function loadUsers() {
  const users = await (await api("/api/users")).json();
  $("user-table").innerHTML = users.map(u => `
    <tr class="border-b border-slate-700/40">
      <td class="py-2">${esc(u.username)} ${u.is_protected ? '<span class="text-amber-400 text-xs" title="root">🔒</span>' : ""}</td>
      <td>${roleBadge(u.role)}</td>
      <td class="text-right whitespace-nowrap">
        ${u.id === me.id ? `<span class="text-slate-500 text-xs">${t("you")}</span>`
          : u.is_protected ? `<span class="text-slate-500 text-xs">${t("protected")}</span>`
          : `<button onclick="resetUserPassword(${u.id})" class="text-sky-400 hover:underline text-xs mr-3">${t("set_pass")}</button>
             <button onclick="deleteUser(${u.id})" class="text-red-400 hover:underline text-xs">${t("del_user")}</button>`}
      </td>
    </tr>`).join("");
}

async function resetUserPassword(id) {
  const password = prompt(t("prompt_new_pass"));
  if (!password) return;
  try {
    await api(`/api/users/${id}/password`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }) });
    alert(t("password_changed"));
  } catch (e) { alert(e.message); }
}

async function deleteUser(id) {
  if (!confirm(t("confirm_del_user"))) return;
  try { await api(`/api/users/${id}`, { method: "DELETE" }); loadUsers(); }
  catch (e) { alert(e.message); }
}

function healthCard(label, value, ok) {
  return `<div class="rounded-xl p-3 border ${ok ? "border-emerald-700/40 bg-emerald-950/20" : "border-red-700/40 bg-red-950/20"}">
    <div class="text-xs text-slate-400">${label}</div>
    <div class="text-sm mt-1 break-all ${ok ? "text-emerald-300" : "text-red-300"}">${esc(value)}</div>
  </div>`;
}

function feedLabel(feed, rows) {
  if (!feed || !feed.updated_at) return t("never");
  const d = new Date(feed.updated_at + (feed.updated_at.endsWith("Z") ? "" : "Z"));
  const extra = feed.extra ? ` · ${feed.extra} ${t("rows")}` : (rows != null ? ` · ${rows} ${t("rows")}` : "");
  return d.toLocaleString(lang === "en" ? "en-GB" : "pl-PL") + extra;
}

function renderHealth(h) {
  healthCache = h;
  const okish = v => v && !String(v).toLowerCase().startsWith("błąd") && String(v) !== "error";
  const cards = [
    healthCard(t("h_trivy"), h.trivy || "—", okish(h.trivy)),
    healthCard(t("h_docker"), h.docker_socket || "—", h.docker_socket === "OK"),
    healthCard(t("h_db"), h.database || "—", h.database === "OK"),
    healthCard(t("h_disk"), h.disk_data_free_mb != null ? h.disk_data_free_mb + " MB" : "—", (h.disk_data_free_mb || 0) > 100),
    healthCard(t("h_cache"), h.disk_cache_free_mb != null ? h.disk_cache_free_mb + " MB" : "—", true),
    healthCard(t("h_epss"), feedLabel(h.epss_feed, h.epss_rows), !!(h.epss_feed && h.epss_feed.updated_at && !(h.epss_feed.extra || "").startsWith("błąd"))),
    healthCard(t("h_kev"), feedLabel(h.kev_feed, h.kev_rows), !!(h.kev_feed && h.kev_feed.updated_at && !(h.kev_feed.extra || "").startsWith("błąd"))),
    healthCard(t("col_scans"), `${h.scans_total || 0} · ${h.scans_running || 0} ${t("running_n")}`, true),
  ];
  $("health-cards").innerHTML = cards.join("");
  $("health-box").textContent = JSON.stringify(h, null, 2);
}

async function loadHealth() {
  const h = await (await api("/api/health")).json();
  renderHealth(h);
}

function fillAuditActions() {
  const sel = $("audit-action");
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">${t("filter_all")}</option>` + AUDIT_ACTIONS.map(a =>
    `<option value="${a}">${t("act_" + a)}</option>`).join("");
  if (AUDIT_ACTIONS.includes(cur)) sel.value = cur;
}

function actionLabel(a) {
  const k = "act_" + a;
  const v = t(k);
  return v === k ? a : v;
}

function renderAudit(data) {
  auditCache = data;
  const loc = lang === "en" ? "en-GB" : "pl-PL";
  $("audit-table").innerHTML = (data.items || []).map(r => `
    <tr class="border-b border-slate-700/40">
      <td class="py-1.5 text-slate-400 whitespace-nowrap">${r.created_at ? new Date(r.created_at + "Z").toLocaleString(loc) : "—"}</td>
      <td>${esc(r.username)}</td>
      <td>${esc(actionLabel(r.action))}</td>
      <td class="font-mono text-slate-400">${esc(r.target || "—")}</td>
      <td class="text-slate-500">${esc(r.details || "")}</td>
      <td class="font-mono text-slate-500">${esc(r.ip || "")}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="py-6 text-center text-slate-500">${t("no_audit")}</td></tr>`;
  $("audit-page-label").textContent = t("page", { p: data.page || 1, n: data.pages || 1, t: data.total || 0 });
  $("audit-prev").disabled = (data.page || 1) <= 1;
  $("audit-next").disabled = (data.page || 1) >= (data.pages || 1);
}

async function loadAudit(page) {
  if (page < 1) page = 1;
  auditPage = page;
  const action = $("audit-action")?.value || "";
  const username = ($("audit-user")?.value || "").trim();
  const qs = new URLSearchParams({ page, per_page: 40 });
  if (action) qs.set("action", action);
  if (username) qs.set("username", username);
  const data = await (await api("/api/audit?" + qs.toString())).json();
  renderAudit(data);
}

async function exportAudit(fmt) {
  const action = $("audit-action")?.value || "";
  const username = ($("audit-user")?.value || "").trim();
  const qs = new URLSearchParams();
  if (action) qs.set("action", action);
  if (username) qs.set("username", username);
  try {
    const res = await api(`/api/audit/export/${fmt}?` + qs.toString());
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = res.headers.get("Content-Disposition")?.match(/filename="(.+)"/)?.[1] || `trivy_audit.${fmt}`;
    a.click();
    URL.revokeObjectURL(a.href);
    loadAudit(auditPage);
  } catch (e) { alert(e.message); }
}

async function maintUpdateDb() {
  const r = await (await api("/api/maintenance/update-db", { method: "POST" })).json();
  $("maint-msg").textContent = r.message;
}
async function maintUpdateFeeds() {
  const r = await (await api("/api/maintenance/update-feeds", { method: "POST" })).json();
  $("maint-msg").textContent = r.message;
}
async function maintCleanup() {
  const days = $("cleanup-days").value || 30;
  const r = await (await api(`/api/maintenance/cleanup?days=${days}`, { method: "POST" })).json();
  $("maint-msg").textContent = t("deleted_n", { n: r.deleted });
  loadScans();
}
async function maintVacuum() {
  await api("/api/maintenance/vacuum", { method: "POST" });
  $("maint-msg").textContent = t("vacuum_ok");
}

async function dl(id, fmt) {
  if (!id) return;
  const res = await api(`/api/scans/${id}/export/${fmt}`);
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = res.headers.get("Content-Disposition")?.match(/filename="(.+)"/)?.[1] || `raport.${fmt}`;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function delScan(id) {
  if (!canManage) return;
  if (!confirm(t("confirm_del_scan"))) return;
  await api(`/api/scans/${id}`, { method: "DELETE" });
  loadScans();
}

function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

applyI18n();
token ? showApp() : $("login-view").classList.remove("hidden");
document.addEventListener("keydown", e => {
  if (e.key === "Escape") { closeVulnModal(); closeLogsModal(); closeModal(); closeDiffModal(); }
});
$("login-pass").addEventListener("keydown", e => { if (e.key === "Enter") login(); });
$("scan-image").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });