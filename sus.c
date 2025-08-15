#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <shadow.h>
#include <crypt.h>

#include "readpassphrase.h"

#define ALLOW_GROUP "wheel"
#define MAX_GROUPS 128
#define SAFE_PATH "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
#define PWBUF_SIZE 16384

static struct passwd userpw, rootpw;
static char userbuf[PWBUF_SIZE], rootbuf[PWBUF_SIZE];

static void integrity_check(const char *argv0)
{
    if (geteuid() != 0)
        errx(1, "Not running with EUID 0, is this root-owned and setuid?");

    const char *name = strrchr(argv0, '/');
    name = name ? &name[1] : argv0;
    if (strcmp(name, "sus"))
        errx(1, "Invoked with wrong filename: %s", name);
}

static bool in_group(const char *user, gid_t gid)
{
    struct group *grp = getgrnam(ALLOW_GROUP);
    if (!grp)
        return false;

    gid_t allow = grp->gr_gid;
    if (gid == allow)
        return true;

    gid_t groups[MAX_GROUPS];
    int ngroups = MAX_GROUPS;

    int ret = getgrouplist(user, gid, groups, &ngroups);
    if (ret == -1)
        errx(1, "Failed to get user groups");

    if (ngroups > MAX_GROUPS)
        errx(1, "Do you really need so many groups?");

    bool ok = false;
    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == allow) {
            ok = true;
            break;
        }
    }
    return ok;
}

static bool shadow_auth(const char *user)
{
    char rbuf[1024], cbuf[128], host[HOST_NAME_MAX + 1];
    const char *chall = "Password: ";
    char *pass = readpassphrase(chall, rbuf, sizeof(rbuf), RPP_REQUIRE_TTY);

    if (!pass)
        err(1, "Failed to read passphrase");

    struct spwd *spw = getspnam(user);
    if (!spw)
        return false;

    char *res = crypt(pass, spw->sp_pwdp);
    return res && !strcmp(res, spw->sp_pwdp);
}

static void user_auth()
{
    uid_t uid = getuid();
    struct passwd *ptr = NULL;

    if (getpwuid_r(uid, &userpw, userbuf, sizeof(userbuf), &ptr) != 0 || ptr == NULL)
        errx(1, "Failed to get user info: entry too large or missing");

    ptr = NULL;
    if (getpwuid_r(0, &rootpw, rootbuf, sizeof(rootbuf), &ptr) != 0 || ptr == NULL)
        errx(1, "Failed to get root info: entry too large or missing");

    // User is already root
    if (uid == 0)
        return;

    if (!in_group(userpw.pw_name, userpw.pw_gid))
        errx(1, "User is not in the %s group", ALLOW_GROUP);

    if (!shadow_auth(userpw.pw_name))
        errx(1, "Authentication failed");
}

static void env_prepare()
{
    const char *pass[3] = { "TERM", "DISPLAY", NULL };
    char *save[3] = { NULL };

    for (int i = 0; pass[i]; i++) {
        const char *val = getenv(pass[i]);
        save[i] = val ? strdup(val) : NULL;
    }

    if (clearenv() == -1)
        err(1, "clearenv");

    if (setenv("PATH", SAFE_PATH, 1) == -1 ||
        setenv("USER", rootpw.pw_name, 1) == -1 ||
        setenv("SHELL", rootpw.pw_shell, 1) == -1 ||
        setenv("HOME", rootpw.pw_dir, 1) == -1 ||
        setenv("LOGNAME", rootpw.pw_name, 1) == -1 ||
        setenv("SUS_USER", userpw.pw_name, 1) == -1)
        err(1, "setenv");

    for (int i = 0; pass[i]; i++) {
        if (!save[i])
            continue;

        if (setenv(pass[i], save[i], 1) == -1)
            err(1, "setenv");
        free(save[i]);
    }
}

static void cmd_execute(int argc, char **argv)
{
    // Escalate privileges
    umask(022);

    if (initgroups(rootpw.pw_name, rootpw.pw_gid) == -1)
        err(1, "initgroups");

    if (setgid(0) == -1)
        err(1, "setgid");

    if (setuid(0) == -1)
        err(1, "setuid");

    // Execute given program (or shell)
    char *binsh[2] = { NULL };
    if (argc <= 1) {
        binsh[0] = rootpw.pw_shell ? rootpw.pw_shell : "/bin/sh";
        argv = binsh;
    }

    execvp(*argv, argv);
    err(1, "Command execution failed");
}

int main(int argc, char **argv)
{
    integrity_check(argc > 0 ? argv[0] : "sus");

    user_auth();

    env_prepare();

    cmd_execute(argc, argv);
}
