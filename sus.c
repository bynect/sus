#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <fcntl.h>
#include <shadow.h>
#include <crypt.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "readpassphrase.h"

#define ALLOW_GROUP "wheel"
#define SAFE_MASK 022
#define MAX_GROUPS 128
#define SAFE_PATH "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
#define PWBUF_SIZE 16384

static struct passwd userpw, rootpw;
static char userbuf[PWBUF_SIZE], rootbuf[PWBUF_SIZE];

// NOTE: basename could modify the buffer, hence the need for this function
static const char *filename(const char *path)
{
    int len = strlen(path);
    for ( ; len > 0 && path[len - 1] != '/'; --len);
    return &path[len];
}

// Verify environment and program state
static void integrity_check(const char *argv0)
{
    uid_t uid = geteuid();
    if (uid != 0)
        errx(1, "Running with the wrong UID: %d", uid);

    const char *name = filename(argv0);
    if (strcmp(name, "sus"))
        errx(1, "Invoked with wrong filename: %s", name);

#ifdef __linux__
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        err(1, "open");

    struct stat st;
    if (fstat(fd, &st) != 0)
        err(1, "stat");

    if (st.st_uid != 0)
        errx(1, "Executable not owned by root!");

    if (!(st.st_mode & S_ISUID))
        errx(1, "Executable missing SUID bit!");

    if (!S_ISREG(st.st_mode))
        errx(1, "Executable is not a regular file!");

    if (st.st_mode & (S_IWGRP | S_IWOTH))
        errx(1, "Executable writable by group/others!");

    close(fd);
#endif
}

static bool is_wheel(const char *user, gid_t gid)
{
    struct group *grp = getgrnam(ALLOW_GROUP);
    if (!grp)
        return false;

    gid_t wheel = grp->gr_gid;
    if (gid == wheel)
        return true;

    gid_t groups[MAX_GROUPS];
    int ngroups = MAX_GROUPS;

    int ret = getgrouplist(user, gid, groups, &ngroups);
    if (ret == -1)
        errx(1, "Failed to get user groups");

    if (ngroups > MAX_GROUPS)
        errx(1, "Do you really need so many groups");

    bool ok = false;
    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == wheel) {
            ok = true;
            break;
        }
    }
    return ok;
}

#ifdef PAM
static int pam_auth(const char *user)
{
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { misc_conv, NULL };

    int ret = pam_start("sus", user, &conv, &pamh);
    if (ret != PAM_SUCCESS)
        return ret;

    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS)
        goto end;

    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS)
        goto end;

    ret = pam_setcred(pamh, PAM_ESTABLISH_CRED);
end:
    pam_end(pamh, ret);
    return ret;
}

#else
static bool shadow_auth(const char *user)
{
    char rbuf[1024], cbuf[128], host[HOST_NAME_MAX + 1];
    char *pass = readpassphrase("Password: ", rbuf, sizeof(rbuf), RPP_REQUIRE_TTY);

    if (!pass)
        err(1, "Failed to read passphrase");

    struct spwd *spw = getspnam(user);
    if (spw == NULL)
        return false;

    char *res = crypt(pass, spw->sp_pwdp);
    if (res == NULL)
        return false;

    return !strcmp(res, spw->sp_pwdp);
}
#endif

// Check if the user has the right permissions
static void user_auth()
{
    struct passwd *ptr = NULL;
    if (getpwuid_r(0, &rootpw, rootbuf, sizeof(rootbuf), &ptr) != 0 || ptr == NULL)
        errx(1, "Failed to get root info: entry too large or missing");

    uid_t uid = getuid();
    ptr = NULL;

    if (getpwuid_r(uid, &userpw, userbuf, sizeof(userbuf), &ptr) != 0 || ptr == NULL)
        errx(1, "Failed to get user info: entry too large or missing");

    if (uid == 0)
        return;

    if (!is_wheel(userpw.pw_name, userpw.pw_gid))
        errx(1, "User is not in the %s group", ALLOW_GROUP);

#ifdef PAM
    int ret = pam_auth(userpw.pw_name);
    if (ret != PAM_SUCCESS)
        errx(1, "PAM authentication failed: %s", pam_strerror(NULL, ret));
#else
    if (!shadow_auth(userpw.pw_name))
        errx(1, "Authentication failed");
#endif
}

// Set root UID and GID
static void priv_commit()
{
    umask(SAFE_MASK);

    if (initgroups(rootpw.pw_name, rootpw.pw_gid) == -1)
        err(1, "initgroups");

    if (setgid(0) == -1)
        err(1, "setgid");

    if (setuid(0) == -1)
        err(1, "setuid");
}

// Set safe environment variables
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

// Execute the provided command
static void cmd_execute(int argc, char **argv)
{
    char *binsh[2] = { NULL };
    if (argc == 0) {
        binsh[0] = rootpw.pw_shell ? rootpw.pw_shell : "/bin/sh";
        argv = binsh;
    }

    execvp(*argv, argv);
    err(1, "Command execution failed");
}

int main(int argc, char **argv)
{
    integrity_check(argv[0]);

    user_auth();

    priv_commit();

    env_prepare();

    cmd_execute(argc - 1, &argv[1]);
}
