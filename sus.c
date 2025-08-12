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
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define ALLOW_GROUP "wheel"
#define MAX_GROUPS 128

// NOTE: basename could modify the buffer, hence the need for this function
static const char *filename(const char *path)
{
    int len = strlen(path);
    for ( ; len > 0 && path[len - 1] != '/'; --len);
    return &path[len];
}

// Verify environment and program state
static void integrity_check()
{
    uid_t uid = geteuid();
    if (uid != 0)
        errx(1, "Running with the wrong UID: %d", uid);

    struct stat st;
    if (stat("/proc/self/exe", &st) != 0)
        err(1, "Failed to get stat: %s", strerror(errno));

    if (st.st_uid != 0)
        errx(1, "Executable not owned by root!");

    if (S_ISREG(st.st_mode))
        errx(1, "Executable is not a regular file!");

    if (st.st_mode & (S_IWGRP | S_IWOTH))
        errx(1, "Executable writable by group/others!");

    char buf[PATH_MAX + 1] = { 0 };
    if (!realpath("/proc/self/exe", buf))
        errx(1, "Failed to get filename: %s", strerror(errno));

    const char *name = filename(buf);
    if (strcmp(name, "sus"))
        errx(1, "Executable with wrong filename: %s", name);
}

// Search the user groups
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

end:
    pam_end(pamh, ret);
    return ret;
}

// Check if the user has the right permissions
static void user_auth()
{
    struct passwd pw, *ptr = NULL;
    uid_t uid = getuid();

    ssize_t size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (size == -1)
        size = 1 << 12;

    char *buf = malloc(size);
    if (!buf)
        errx(1, "Failed to allocate memory");

    if (getpwuid_r(uid, &pw, buf, size, &ptr) != 0 || ptr == NULL)
        errx(1, "User lookup failed: %s", strerror(errno));

    if (!is_wheel(pw.pw_name, pw.pw_gid))
        errx(1, "User is not in the %s group", ALLOW_GROUP);

    int ret = pam_auth(pw.pw_name);
    if (ret != PAM_SUCCESS)
        errx(1, "PAM authentication failed: %s", pam_strerror(NULL, ret));

    free(buf);
}

int main(int argc, char **argv)
{
    integrity_check();

    user_auth();

    char *binsh[] = { "sh", "-i", NULL };
    argv = argc > 1 ? &argv[1] : binsh;

    // TODO: Improve env handling
    clearenv();
    setenv("PATH", "/usr/bin:/bin", 1);
    setenv("TERM", "xterm-256color", 1);

    execvp(*argv, argv);
    errx(1, "Command execution failed: %s", strerror(errno));
}
