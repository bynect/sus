#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>

static const char *filename(const char *path)
{
    int len = strlen(path);
    while (len > 0 && path[len - 1] != '/')
        --len;
    return &path[len];
}

static void integrity_check()
{
    uid_t uid = geteuid();
    if (uid != 0)
        errx(1, "Wrong UID detected: %d", uid);

    char buf[PATH_MAX + 1] = { 0 };
    ssize_t r = readlink("/proc/self/exe", buf, PATH_MAX);

    if (r <= 0)
        errx(1, "Failed to get filename: %s", strerror(errno));

    const char *name = filename(buf);
    if (strcmp(name, "sus"))
        errx(1, "Wrong filename detected: %s", name);
}

static bool is_wheel(const char *user, gid_t gid)
{
    struct group *wheel = getgrnam("wheel");
    if (!wheel) return false;

    int ngroups = 0;
    getgrouplist(user, gid, NULL, &ngroups);

    gid_t *groups = malloc(ngroups * sizeof(gid_t));
    if (!groups)
        errx(1, "Failed to allocate memory");

    bool ok = false;
    if (getgrouplist(user, gid, groups, &ngroups) != -1) {
        for (int i = 0; i < ngroups; i++) {
            if (groups[i] == wheel->gr_gid) {
                ok = true;
                break;
            }
        }
    }

    free(groups);
    return ok;
}

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

    if (getpwuid_r(uid, &pw, buf, size, &ptr) != 0 || ptr == NULL) {
        free(buf);
        errx(1, "User lookup failed: %s", strerror(errno));
    }

    if (!is_wheel(pw.pw_name, pw.pw_gid))
        errx(1, "User is not in the wheel group");

    free(buf);
}

int main(int argc, char **argv)
{
    // Check program state
    integrity_check();

    // Authenticate user
    user_auth();

    // Execute command
    char *binsh[] = { "sh", "-i", NULL };
    argv = argc > 1 ? &argv[1] : binsh;

    execvp(*argv, argv);
    errx(1, "Command execution failed: %s", strerror(errno));
}
