#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <wchar.h>
#include <stdio.h>
#include <unistd.h>
#ifndef __APPLE__
#include <stdio_ext.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>

#endif
#include "sigset.h"

#include "../include/hybris/hook.h"
#include "../include/hybris/binding.h"


#ifdef __APPLE__

int darwin_convert_fd_flags_to_native(int flags)
{
    int ret = flags & 4;
    if (flags & 0100) ret |= O_CREAT;
    if (flags & 0200) ret |= O_EXCL;
    if (flags & 01000) ret |= O_TRUNC;
    if (flags & 02000) ret |= O_APPEND;
    if (flags & 04000) ret |= O_NONBLOCK;
    return ret;
}

int darwin_convert_fd_flags_from_native(int flags)
{
    int ret = flags & 4;
    if (flags & O_CREAT)
        ret |= 0100;
    return ret;
}

#endif

int my_openat(int fd, const char *pathname, int flags, int mode) {
#ifdef __APPLE__
    flags = darwin_convert_fd_flags_to_native(flags);
#endif
    return openat(fd, pathname, flags, (mode_t) mode);
}


struct bionic_stat64 {
    unsigned long long st_dev;
    unsigned char __pad0[4];
    unsigned long __st_ino;
    unsigned int st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    unsigned long long st_rdev;
    unsigned char __pad3[4];
    long long st_size;
    unsigned long st_blksize;
    unsigned long long st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    unsigned long long st_ino;
};

void stat_to_bionic_stat(struct stat *s, struct bionic_stat64 *b) {
    b->st_dev = s->st_dev;
    b->__st_ino = s->st_ino;
    b->st_mode = s->st_mode;
    b->st_nlink = s->st_nlink;
    b->st_uid = s->st_uid;
    b->st_gid = s->st_gid;
    b->st_rdev = s->st_rdev;
    b->st_size = s->st_size;
    b->st_blksize = (unsigned long) s->st_blksize;
    b->st_blocks = (unsigned long long) s->st_blocks;
#ifdef __APPLE__
    b->st_atim = s->st_atimespec;
    b->st_mtim = s->st_mtimespec;
    b->st_ctim = s->st_ctimespec;
#else
    b->st_atim = s->st_atim;
    b->st_mtim = s->st_mtim;
    b->st_ctim = s->st_ctim;
#endif
    b->st_ino = s->st_ino;
}

#ifndef __APPLE__
void stat64_to_bionic_stat(struct stat64 *s, struct bionic_stat64 *b) {
    b->st_dev = s->st_dev;
    b->__st_ino = s->__st_ino;
    b->st_mode = s->st_mode;
    b->st_nlink = s->st_nlink;
    b->st_uid = s->st_uid;
    b->st_gid = s->st_gid;
    b->st_rdev = s->st_rdev;
    b->st_size = s->st_size;
    b->st_blksize = (unsigned long) s->st_blksize;
    b->st_blocks = (unsigned long long) s->st_blocks;
    b->st_atim = s->st_atim;
    b->st_mtim = s->st_mtim;
    b->st_ctim = s->st_ctim;
    b->st_ino = s->st_ino;
}
#endif


#ifndef __APPLE__

int my_fstat(int fd, struct bionic_stat64 *s)
{
    struct stat64 tmp;
    int ret = fstat64(fd, &tmp);
    stat64_to_bionic_stat(&tmp, s);
    return ret;
}
int my_fstatat(int fd, const char *file, struct bionic_stat64 *s, int flag)
{
    struct stat64 tmp;
    int ret = fstatat64(fd, file, &tmp, flag);
    stat64_to_bionic_stat(&tmp, s);
    return ret;
}

#else

int my_fstat(int fd, struct bionic_stat64 *s)
{
    struct stat64 tmp;
    int ret = fstat(fd, &tmp);
    stat_to_bionic_stat(&tmp, s);
    return ret;
}
int my_fstatat(int fd, const char *file, struct bionic_stat64 *s, int flag)
{
    struct stat tmp;
    int ret = fstatat(fd, file, &tmp, flag);
    stat_to_bionic_stat(&tmp, s);
    return ret;
}

#endif

#ifdef __APPLE__

struct android_flock {
    short l_type;
    short l_whence;
    long l_start;
    long l_len;
    long l_sysid;
    int l_pid;
    long pad[4];
};

int darwin_my_fcntl(int fd, int cmd, ...)
{
    int ret = -1;
    va_list ap;
    va_start(ap, cmd);
    if (cmd == 2) {
        int flags = va_arg(ap, int);
        ret = fcntl(fd, F_SETFD, flags);
    } else if (cmd == 4) {
        int flags = va_arg(ap, int);
        ret = fcntl(fd, F_SETFL, darwin_convert_fd_flags_to_native(flags));
    } else if (cmd == 6) {
        struct android_flock* afl = va_arg(ap, struct android_flock*);
        struct flock fl;
        memset(&fl, 0, sizeof(fl));
        fl.l_type = afl->l_type;
        fl.l_whence = afl->l_whence;
        fl.l_start = afl->l_start;
        fl.l_len = afl->l_len;
        fl.l_pid = afl->l_pid;
        ret = fcntl(fd, F_SETLK, &fl);
    } else {
        printf("unsupported fcntl %i\n", cmd);
    }
    va_end(ap);
    return ret;
}

int darwin_my_fdatasync(int fildes) {
    return fcntl(fildes, F_FULLFSYNC);
}

#endif

#ifdef __APPLE__

int darwin_my_ioctl(int s, int cmd, void* arg) {
    unsigned long mcmd = cmd;
    if (cmd == 0x5421)
        mcmd = FIONBIO;
    else
        printf("potentially unsupported ioctl: %x\n", cmd);
    return ioctl(s, mcmd, arg);
}

#else

static int my_ioctl(int fd, int req, void *argp) {
    return ioctl(fd, req, argp);
}

#endif

#ifdef __APPLE__

int darwin_my_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    // Mac OS has a broken poll implementation
    struct timeval t;
    t.tv_sec = timeout / 1000;
    t.tv_usec = (timeout % 1000) * 1000;

    fd_set r_fdset, w_fdset, e_fdset;
    int maxfd = 0;
    FD_ZERO(&r_fdset);
    FD_ZERO(&w_fdset);
    FD_ZERO(&e_fdset);
    for (nfds_t i = 0; i < nfds; i++) {
        if (fds[i].fd > maxfd)
            maxfd = fds[i].fd;
        if (fds[i].events & POLLIN || fds[i].events & POLLPRI)
            FD_SET(fds[i].fd, &r_fdset);
        if (fds[i].events & POLLOUT)
            FD_SET(fds[i].fd, &w_fdset);
        FD_SET(fds[i].fd, &e_fdset);
    }
    int ret = select(maxfd + 1, &r_fdset, &w_fdset, &e_fdset, &t);
    for (nfds_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        if (FD_ISSET(fds[i].fd, &r_fdset))
            fds[i].revents |= POLLIN;
        if (FD_ISSET(fds[i].fd, &w_fdset))
            fds[i].revents |= POLLOUT;
        if (FD_ISSET(fds[i].fd, &e_fdset))
            fds[i].revents |= POLLERR;
    }
    return ret;
}

int darwin_my_ppoll_impl(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
    // Mac OS has a broken poll implementation
    fd_set r_fdset, w_fdset, e_fdset;
    int maxfd = 0;
    FD_ZERO(&r_fdset);
    FD_ZERO(&w_fdset);
    FD_ZERO(&e_fdset);
    for (nfds_t i = 0; i < nfds; i++) {
        if (fds[i].fd > maxfd)
            maxfd = fds[i].fd;
        if (fds[i].events & POLLIN || fds[i].events & POLLPRI)
            FD_SET(fds[i].fd, &r_fdset);
        if (fds[i].events & POLLOUT)
            FD_SET(fds[i].fd, &w_fdset);
        FD_SET(fds[i].fd, &e_fdset);
    }
    int ret = pselect(maxfd + 1, &r_fdset, &w_fdset, &e_fdset, timeout_ts, sigmask);
    for (nfds_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        if (FD_ISSET(fds[i].fd, &r_fdset))
            fds[i].revents |= POLLIN;
        if (FD_ISSET(fds[i].fd, &w_fdset))
            fds[i].revents |= POLLOUT;
        if (FD_ISSET(fds[i].fd, &e_fdset))
            fds[i].revents |= POLLERR;
    }
    return ret;
}

#endif

static int my_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts,
        const bionic_sigset_t *sigmask) {
    sigset_t sigmask_host;
    bionic_sigset_t_to_host(&sigmask_host, sigmask);
#ifndef __APPLE__
    return ppoll(fds, nfds, timeout_ts, &sigmask_host);
#else
    return darwin_my_ppoll_impl(fds, nfds, timeout_ts, &sigmask_host);
#endif
}
static int my_ppoll64(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts,
        const bionic_sigset64_t *sigmask) {
    sigset_t sigmask_host;
    bionic_sigset64_t_to_host(&sigmask_host, sigmask);
#ifndef __APPLE__
    return ppoll(fds, nfds, timeout_ts, &sigmask_host);
#else
    return darwin_my_ppoll_impl(fds, nfds, timeout_ts, &sigmask_host);
#endif
}

struct _hook io_hooks[] = {
    {"__close", close},
    {"__openat", my_openat},
#ifdef __APPLE__
    {"fcntl", darwin_my_fcntl},
    {"fdatasync", darwin_my_fdatasync},
#else
    {"fcntl", fcntl},
    {"fdatasync", fdatasync},
#endif
    {"fsync", fsync},
    {"sync", sync},
    {"read", read},
    {"write", write},
    {"readv", readv},
    {"writev", writev},
#ifdef __APPLE__
    {"pread64", pread},
    {"pwrite64", pwrite},
    {"preadv64", preadv},
    {"pwritev64", pwritev},
#else
    {"pread64", pread64},
    {"pwrite64", pwrite64},
    {"preadv64", preadv64},
    {"pwritev64", pwritev64},
#endif
    {"lseek", lseek},
    {"lseek64", lseek64},

    {"dup3", dup3},
    {"pipe2", pipe2},

    {"umask", umask},
    {"chdir", chdir},
    {"fchdir", fchdir},

    {"fstat", my_fstat},
    {"fstatat", my_fstatat},
    {"fchmod", fchmod},
    {"fchmodat", fchmodat},
    {"fchown", fchown},
    {"fchownat", fchownat},
    {"faccessat", faccessat},
    {"fgetxattr", fgetxattr},
    {"fsetxattr", fsetxattr},
    {"flistxattr", flistxattr},

    {"fallocate64", fallocate64},
    {"truncate", truncate},
    {"truncate64", truncate64},
    {"ftruncate64", ftruncate64},

#ifdef __APPLE__
    {"__ioctl", darwin_my_ioctl},
#else
    {"__ioctl", my_ioctl},
#endif

    {"mkdirat", mkdirat},
    {"renameat", renameat},
    {"unlinkat", unlinkat},
    {"linkat", linkat},
    {"symlinkat", symlinkat},
    {"readlinkat", readlinkat},
    {"mknodat", mknodat},

    {"utimes", utimes},
    {"utimensat", utimensat},

    /* poll.h */
#ifdef __APPLE__
    {"poll", darwin_my_poll},
#else
    {"poll", poll},
#endif
    {"ppoll", my_ppoll},
    {"ppoll64", my_ppoll64},
    {"select", select},
    {NULL, NULL}
};