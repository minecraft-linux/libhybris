/*
 * Copyright (c) 2012 Carsten Munk <carsten.munk@gmail.com>
 * Copyright (c) 2012 Canonical Ltd
 * Copyright (c) 2013 Christophe Chapuis <chris.chapuis@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "../include/hybris/binding.h"

#include "hooks_shm.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdarg.h>
#include <semaphore.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <wait.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>

#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <locale.h>
#ifndef __APPLE__
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <malloc.h>
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <sys/mman.h>
#include <wchar.h>
#include <sys/utsname.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <utime.h>
#include <wctype.h>
#include <ctype.h>
#include <setjmp.h>
#include <bits/sigaction.h>

#ifdef __APPLE__
#include <xlocale.h>
#endif

#include "../include/hybris/hook.h"
#include "../include/hybris/properties.h"
#include "sigset.h"

static locale_t hybris_locale;
static int locale_inited = 0;

/* Debug */
#include "logging.h"

#define LOGD(message, ...) HYBRIS_DEBUG_LOG(HOOKS, message, ##__VA_ARGS__)


#ifdef __APPLE__
static char hybris_fake_at_random[16];
static void __attribute__((constructor)) __init_fake_at_random() {
    arc4random_buf(hybris_fake_at_random, 16);
}
#endif

unsigned long int my_getauxval(int what) {
    switch (what) {
        case 25: /* AT_RANDOM */
#ifdef __APPLE__
            return (unsigned long int) (void *) hybris_fake_at_random;
#else
            return getauxval(AT_RANDOM);
#endif
        case 6: /* AT_PAGESZ */
            return getpagesize();
        default:
            printf("getauxval: unsupported value: %i\n", what);
            abort();
    }
}

#ifdef __APPLE__

struct android_rlimit {
    unsigned long int rlim_cur;
    unsigned long int rlim_max;
};
struct android_rlimit64 {
    unsigned long long int rlim_cur;
    unsigned long long int rlim_max;
};

static int _darwin_android_rlimit_to_host(int resource) {
    if (resource == 7) return RLIMIT_NOFILE;
    printf("unsupported rlimit resource: %i\n", resource);
    return -1;
}

int darwin_my_getrlimit(int resource, struct android_rlimit *rlim) {
    resource = _darwin_android_rlimit_to_host(resource);
    if (resource < 0)
        return resource;
    struct rlimit os_rlim;
    int ret = getrlimit(resource, &os_rlim);
    rlim->rlim_cur = (unsigned long int) os_rlim.rlim_cur;
    rlim->rlim_max = (unsigned long int) os_rlim.rlim_max;
    return ret;
}

int darwin_my_prlimit64(pid_t pid, int resource,
        const struct android_rlimit64 *new_limit, struct android_rlimit64 *old_limit) {
    resource = _darwin_android_rlimit_to_host(resource);
    if (resource < 0)
        return resource;
    struct rlimit os_new_rlim, os_old_rlim;
    os_new_rlim.rlim_cur = new_limit->rlim_cur;
    os_new_rlim.rlim_max = new_limit->rlim_max;
    int ret = prlimit(pid, resource, &os_new_rlim, &os_old_rlim);
    if (old_limit) {
        old_limit->rlim_cur = os_old_rlim.rlim_cur;
        old_limit->rlim_max = os_old_rlim.rlim_max;
    }
    return ret;
}

static void darwin_clock_id(clockid_t clk_id) {
    if (clk_id == 1)
        return CLOCK_MONOTONIC;
    printf("unknown clockid: %i\n", clk_id);
}

int darwin_my_clock_getres(clockid_t clk_id, struct timespec *res) {
    return clock_getres(darwin_clock_id(clk_id), res);
}
int darwin_my_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    return clock_gettime(darwin_clock_id(clk_id), tp);
}

int* darwin_my_errno() {
    int* ret = &errno;
    if (*ret == EAGAIN) *ret = 11;
    else if (*ret == ETIMEDOUT) *ret = 110;
    else if (*ret == EINPROGRESS) *ret = 115;
    return ret;
}


int darwin_my_prctl(int opt) {
    printf("unsupported prctl %i\n", opt);
    return 0;
}

static void* darwin_my_mmap(void *addr, size_t length, int prot, int flags,
                            int fd, off_t offset) {
    int flags_m = flags & 0xf;
    if (flags & 0x10)
        flags_m |= MAP_FIXED;
    if (flags & 0x20)
        flags_m |= MAP_ANON;
    if (flags & 0x4000)
        flags_m |= MAP_NORESERVE;
    return mmap(addr, length, prot, flags_m, fd, offset);
}

#endif

static void my_sig_stub() {
    printf("unsupported signal related function\n");
    abort();
}

struct bionic_sigaction {
    void (*sa_handler_func)(int);
    bionic_sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};
struct bionic_sigaction64 {
    void (*sa_handler_func)(int);
    int sa_flags;
    void (*sa_restorer)(void);
    bionic_sigset64_t sa_mask;
};
static int my_sigaction(int signum, const struct bionic_sigaction *act,
        struct bionic_sigaction *oldact) {
    struct sigaction host_act, host_oldact;
    host_act.sa_handler = act->sa_handler_func;
    bionic_sigset_t_to_host(&host_act.sa_mask, &act->sa_mask);
    host_act.sa_flags = act->sa_flags;
    host_act.sa_restorer = act->sa_restorer;
    int ret = sigaction(signum, &host_act, &host_oldact);
    if (oldact) {
        oldact->sa_handler_func = host_oldact.sa_handler;
        bionic_sigset_t_from_host(&oldact->sa_mask, &host_oldact.sa_mask);
        oldact->sa_flags = host_oldact.sa_flags;
        oldact->sa_restorer = host_oldact.sa_restorer;
    }
    return ret;
}
static int my_sigaction64(int signum, const struct bionic_sigaction64 *act,
        struct bionic_sigaction64 *oldact) {
    struct sigaction host_act, host_oldact;
    host_act.sa_handler = act->sa_handler_func;
    bionic_sigset64_t_to_host(&host_act.sa_mask, &act->sa_mask);
    host_act.sa_flags = act->sa_flags;
    host_act.sa_restorer = act->sa_restorer;
    int ret = sigaction(signum, &host_act, &host_oldact);
    if (oldact) {
        oldact->sa_handler_func = host_oldact.sa_handler;
        bionic_sigset64_t_from_host(&oldact->sa_mask, &host_oldact.sa_mask);
        oldact->sa_flags = host_oldact.sa_flags;
        oldact->sa_restorer = host_oldact.sa_restorer;
    }
    return ret;
}

static int my_getcwd(char* buf, size_t size) {
    char *ret = getcwd(buf, size);
    if (ret != buf)
        abort();
    return (ret ? 0 : (-1));
}

static void my_syscall() {
    printf("syscall is not supported\n");
    abort();
}

extern int __cxa_atexit(void (*)(void*), void*, void*);
extern void __cxa_finalize(void * d);

void *get_hooked_symbol(const char *sym);
void *my_android_dlsym(void *handle, const char *symbol)
{
    void *retval = get_hooked_symbol(symbol);
    if (retval != NULL) {
        return retval;
    }
    return android_dlsym(handle, symbol);
}

extern void _Znwj();
extern void _ZdlPv();

struct _hook main_hooks[] = {
    {"dlopen", android_dlopen},
    {"dlerror", android_dlerror},
    {"dlsym", my_android_dlsym},
    {"dladdr", android_dladdr},
    {"dlclose", android_dlclose},

    {"syscall", my_syscall},

#ifdef __APPLE__
    {"__errno", darwin_my_errno},
#else
    {"__errno", __errno_location},
#endif
    {"environ", &environ},
    {"getauxval", my_getauxval},
    {"execve", execve},
    {"exit", exit},
    {"_exit", _exit},
    {"__exit", _exit},
    {"_Exit", _exit},
    // {"quick_exit", quick_exit},
    // {"at_quick_exit", at_quick_exit},
    {"abort", abort},
    {"atexit", atexit},
    {"__cxa_atexit", __cxa_atexit},
    {"__cxa_finalize", __cxa_finalize},
    {"raise", raise},
    {"tgkill", tgkill},
    {"kill", kill},
    {"sigaction", my_sigaction},
    {"sigaction64", my_sigaction64},
    {"sigsuspend64", my_sig_stub},
    {"sigtimedwait64", my_sig_stub},
    {"sigprocmask64", my_sig_stub},
    {"__brk", brk},
    {"fork", fork},
    {"vfork", vfork},
    {"wait4", wait4},
    {"waitid", waitid},

#ifdef __APPLE__
    {"prctl", darwin_my_prctl},
    {"getrlimit", darwin_my_getrlimit},
    {"prlimit64", darwin_my_prlimit64},
#else
    {"prctl", prctl},
    {"getrlimit", getrlimit},
    {"prlimit64", prlimit64},
#endif
    {"getrusage", getrusage},
    {"get_phys_pages", get_phys_pages},
    {"get_avphys_pages", get_avphys_pages},
    {"sysinfo", sysinfo},

    {"nanosleep", nanosleep},
    {"getpid", getpid},
    {"getppid", getppid},
    {"getpgrp", getpgrp},
    {"setpgid", setpgid},
    {"setpgrp", setpgrp},
    {"setsid", setsid},
    {"getsid", getsid},
    {"getuid", getuid},
    {"geteuid", geteuid},
    {"getgid", getgid},
    {"getegid", getegid},
    {"getgroups", getgroups},
    // {"group_member", group_member},
    {"setuid", setuid},
    {"setreuid", setreuid},
    {"seteuid", seteuid},
    {"setgid", setgid},
    {"setregid", setregid},
    {"setegid", setegid},
    // {"getresuid", getresuid},
    // {"getresgid", getresgid},
    // {"setresuid", setresuid},
    // {"setresgid", setresgid},
    {"getgrnam", getgrnam},
    {"uname", uname },
    {"__getcwd", my_getcwd },

    {"setitimer", setitimer},
    {"gettimeofday", gettimeofday},
    {"setlocale", setlocale},
    {"localeconv", localeconv},

    {"sched_getcpu", sched_getcpu},
    {"sched_yield", sched_yield},
    {"sched_getscheduler", sched_getscheduler},
    {"sched_setparam", sched_setparam},
    {"get_nprocs", get_nprocs},
    {"get_nprocs_conf", get_nprocs_conf},
    {"getpagesize", getpagesize},

#ifdef __APPLE__
    {"mmap", darwin_my_mmap},
#else
    {"mmap", mmap},
#endif
    {"munmap", munmap},
    {"mprotect", mprotect},
    {"madvise", madvise},
    {"msync", msync},
    {"mlock", mlock},
    {"munlock", munlock},
    {"mlockall", mlockall},
    {"munlockall", munlockall},

    /* time.h */
    {"time", time},
    {"difftime", difftime},
    {"mktime", mktime},
    {"strftime", strftime},
    {"strptime", strptime},
    {"strftime_l", strftime_l},
    {"strptime_l", strptime_l},
    {"gmtime", gmtime},
    {"gmtime_r", gmtime_r},
    {"localtime", localtime},
    {"localtime_r", localtime_r},
    {"asctime", asctime},
    {"asctime_r", asctime_r},
    {"ctime", ctime},
    {"ctime_r", ctime_r},
    // {"__tzname", __tzname},
    // {"__daylight", &__daylight},
    // {"__timezone", &__timezone},
    {"tzname", tzname},
    {"tzset", tzset},
    {"daylight", &daylight},
    {"timezone", &timezone},
    // {"stime", stime},
    {"timegm", timegm},
    {"timelocal", timelocal},
    // {"dysize", dysize},
#ifdef __APPLE__
    {"clock_getres", darwin_my_clock_getres},
    {"clock_gettime", darwin_my_clock_gettime},
#else
    {"clock_getres", clock_getres},
    {"clock_gettime", clock_gettime},
#endif
    // {"clock_settime", clock_settime},
    {"clock_nanosleep", clock_nanosleep},
    // {"clock_getcpuclockid", clock_getcpuclockid},

    {"getentropy", getentropy},

    /* HOST ALLOCATOR BRIDGE */
    {"malloc", malloc },
    {"_ZdlPv", _ZdlPv },
    {"_Znwj", _Znwj },
    {"calloc", calloc},
    {"realloc", realloc},
    {"free", free},
    {"valloc", valloc},
    {"memalign", memalign},
    {"posix_memalign", posix_memalign},
    /* END OF HOST ALLOCATOR BRIDGE */

    /* OPTIONAL SET OF FUNCTIONS (MAYBE PERFORMANCE IMPROVEMENT?) */
    /*
    {"memccpy",memccpy},
    {"memchr",memchr},
    {"memcmp",memcmp},
    {"memcpy",my_memcpy},
    {"memmove",memmove},
    {"memset",memset},
    {"memmem",memmem},
    // {"memswap",memswap},
    {"strchr",strchr},
    {"strrchr",strrchr},
    {"strlen",my_strlen},
    {"__strlen_chk",my_strlen_chk},
    {"strcmp",strcmp},
    {"strcpy",strcpy},
    {"strcat",strcat},
    {"strstr",strstr},
    {"strtok",strtok},
    {"strtok_r",strtok_r},
    {"strnlen",strnlen},
    {"strncat",strncat},
    {"strncmp",strncmp},
    {"strncpy",strncpy},
    // {"strlcat",strlcat},
    {"strcspn",strcspn},
    {"strpbrk",strpbrk},
    {"strsep",strsep},
    {"strspn",strspn},
    {"bcopy",bcopy},
    {"bzero",bzero},
    {"index",index},
    {"strcoll", strcoll},
    {"strxfrm", strxfrm},
     */
    /* END OF OPTIONAL SET */

    /* Start of misc forwarded functions */

    {"strerror", strerror}, //TODO:
    {"strerror_r", strerror_r},

    {"posix_openpt", posix_openpt},
    {"grantpt", grantpt},
    {"unlockpt", unlockpt},
    {"ptsname", ptsname},
    // {"ptsname_r", ptsname_r},
    // {"getpt", getpt},
    {"getloadavg", getloadavg},

    /* errno.h */
    // {"timer_create", timer_create},
    // {"timer_settime", timer_settime},
    // {"timer_gettime", timer_gettime},
    // {"timer_delete", timer_delete},
    // {"timer_getoverrun", timer_getoverrun},
    /* unistd.h */
    {"getcwd", getcwd},
    // {"get_current_dir_name", get_current_dir_name},
    {"nice", nice},
    {"confstr", confstr},
    {"getlogin", getlogin},
    {"getlogin_r", getlogin_r},
    {"sethostid", sethostid},
    // {"vhangup", vhangup},
    // {"profil", profil},
    {"acct", acct},
    {"getusershell", getusershell},
    {"endusershell", endusershell},
    {"setusershell", setusershell},
    {"daemon", daemon},
    {"chroot", chroot},
    {"getpass", getpass},
    // {"syncfs", syncfs},
    {"gethostid", gethostid},
    {"getdtablesize", getdtablesize},

    /* sys/epoll.h */
    {"epoll_create", epoll_create},
    // {"epoll_create1", epoll_create1},
    {"epoll_ctl", epoll_ctl},
    {"epoll_wait", epoll_wait},
    /* grp.h */
    {"getgrgid", getgrgid},
    /* net/if.h */
    {"if_nametoindex", if_nametoindex},
    {"if_indextoname", if_indextoname},
    {"if_nameindex", if_nameindex},
    {"if_freenameindex", if_freenameindex},
    {NULL, NULL},
};
static struct _hook* user_hooks = NULL;
static int user_hooks_size = 0;
static int user_hooks_arr_size = 0;

void user_hooks_resize() {
    if (user_hooks_arr_size == 0) {
        user_hooks_arr_size = 512;
        user_hooks = (struct _hook*) malloc(user_hooks_arr_size * sizeof(struct _hook));
    } else {
        user_hooks_arr_size *= 2;
        struct _hook* new_array = (struct _hook*) malloc(user_hooks_arr_size * sizeof(struct _hook));
        memcpy(&new_array[0], &user_hooks[0], user_hooks_size * sizeof(struct _hook));
        free(user_hooks);
        user_hooks = new_array;
    }
}

void add_user_hook(struct _hook h, int user) {
    if (user_hooks_size + 1 >= user_hooks_arr_size)
        user_hooks_resize();

    for (int i = 0; i < user_hooks_size; i++) {
        if (strcmp(user_hooks[i].name, h.name) == 0) {
            if (!user)
                printf("warn: duplicate hook: %s\n", h.name);
            user_hooks[i] = h;
            return;
        }
    }
    user_hooks[user_hooks_size++] = h;
}

void hybris_register_hooks(struct _hook *hooks) {
    struct _hook *ptr = &hooks[0];
    while (ptr->name != NULL)
    {
        add_user_hook(*ptr, 0);
        ptr++;
    }
}

void hybris_hook(const char *name, void* func) {
    struct _hook h;
    h.name = name;
    h.func = func;
    add_user_hook(h, 1);
}

void *get_hooked_symbol(const char *sym)
{
    int i;

    static int counter = -1;

    for (i = 0; i < user_hooks_size; i++) {
        struct _hook* h = &user_hooks[i];
        if (strcmp(sym, h->name) == 0) {
            //printf("redirect %s --> %s\n", sym, h->name);
            return h->func;
        }
    }

    if (strstr(sym, "pthread") != NULL)
    {
        /* safe */
        if (strcmp(sym, "pthread_sigmask") == 0)
           return NULL;
        /* not safe */
        counter--;
        LOGD("%s %i\n", sym, counter);
        return (void *) counter;
    }
    return NULL;
}

#include "hooks_list.h"

// This file will be definitely included and therefore it's safe to use __attribute__((constructor)) here.
__attribute__((constructor))
static void android_linker_init()
{
    hybris_register_default_hooks();
}
