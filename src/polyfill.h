// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi
#ifndef THEFT_POLYFILL_H
#define THEFT_POLYFILL_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define THEFT_POLYFILL_HAVE_FORK true
#if defined(_WIN32)
#undef THEFT_POLYFILL_HAVE_FORK
#define THEFT_POLYFILL_HAVE_FORK false
#include "poll_windows.h"

// Windows's read() function returns int.
typedef int ssize_t;

struct timespec;

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

typedef int pid_t;

// Not actually used. Here to silence "incomplete type" warnings.
struct sigaction {
	void (*sa_handler)(int);
	void (*sa_sigaction)(int, void*, void*);
	int sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};

// Not actually used. Here to silence "incomplete type" warnings.
struct rlimit {
	int rlim_cur;
	int rlim_max;
};

#define RLIMIT_CPU     0
#define SIGKILL        0
#define SIGUSR1        0
#define WIFEXITED(x)   ((void)(x), 0)
#define WEXITSTATUS(x) ((void)(x), 0)
#define WNOHANG        0

// POSIX pipe(2)
int pipe(int pipefd[2]);

// POSIX nanosleep(2)
int nanosleep(const struct timespec* req, struct timespec* rem);

// Not actually implemented. Disabled on Windows.
int fork();

int gettimeofday(struct timeval* tp, struct timezone* tzp);

// When POLYFILL_HAVE_FORK is false, these do nothing and are never called.
// They only exist to prevent linker errors.
int wait(int* status);
int waitpid(int pid, int* status, int options);
int kill(int pid, int sig);

int sigaction(int signum, const struct sigaction* act,
		struct sigaction* oldact);

int setrlimit(int resource, const struct rlimit* rlim);
int getrlimit(int resource, struct rlimit* rlim);
#endif

#endif // THEFT_POLYFILL_H
