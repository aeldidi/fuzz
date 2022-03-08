#ifndef POLYFILL_H
#define POLYFILL_H

#include <errno.h>
#include <stdbool.h>
#include <time.h>

#ifndef _WIN32
#include <poll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define POLYFILL_HAVE_FORK true

#else

// polyfill.h provides implementations of used POSIX functions for non-POSIX
// systems.

#define POLYFILL_HAVE_FORK false

#define WIN32_LEAN_AND_MEAN
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#include <winsock2.h>

#ifndef __MINGW32__
// Windows's read() function returns int.
typedef int ssize_t;

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

typedef int pid_t;
#endif // __MINGW32__

struct pollfd;

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
#define WIFEXITED(x)   0
#define WEXITSTATUS(x) 0
#define WNOHANG        0

// POSIX pipe(2)
int pipe(int pipefd[2]);

// POSIX nanosleep(2)
int nanosleep(const struct timespec* req, struct timespec* rem);

// POSIX poll(2) approximated with select
int poll(struct pollfd* p, int num, int timeout);

// Not actually implemented. Disabled on Windows.
int fork();

int gettimeofday(struct timeval* tp, struct timezone* tzp);

// When POLYFILL_HAVE_FORK is 0, these do nothing and are never called.
// They only exist to prevent linker errors.
int wait(int* status);
int waitpid(int pid, int* status, int options);
int kill(int pid, int sig);

int sigaction(int signum, const struct sigaction* act,
		struct sigaction* oldact);

int setrlimit(int resource, const struct rlimit* rlim);
int getrlimit(int resource, struct rlimit* rlim);

#endif // defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE < 200809L
#endif // POLYFILL_H
