// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi
#include <stdint.h>
#include <stdio.h>

#include "polyfill.h"

#ifdef _WIN32

int
pipe(int pipefd[2])
{
	return _pipe(pipefd, BUFSIZ, O_BINARY);
}

int
nanosleep(const struct timespec* req, struct timespec* rem)
{
	(void)rem;
	DWORD ms = (req->tv_sec * 1000) + (req->tv_nsec / 1000000);
	Sleep(ms);
	return 0;
}

// likely very buggy "works on my machine" type of code.
int
poll(struct pollfd* p, int num, int timeout)
{
	struct timeval tv;
	fd_set         read, write, except;
	int            i, n, ret;

	FD_ZERO(&read);
	FD_ZERO(&write);
	FD_ZERO(&except);

	n = -1;
	for (i = 0; i < num; i++) {
		if (p[i].fd < 0)
			continue;
		if (p[i].events & POLLIN) {
			FD_SET(p[i].fd, &read);
		}
		if (p[i].events & POLLOUT) {
			FD_SET(p[i].fd, &write);
		}
		if (p[i].events & POLLERR) {
			FD_SET(p[i].fd, &except);
		}
		if (p[i].fd > n) {
			n = p[i].fd;
		}
	}

	if (n == -1) {
		return 0;
	}

	if (timeout < 0) {
		ret = select(n + 1, &read, &write, &except, NULL);
	} else {
		tv.tv_sec  = timeout / 1000;
		tv.tv_usec = 1000 * (timeout % 1000);
		ret        = select(n + 1, &read, &write, &except, &tv);
	}

	for (i = 0; ret >= 0 && i < num; i++) {
		p[i].revents = 0;
		if (FD_ISSET(p[i].fd, &read))
			p[i].revents |= POLLIN;
		if (FD_ISSET(p[i].fd, &write))
			p[i].revents |= POLLOUT;
		if (FD_ISSET(p[i].fd, &except))
			p[i].revents |= POLLERR;
	}
	return (ret);
}

int
fork()
{
	errno = ENOSYS;
	return -1;
}

int
kill(int pid, int sig)
{
	(void)pid;
	(void)sig;
	errno = ENOSYS;
	return -1;
}

int
wait(int* status)
{
	(void)status;
	errno = ENOSYS;
	return -1;
}

int
waitpid(int pid, int* status, int options)
{
	(void)pid;
	(void)status;
	(void)options;
	errno = ENOSYS;
	return -1;
}

int
sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
	(void)signum;
	(void)act;
	(void)oldact;
	errno = ENOSYS;
	return -1;
}

int
setrlimit(int resource, const struct rlimit* rlim)
{
	(void)resource;
	(void)rlim;
	errno = ENOSYS;
	return -1;
}

int
getrlimit(int resource, struct rlimit* rlim)
{
	(void)resource;
	(void)rlim;
	return -1;
}

int
gettimeofday(struct timeval* tp, struct timezone* tzp)
{
	(void)tzp;
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME system_time = {0};
	FILETIME   file_time   = {0};
	uint64_t   time        = 0;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec  = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}

#endif // _WIN32
