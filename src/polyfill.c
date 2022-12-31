// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi

extern int errno;

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#undef WIN32_LEAN_AND_MEAN

#include "poll_windows.h"
#include "polyfill.h"

int
pipe(int pipefd[2])
{
	return _pipe(pipefd, BUFSIZ, O_BINARY);
}

int
nanosleep(const struct timespec* req, struct timespec* rem)
{
	(void)rem;
	time_t ms = (req->tv_sec * 1000) + (req->tv_nsec / 1000000);
	if (ms > UINT32_MAX) {
		Sleep(UINT32_MAX);
		return 0;
	}
	Sleep((DWORD)ms);
	return 0;
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

// Public domain
//
// poll(2) emulation for Windows from LibreSSL
//
// This emulates just-enough poll functionality on Windows to work in the
// context of the openssl(1) program. This is not a replacement for
// POSIX.1-2001 poll(2), though it may come closer than I care to admit.
//
// Dongsheng Song <dongsheng.song@gmail.com>
// Brent Cook <bcook@openbsd.org>

#include <conio.h>
#include <errno.h>
#include <io.h>
#include <ws2tcpip.h>

static int
conn_is_closed(SOCKET fd)
{
	char buf[1];
	int  ret = recv(fd, buf, 1, MSG_PEEK);
	if (ret == -1) {
		switch (WSAGetLastError()) {
		case WSAECONNABORTED:
		case WSAECONNRESET:
		case WSAENETRESET:
		case WSAESHUTDOWN:
			return 1;
		}
	}
	return 0;
}

static int
conn_has_oob_data(SOCKET fd)
{
	char buf[1];
	return (recv(fd, buf, 1, MSG_PEEK | MSG_OOB) == 1);
}

static int
is_socket(SOCKET fd)
{
	if (fd < 3)
		return 0;
	WSANETWORKEVENTS events;
	return (WSAEnumNetworkEvents(fd, NULL, &events) == 0);
}

static SHORT
compute_select_revents(SOCKET fd, short events, fd_set* rfds, fd_set* wfds,
		fd_set* efds)
{
	SHORT rc = 0;

	if ((events & (POLLIN | POLLRDNORM | POLLRDBAND)) &&
			FD_ISSET(fd, rfds)) {
		if (conn_is_closed(fd))
			rc |= POLLHUP;
		else
			rc |= POLLIN | POLLRDNORM;
	}

	if ((events & (POLLOUT | POLLWRNORM | POLLWRBAND)) &&
			FD_ISSET(fd, wfds))
		rc |= POLLOUT;

	if (FD_ISSET(fd, efds)) {
		if (conn_is_closed(fd))
			rc |= POLLHUP;
		else if (conn_has_oob_data(fd))
			rc |= POLLRDBAND | POLLPRI;
	}

	return rc;
}

static SHORT
compute_wait_revents(HANDLE h, short events, int object, int wait_rc)
{
	SHORT        rc = 0;
	INPUT_RECORD record;
	DWORD        num_read;

	// Assume we can always write to file handles (probably a bad
	// assumption but works for now, at least it doesn't block).
	if (events & (POLLOUT | POLLWRNORM)) {
		rc |= POLLOUT;
	}

	// Check if this handle was signaled by WaitForMultipleObjects
	if ((DWORD)wait_rc >= WAIT_OBJECT_0 &&
			(object == (int)(wait_rc - WAIT_OBJECT_0)) &&
			(events & (POLLIN | POLLRDNORM))) {

		// Check if this file is stdin, and if so, if it is a console.
		if (h == GetStdHandle(STD_INPUT_HANDLE) &&
				PeekConsoleInput(h, &record, 1, &num_read) ==
						1) {

			// Handle the input console buffer differently,
			// since it can signal on other events like
			// window and mouse, but read can still block.
			if (record.EventType == KEY_EVENT &&
					record.Event.KeyEvent.bKeyDown) {
				rc |= POLLIN;
			} else {
				// Flush non-character events from the
				// console buffer.
				ReadConsoleInput(h, &record, 1, &num_read);
			}
		} else {
			rc |= POLLIN;
		}
	}

	return rc;
}

static int
wsa_select_errno(int err)
{
	switch (err) {
	case WSAEINTR:
	case WSAEINPROGRESS:
		errno = EINTR;
		break;
	case WSAEFAULT:
		// Windows uses WSAEFAULT for both resource allocation failures
		// and arguments not being contained in the user's address
		// space. So, we have to choose EFAULT or ENOMEM.
		errno = EFAULT;
		break;
	case WSAEINVAL:
		errno = EINVAL;
		break;
	case WSANOTINITIALISED:
		errno = EPERM;
		break;
	case WSAENETDOWN:
		errno = ENOMEM;
		break;
	}
	return -1;
}

int
poll(struct pollfd* pfds, nfds_t nfds, int timeout_ms)
{
	nfds_t i;
	int    timespent_ms, looptime_ms;

	// select machinery
	fd_set rfds, wfds, efds;
	int    rc;
	int    num_sockets;

	// wait machinery
	DWORD  wait_rc;
	HANDLE handles[FD_SETSIZE];
	int    num_handles;

	if (pfds == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (nfds <= 0) {
		return 0;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	num_sockets = 0;
	num_handles = 0;

	for (i = 0; i < nfds; i++) {
		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {
			if (num_sockets >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			FD_SET(pfds[i].fd, &efds);

			if (pfds[i].events &
					(POLLIN | POLLRDNORM | POLLRDBAND)) {
				FD_SET(pfds[i].fd, &rfds);
			}

			if (pfds[i].events &
					(POLLOUT | POLLWRNORM | POLLWRBAND)) {
				FD_SET(pfds[i].fd, &wfds);
			}
			num_sockets++;

		} else {
			if (num_handles >= FD_SETSIZE) {
				errno = EINVAL;
				return -1;
			}

			handles[num_handles++] = (HANDLE)_get_osfhandle(
					(int)pfds[i].fd);
		}
	}

	// Determine if the files, pipes, sockets, consoles, etc. have signaled.
	//
	// Do this by alternating a loop between WaitForMultipleObjects for
	// non-sockets and and select for sockets.
	//
	// I tried to implement this all in terms of WaitForMultipleObjects
	// with a select-based 'poll' of the sockets at the end to get extra
	// specific socket status.
	//
	// However, the cost of setting up an event handle for each socket and
	// cleaning them up reliably was pretty high. Since the event handle
	// associated with a socket is also global, creating a new one here
	// cancels one that may exist externally to this function.
	//
	// At any rate, even if global socket event handles were not an issue,
	// the 'FD_WRITE' status of a socket event handle does not behave in an
	// expected fashion, being triggered by an edge on a write buffer rather
	// than simply triggering if there is space available.
	timespent_ms = 0;
	wait_rc      = WAIT_FAILED;

	if (timeout_ms < 0)
		timeout_ms = INFINITE;
	looptime_ms = timeout_ms > 100 ? 100 : timeout_ms;

	do {
		struct timeval tv;
		tv.tv_sec           = 0;
		tv.tv_usec          = looptime_ms * 1000;
		int handle_signaled = 0;

		// Check if any file handles have signaled
		if (num_handles) {
			wait_rc = WaitForMultipleObjects(
					num_handles, handles, FALSE, 0);
			if (wait_rc == WAIT_FAILED) {
				// The documentation for WaitForMultipleObjects
				// does not specify what values GetLastError
				// may return here. Rather than enumerate
				// badness like for wsa_select_errno, assume a
				// general errno value.
				errno = ENOMEM;
				return 0;
			}
		}

		// If we signaled on a file handle, don't wait on the sockets.
		if (wait_rc >= WAIT_OBJECT_0 &&
				(wait_rc <= WAIT_OBJECT_0 + num_handles - 1)) {
			tv.tv_usec      = 0;
			handle_signaled = 1;
		}

		// Check if any sockets have signaled
		rc = select(0, &rfds, &wfds, &efds, &tv);
		if (!handle_signaled && rc == SOCKET_ERROR)
			return wsa_select_errno(WSAGetLastError());

		if (handle_signaled || (num_sockets && rc > 0))
			break;

		timespent_ms += looptime_ms;

	} while (timespent_ms < timeout_ms);

	rc          = 0;
	num_handles = 0;
	for (i = 0; i < nfds; i++) {
		pfds[i].revents = 0;

		if ((int)pfds[i].fd < 0)
			continue;

		if (is_socket(pfds[i].fd)) {

			pfds[i].revents = compute_select_revents(pfds[i].fd,
					pfds[i].events, &rfds, &wfds, &efds);

		} else {
			pfds[i].revents = compute_wait_revents(
					handles[num_handles], pfds[i].events,
					num_handles, wait_rc);
			num_handles++;
		}

		if (pfds[i].revents)
			rc++;
	}

	return rc;
}

#endif
