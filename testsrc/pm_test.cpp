#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "extprocess.hpp"
#include <string.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <time.h>
#include <poll.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static int64_t _get_monotonic_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000LL + ((int64_t)ts.tv_nsec / 1000000);
}

ExtProcesses monitoredprocesses{-1};

volatile sig_atomic_t should_quit;
volatile sig_atomic_t should_term;

void sigquit_handler(int sig, siginfo_t * info, void * context) {
	should_quit = 1;
}

void sigterm_handler(int sig) {
	should_term = 1;
}

int producer_main(int argc, char *argv[]) {
	struct sigaction sa;
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sigterm_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sa.sa_sigaction = sigquit_handler;
	sigaction(SIGQUIT, &sa, NULL);

	fprintf(stderr, "%s Process %d\n", argv[0], getpid());
	if (argc >= 3) {
		if (strcmp(argv[2], "fast") == 0) {
			while (!should_quit && !should_term) {
				write(STDOUT_FILENO, "01234567", 8);
			}
		}
		if (strcmp(argv[2], "fastignoresignals") == 0) {
			do {
				write(STDOUT_FILENO, "01234567", 8);
			} while (1);
		}
		if (strcmp(argv[2], "none") == 0) {
			sleep(3);
			fprintf(stderr, "Closing STDOUT\n");
			close(STDOUT_FILENO);
			sleep(3);
		}
		if (strcmp(argv[2], "justsleep") == 0) {
			do {
				sleep(4096);
			} while(1);
		}
		if (strcmp(argv[2], "sleepandproduce") == 0) {
			do {
				sleep(3);
				write(STDOUT_FILENO, "0123456789012345", 16);
			} while (!should_quit && !should_term);
		}
	}
	fprintf(stderr, "%d (%s) Terminating\n", getpid(), argv[0]);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc >= 2) {
		if (strcmp(argv[1], "producer") == 0) {
			return producer_main(argc, argv);
		}
	}

	extprocess_context * startup = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	startup->redirectfd = 1;
	monitoredprocesses.spawn(startup, argv[0], "startupprocess", "producer", "none");
	extprocess_context * sleeper = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	sleeper->redirectfd = 1;
	monitoredprocesses.spawn(sleeper, argv[0], "sleeper", "producer", "sleepandproduce");

	int rc;
	int64_t start_time = _get_monotonic_time_ms();
	do {
		rc = monitoredprocesses.maintain();
		if (_get_monotonic_time_ms() - start_time > 4000) {
			kill(sleeper->pid, SIGKILL);
		}
	} while (rc == 0);
	int64_t end_time = _get_monotonic_time_ms();

	fprintf(stderr, "start_time: %lld\nend_time:   %lld\n", start_time, end_time);

	return 0;
}

