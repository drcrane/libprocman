#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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

#include <memory>

#include "extprocess.hpp"
#include "minunit.h"

static int64_t _get_monotonic_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000LL + ((int64_t)ts.tv_nsec / 1000000);
}

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
		if (strcmp(argv[2], "quickquit") == 0) {
			sleep(1);
			fprintf(stderr, "Quitting...\n");
			sleep(1);
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

std::unique_ptr<ExtProcesses> monitoredprocesses;
//ExtProcesses& monitoredprocesses = nullptr;

const char * unredirected_child_with_self_termination_test(ExtProcesses& monitoredprocesses, int argc, char *argv[]) {
	extprocess_context * simplechild = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	monitoredprocesses.spawn(simplechild, argv[0], "simplechild", "producer", "quickquit");
	int rc;
	int64_t start_time;
	start_time = _get_monotonic_time_ms();
	do {
		rc = monitoredprocesses.maintain();
		if (_get_monotonic_time_ms() - start_time > 4000) {
			kill(simplechild->pid, SIGKILL);
			return "Process did not quit in appropriate time";
		}
	} while (rc == 0);
	return NULL;
}

int main(int argc, char *argv[]) {
	if (argc >= 2) {
		if (strcmp(argv[1], "producer") == 0) {
			return producer_main(argc, argv);
		}
	}

	//monitoredprocesses = std::make_unique<ExtProcesses>(-1);
	ExtProcesses monitoredprocesses{-1};

	int rc;
	int64_t start_time;
	int64_t end_time;

	const char * res;
	if ((res = unredirected_child_with_self_termination_test(monitoredprocesses, argc, argv))) { fprintf(stderr, "FAILED: %s\n", res); }

	#define TEST1
	#define TEST2
	#define TEST3

	#ifdef TEST1
	extprocess_context * startup = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	monitoredprocesses.spawn(startup, argv[0], "startupprocess", "producer", "none");
	extprocess_context * sleeper = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	monitoredprocesses.spawn(sleeper, argv[0], "sleeper", "producer", "sleepandproduce");

	start_time = _get_monotonic_time_ms();
	do {
		rc = monitoredprocesses.maintain();
		if (_get_monotonic_time_ms() - start_time > 4000) {
			kill(sleeper->pid, SIGKILL);
		}
	} while (rc == 0);
	end_time = _get_monotonic_time_ms();

	fprintf(stderr, "PROCESS COUNT should now be 0 actual = %d\n", monitoredprocesses.runningcount());

	rc = monitoredprocesses.cleanup();
	fprintf(stderr, "Cleanup Successful %s\n", rc == 0 ? "Yes" : "No");
	#endif

	#ifdef TEST2
	fprintf(stderr, "start_time: %lld\nend_time:   %lld\n", (long long int)start_time, (long long int)end_time);

	extprocess_context * fastproducer = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	monitoredprocesses.spawn(fastproducer, argv[0], "fastproducer", "producer", "fast");

	start_time = _get_monotonic_time_ms();
	int64_t notify_time = 0;
	do {
		rc = monitoredprocesses.maintain();
		if (_get_monotonic_time_ms() - notify_time > 1000) {
			fprintf(stderr, "size() %d\n", (int)fastproducer->stdoutbuf.size());
			notify_time = _get_monotonic_time_ms();
		}
		if (_get_monotonic_time_ms() - start_time > 5000) {
			kill(fastproducer->pid, SIGTERM);
		}
	} while (rc == 0);

	rc = monitoredprocesses.cleanup();

	fprintf(stderr, "cleanup() %d\n", rc);
	#endif

	#ifdef TEST3
	extprocess_context * readfile = monitoredprocesses.create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	monitoredprocesses.spawn(readfile, "cat", "cat", "inputfile.bin");

	int outfd = open("outputfile.bin", O_TRUNC | O_CREAT | O_RDWR, 0644);
	fprintf(stderr, "fd %d\n", outfd);
	do {
		rc = monitoredprocesses.maintain();
		//fprintf(stderr, "%d ", (int)readfile->stdoutbuf.size());
		// loop for the times when the buffer overlaps the end
		while (readfile->stdoutbuf.size() > 0) {
			auto [ptr, ptr_sz] = readfile->stdoutbuf.prepare_read();
			//fprintf(stderr, "prepare_read() %p %d\n", ptr, ptr_sz);
			if (ptr_sz == 0) {
				fprintf(stderr, "should never be 0!\n");
				break;
			}
			int wrc = write(outfd, ptr, ptr_sz);
			if (wrc <= 0) {
				fprintf(stderr, "BORKED %d %s\n", errno, strerror(errno));
				break;
			}
			if (wrc > 0) {
				readfile->stdoutbuf.commit_read(ptr_sz);
			}
		}
	} while (rc == 0);
	close(outfd);
	outfd = -1;
	fprintf(stderr, "EXIT STATUS: %08x\n", WEXITSTATUS(readfile->exitstatus));
	fprintf(stderr, "OUTPUT BUFFER SIZE %d\n", (int)readfile->stdoutbuf.size());

	rc = monitoredprocesses.cleanup();
	fprintf(stderr, "cleanup() %d\n", rc);
	#endif

/*
	extprocess_context * startup = monitoredprocesses->create(EXTPROCESS_INIT_FLAG_CAPTURESTDOUT);
	monitoredprocesses->spawn(startup, argv[0], "startupprocess", "producer", "none");

	do {
		rc = monitoredprocesses->maintain();
		sleep(1);
	} while (rc != -1);
*/

	return 0;
}

