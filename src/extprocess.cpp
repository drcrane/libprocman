#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "extprocess.h"
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

int extprocess_init(extprocess_context * ctx) {
	ctx->pid = -1;
	ctx->state = EXTPROCESS_STATE_INIT;
	char * buffer = (char *)malloc(EXTPROCESS_BUFFER_INIT_SIZE);
	if (buffer == NULL) {
		errno = ENOMEM;
		return -1;
	}
	if (pipe2(ctx->stdoutfds, O_NONBLOCK) == -1) {
		free(buffer);
		return -1;
	}
	ctx->stdoutbuffer = buffer;
	ctx->stdoutcapacity = EXTPROCESS_BUFFER_INIT_SIZE;
	ctx->stdoutsize = 0;
	ctx->redirectfd = -1;
	return 0;
}

int extprocess_spawn(extprocess_context * ctx, const char * cmd, char * argv[]) {
	int rc;
	assert(ctx->state == EXTPROCESS_STATE_INIT);
	pid_t parentpid = getpid();
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		// this is the child
		pid_t ppid;
		close(ctx->stdoutfds[0]);
		ctx->stdoutfds[0] = -1;
		if (ctx->redirectfd != -1 && ctx->redirectfd != ctx->stdoutfds[1]) {
			dup2(ctx->stdoutfds[1], ctx->redirectfd);
			close(ctx->stdoutfds[1]);
		}
		rc = setpgid(0, 0);
		if (rc == -1) { rc = EXTPROCESS_SPAWN_ERROR_SETPGID; goto child_error; }
		rc = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (rc == -1) { rc = EXTPROCESS_SPAWN_ERROR_PRCTL; goto child_error; }
		ppid = getppid();
		if (ppid != parentpid) { rc = EXTPROCESS_SPAWN_ERROR_PARENT_DEAD; goto child_error; }
		rc = execvp(cmd, (char * const *)argv);
child_error:
		fprintf(stderr, "spawn error %d %s\n", rc, strerror(errno));
		exit(rc);
	}
	close(ctx->stdoutfds[1]);
	ctx->stdoutfds[1] = -1;
	rc = fcntl(ctx->stdoutfds[0], F_SETFD, FD_CLOEXEC);
	if (rc < 0) {
		kill(pid, SIGKILL);
		close(ctx->stdoutfds[0]);
		ctx->stdoutfds[0] = -1;
		return -1;
	}
	ctx->pid = pid;
	ctx->state = EXTPROCESS_STATE_RUNNING;
	return 0;
}

int extprocess_setupsignalhandler() {
	sigset_t mask;
	int sfd;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		perror("sigprocmask");
		return -1;
	}

	sfd = signalfd(-1, &mask, 0);
	return sfd;
}

int extprocess_releasesignalhandler(int sfd) {
	sigset_t mask;
	close(sfd);
	sigemptyset(&mask);
	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		perror("sigprocmask");
		return -1;
	}
	return 0;
}

