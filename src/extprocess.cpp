#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "extprocess.hpp"
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/signalfd.h>

#include <vector>
#include <string>
#include <stdexcept>


#define debug(...) fprintf(stderr, __VA_ARGS__)

int extprocess_init(extprocess_context * ctx, uint32_t flags) {
	ctx->pid = -1;
	ctx->state = EXTPROCESS_STATE_INIT;
	ctx->redirectfd = -1;
	if (flags & EXTPROCESS_INIT_FLAG_CAPTURESTDOUT) {
		//if (pipe2(ctx->stdoutfds, O_NONBLOCK) == -1) {
		if (pipe(ctx->stdoutfds) == -1) {
			return -1;
		}
		int flags = fcntl(ctx->stdoutfds[0], F_GETFL, 0);
		if (flags == -1) {
			close(ctx->stdoutfds[0]);
			close(ctx->stdoutfds[1]);
			ctx->stdoutfds[0] = -1;
			ctx->stdoutfds[1] = -1;
			return -1;
		}
		flags |= O_NONBLOCK;
		if (fcntl(ctx->stdoutfds[0], F_SETFL, flags) == -1) {
			close(ctx->stdoutfds[0]);
			close(ctx->stdoutfds[1]);
			ctx->stdoutfds[0] = -1;
			ctx->stdoutfds[1] = -1;
			return -1;
		}
		ctx->redirectfd = 1;
	}
	if (flags & EXTPROCESS_INIT_FLAG_CAPTURESTDERR && pipe(ctx->stderrfds) == -1) {
		close(ctx->stdoutfds[0]);
		close(ctx->stdoutfds[1]);
		return -1;
	}
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

ExtProcesses::ExtProcesses(int sfd) {
	if (sfd == -1) {
		sfd_ = extprocess_setupsignalhandler();
	} else {
		sfd_ = sfd;
	}
	timeout_ = 1000;
}

ExtProcesses::~ExtProcesses() {
	extprocess_releasesignalhandler(sfd_);
	sfd_ = 0;
}

extprocess_context * ExtProcesses::create(uint8_t flags) {
	extprocess_context * proc = NULL;
	for (extprocess_context& ctx : processes_) {
		if (ctx.state == EXTPROCESS_STATE_FINISHED) {
			proc = &ctx;
			break;
		}
	}
	if (proc == NULL) {
		proc = &processes_.emplace_back();
	}
	int rc = extprocess_init(proc, flags);
	if (rc != 0) {
		throw std::runtime_error("extprocess_init() failure");
	}
	return proc;
}

int ExtProcesses::spawn(extprocess_context * proc, std::string cmd, std::vector<std::string> argv) {
	std::vector<char *> argv_charptr{};
	argv_charptr.reserve(argv.size());
	for (std::string& arg : argv) {
		argv_charptr.push_back(arg.data());
	}
	argv_charptr.push_back(NULL);
	int rc = extprocess_spawn(proc, cmd.c_str(), argv_charptr.data());
	if (rc != 0) {
		throw std::runtime_error("ExtProcesses: extprocess_spawn() " + std::to_string(rc) + " " + strerror(errno));
	}
	return rc;
}

int ExtProcesses::maintain() {
	struct signalfd_siginfo siginfo;
	// one extra for the signalfd
	size_t fd_count = processes_.size() + 1;
	processpollfd_idxs_.resize(0);
	poll_fds_.resize(0);
	fdbuffers_.resize(0);
	struct pollfd * pollfd = &poll_fds_.emplace_back();
	pollfd->fd = sfd_;
	pollfd->events = POLLIN | POLLHUP;
	pollfd->revents = 0;
	size_t processes_len = this->processes_.size();
	size_t pollfd_len = 1;
	size_t running_process_count = 0;
	for (size_t process_idx = 0; process_idx < processes_len; ++ process_idx) {
		extprocess_context& currproc = processes_.at(process_idx);
		if (currproc.stdoutfds[0] != -1) {
			struct pollfd& pfd = poll_fds_.emplace_back();
			pfd.fd = currproc.stdoutfds[0];
			pfd.events = POLLIN | POLLHUP;
			pfd.revents = 0;
			processpollfd_idxs_.emplace_back(pollfd_len) = process_idx;
			fdbuffers_.emplace_back(process_idx, &currproc.stdoutbuf);
			++ pollfd_len;
		}
		if (currproc.state == EXTPROCESS_STATE_RUNNING || currproc.state == EXTPROCESS_STATE_STOPPING_FDCLOSED || currproc.state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
			running_process_count += 1;
		}
	}
	// this should never happen as there should always be sfd_
	int res = 0;
	if (!pollfd_len) {
		throw std::runtime_error("ExtProcesses: maintain() pollfd_len == 0");
		res = -1;
		goto finish;
	}
	if (running_process_count == 0) {
		res = 1;
		goto finish;
	}
	{
		int rc = poll(poll_fds_.data(), pollfd_len, timeout_);
		if (rc < 0) {
			if (errno == EINTR) {
				debug("poll() EINTR\n");
			}
			throw std::runtime_error(std::string("ExtProcesses: maintain() poll() ") + strerror(errno));
			res = -1;
			goto finish;
		}
		//debug("poll() %d my pid: %d\n", rc, getpid());
	}
	for (size_t pollfd_idx = 1; pollfd_idx < pollfd_len; ++ pollfd_idx) {
		if (poll_fds_[pollfd_idx].revents & POLLIN) {
			ExtProcessBuffer * curr_buf = fdbuffers_.at(pollfd_idx - 1).second;
			auto [ptr, ptr_sz] = curr_buf->prepare_write();
			int rc = read(poll_fds_[pollfd_idx].fd, ptr, ptr_sz);
			if (rc > 0) {
				curr_buf->commit_write(rc);
			}
//			debug("read() %d from %d\n", rc, curr_ctx->pid);
		} else
		if (poll_fds_[pollfd_idx].revents & POLLHUP) {
			extprocess_context * curr_ctx = &processes_.at(fdbuffers_.at(pollfd_idx - 1).first);
			// a signal could have already set this FD to -1, don't try
			// and close it again
			// this is still required though in the event that a child
			// closes their end of the pipe without terminating
			debug("HUP %d %s\n", curr_ctx->pid, curr_ctx->state == EXTPROCESS_STATE_STOPPING_PROCESSDIED ? "DEFUNCT" : "RUNNING");
			if (curr_ctx->stdoutfds[0] != -1) {
				close(curr_ctx->stdoutfds[0]);
				curr_ctx->stdoutfds[0] = -1;
				if (curr_ctx->state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
					curr_ctx->state = EXTPROCESS_STATE_STOPPED;
				} else {
					curr_ctx->state = EXTPROCESS_STATE_STOPPING_FDCLOSED;
				}
			}
		}
	}
	if (poll_fds_[0].revents & POLLIN) {
		ssize_t len = read(sfd_, &siginfo, sizeof(struct signalfd_siginfo));
		if (len < 0) {
			throw std::runtime_error(std::string("ExtProcesses: maintain() read(sfd_) ") + strerror(errno));
			res = -2;
			goto finish;
		}
		if (len == 0) {
			throw std::runtime_error("ExtProcesses: maintain() read(sfd_) == 0");
			res = -3;
			goto finish;
		}
		if (siginfo.ssi_signo == SIGCHLD) {
			debug("SIGCHLD for %d\n", siginfo.ssi_pid);
			for (size_t i = 0; i < processes_len; ++ i) {
				extprocess_context * curr_ctx = &processes_[i];
				if (static_cast<pid_t>(siginfo.ssi_pid) == curr_ctx->pid) {
					int pstatus = 0;
					pid_t chldpid = waitpid(curr_ctx->pid, &pstatus, WNOHANG | WUNTRACED | WCONTINUED);
					if (chldpid < 0) {
						//debug("waitpid %s\n", strerror(errno));
					}
					if (chldpid > 0) {
						if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {
							if (curr_ctx->state == EXTPROCESS_STATE_STOPPING_FDCLOSED) {
								curr_ctx->state = EXTPROCESS_STATE_STOPPED;
								running_process_count --;
							} else {
								curr_ctx->state = EXTPROCESS_STATE_STOPPING_PROCESSDIED;
							}
						}
						if (WIFSTOPPED(pstatus)) {
							debug("STOPPED\n");
						}
						if (WIFCONTINUED(pstatus)) {
							debug("CONTINUED\n");
						}
						curr_ctx->exitstatus = pstatus;
						if (running_process_count == 0) {
							res = 1;
						}
					}
				}
			}
		} else if (siginfo.ssi_signo == SIGINT) {
			debug("SIGINT\n");
			res = -1;
			goto finish;
		}
	}
finish:
	return res;
}

const int ExtProcesses::runningcount() const {
	size_t count = 0;
	for (const extprocess_context& proc : processes_) {
		if (proc.state == EXTPROCESS_STATE_RUNNING || proc.state == EXTPROCESS_STATE_STOPPING_FDCLOSED || proc.state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
			count ++;
		}
	}
	return count;
}

int ExtProcesses::cleanup() {
	size_t count = 0;
	for (extprocess_context& proc : processes_) {
		if (proc.state == EXTPROCESS_STATE_INIT) {
			// In the init state there are open file descriptors, close them
			if (proc.stderrfds[0] != -1) {
				close(proc.stderrfds[0]);
				close(proc.stderrfds[1]);
				proc.stderrfds[0] = -1;
				proc.stderrfds[1] = -1;
			}
			if (proc.stdoutfds[0] != -1) {
				close(proc.stdoutfds[0]);
				close(proc.stdoutfds[1]);
				proc.stdoutfds[0] = -1;
				proc.stdoutfds[1] = -1;
			}
			proc.state = EXTPROCESS_STATE_FINISHED;
		}
		if (proc.state == EXTPROCESS_STATE_STOPPED || proc.state == EXTPROCESS_STATE_FINISHED) {
			count += 1;
		}
	}
	if (processes_.size() == count) {
		processes_.resize(0);
		return 0;
	}
	return -1;
}

