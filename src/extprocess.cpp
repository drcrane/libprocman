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

static int extprocess_resetpipes(int * pipes_ptr) {
	int rc;
	if (pipes_ptr[0] != -1) {
		rc = close(pipes_ptr[0]);
		pipes_ptr[0] = -1;
		if (rc != 0) {
			return -1;
		}
	}
	if (pipes_ptr[1] != -1) {
		rc = close(pipes_ptr[1]);
		pipes_ptr[1] = -1;
		if (rc != 0) {
			return -1;
		}
	}
	return 0;
}

static int extprocess_configurepipes(int * pipes_ptr) {
	int rc = pipe2(pipes_ptr, O_CLOEXEC);
	if (rc == -1) {
		return -1;
	}
	int flags = fcntl(pipes_ptr[0], F_GETFL, 0);
	if (flags == -1) {
		extprocess_resetpipes(pipes_ptr);
		return -1;
	}
	flags |= O_NONBLOCK;
	rc = fcntl(pipes_ptr[0], F_SETFL, flags);
	if (rc == -1) {
		extprocess_resetpipes(pipes_ptr);
		return -1;
	}
	flags = fcntl(pipes_ptr[1], F_GETFD, 0);
	if (flags == -1) {
		extprocess_resetpipes(pipes_ptr);
		return -1;
	}
	flags &= ~FD_CLOEXEC;
	rc = fcntl(pipes_ptr[1], F_SETFD, flags);
	if (rc == -1) {
		extprocess_resetpipes(pipes_ptr);
		return -1;
	}
	return 0;
}

int extprocess_setupsignalhandler() {
	sigset_t mask, oldmask;
	int sfd;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) == -1) {
		perror("sigprocmask");
		return -1;
	}

	sfd = signalfd(-1, &mask, 0);
	int rc = fcntl(sfd, F_SETFD, FD_CLOEXEC);
	if (rc == -1) {
		sigprocmask(SIG_SETMASK, &oldmask, NULL);
		close(sfd);
		return -1;
	}
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

ExtProcessBuffer::ExtProcessBuffer() : CircularBuffer<EXTPROCESS_BUFFER_INIT_SIZE>() {
	int rc = extprocess_configurepipes(m_fds);
	if (rc != 0) {
		throw std::runtime_error("Could not open pipes");
	}
}

ExtProcessBuffer::~ExtProcessBuffer() {
	extprocess_resetpipes(m_fds);
}

void ExtProcessBuffer::close_read() {
	if (m_fds[0] != -1) {
		close(m_fds[0]);
		m_fds[0] = -1;
	}
}

ExtProcess::ExtProcess(uint32_t flags) {
	this->pid = -1;
	this->state = EXTPROCESS_STATE_INIT;
	if (flags & EXTPROCESS_INIT_FLAG_CAPTURESTDOUT) {
		this->stdoutbuf = std::make_unique<ExtProcessBuffer>();
	}
	if (flags & EXTPROCESS_INIT_FLAG_CAPTURESTDERR) {
		this->stderrbuf = std::make_unique<ExtProcessBuffer>();
	}
	if (flags & EXTPROCESS_INIT_FLAG_CREATEHEARTBEAT) {
		this->heartbeatbuf = std::make_unique<ExtProcessBuffer>();
	}
}

ExtProcess::~ExtProcess() {
}

void ExtProcess::spawn(std::string cmd, std::vector<std::string> argv) {
	std::vector<char *> argv_charptr{};
	argv_charptr.reserve(argv.size());
	for (std::string& arg : argv) {
		argv_charptr.push_back(arg.data());
	}
	argv_charptr.push_back(NULL);
	assert(state == EXTPROCESS_STATE_INIT);
	int rc;
	pid_t parentpid = getpid();
	pid_t pid = fork();
	if (pid < 0) {
		throw std::runtime_error("Could not fork");
	}
	if (pid == 0) {
		// this is the child
		pid_t ppid;
		{
			signal(SIGQUIT, SIG_DFL);
			signal(SIGTERM, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGCHLD, SIG_DFL);
			sigset_t new_mask;
			sigemptyset(&new_mask);
			sigprocmask(SIG_SETMASK, &new_mask, NULL);
		}
		if (stdoutbuf != nullptr && stdoutbuf->m_fds[1] != -1) {
			int rc = close(stdoutbuf->m_fds[0]);
			fprintf(stderr, "close() parent fd %d: %d %d %s\n", stdoutbuf->m_fds[0], rc, errno, strerror(errno));
			stdoutbuf->m_fds[0] = -1;
			dup2(stdoutbuf->m_fds[1], 1);
			close(stdoutbuf->m_fds[1]);
		}
		if (stderrbuf != nullptr && stderrbuf->m_fds[1] != -1) {
			int rc = close(stderrbuf->m_fds[0]);
			fprintf(stderr, "close() parent fd %d: %d %d %s\n", stderrbuf->m_fds[0], rc, errno, strerror(errno));
			stderrbuf->m_fds[0] = -1;
			dup2(stderrbuf->m_fds[1], 2);
			close(stderrbuf->m_fds[1]);
		}
		rc = setpgid(0, 0);
		if (rc == -1) { rc = EXTPROCESS_SPAWN_ERROR_SETPGID; goto child_error; }
		rc = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (rc == -1) { rc = EXTPROCESS_SPAWN_ERROR_PRCTL; goto child_error; }
		ppid = getppid();
		if (ppid != parentpid) { rc = EXTPROCESS_SPAWN_ERROR_PARENT_DEAD; goto child_error; }
		rc = execvp(cmd.c_str(), (char * const *)argv_charptr.data());
child_error:
		fprintf(stderr, "spawn error %d %s\n", rc, strerror(errno));
		exit(rc);
	}
	if (stdoutbuf && stdoutbuf->m_fds[1] != -1) {
		rc = close(stdoutbuf->m_fds[1]);
		stdoutbuf->m_fds[1] = -1;
	}
	if (stderrbuf && stderrbuf->m_fds[1] != -1) {
		rc = close(stderrbuf->m_fds[1]);
		stderrbuf->m_fds[1] = -1;
	}
	if (heartbeatbuf && heartbeatbuf->m_fds[1] != -1) {
		rc = close(heartbeatbuf->m_fds[1]);
		heartbeatbuf->m_fds[1] = -1;
	}
	this->pid = pid;
	state = EXTPROCESS_STATE_RUNNING;
}

ExtProcesses::ExtProcesses(int sfd) {
	if (sfd == -1) {
		m_sfd = extprocess_setupsignalhandler();
	} else {
		m_sfd = sfd;
	}
	m_timeout = 1000;
	m_dirty = 1;
}

ExtProcesses::~ExtProcesses() {
	extprocess_releasesignalhandler(m_sfd);
	m_sfd = 0;
}

std::weak_ptr<ExtProcess> ExtProcesses::create_ex(uint8_t flags) {
	return std::weak_ptr<ExtProcess>(m_processes.emplace_back(std::make_shared<ExtProcess>(flags)));
}

void ExtProcesses::add_fd(std::vector<std::pair<size_t, ExtProcessBuffer *>>& bufs, std::vector<struct pollfd>& pollfds, size_t process_idx, int fd, ExtProcessBuffer * buf) {
	struct pollfd& pfd = pollfds.emplace_back();
	pfd.fd = fd;
	pfd.events = POLLIN | POLLHUP;
	pfd.revents = 0;
	bufs.emplace_back(process_idx, buf);
}

int ExtProcesses::maintain() {
	struct signalfd_siginfo siginfo;
	// one extra for the signalfd
	size_t pollfd_len = 1;
	size_t running_process_count = m_running_process_count;
	if (m_dirty) {
		m_poll_fds.clear();
		m_fdbuffers.clear();
		struct pollfd * pollfd = &m_poll_fds.emplace_back();
		pollfd->fd = m_sfd;
		pollfd->events = POLLIN | POLLHUP;
		pollfd->revents = 0;
		size_t processes_len = m_processes.size();
		running_process_count = 0;
		for (size_t process_idx = 0; process_idx < processes_len; ++ process_idx) {
			ExtProcess& curr_proc = *m_processes.at(process_idx).get();
			if (curr_proc.stdoutbuf && curr_proc.stdoutbuf->m_fds[0] != -1) {
				add_fd(m_fdbuffers, m_poll_fds, process_idx, curr_proc.stdoutbuf->m_fds[0], curr_proc.stdoutbuf.get());
				++ pollfd_len;
			}
			if (curr_proc.stderrbuf && curr_proc.stderrbuf->m_fds[0] != -1) {
				add_fd(m_fdbuffers, m_poll_fds, process_idx, curr_proc.stderrbuf->m_fds[0], curr_proc.stderrbuf.get());
				++ pollfd_len;
			}
			if (curr_proc.heartbeatbuf && curr_proc.heartbeatbuf->m_fds[0] != -1) {
				add_fd(m_fdbuffers, m_poll_fds, process_idx, curr_proc.heartbeatbuf->m_fds[0], curr_proc.heartbeatbuf.get());
				++ pollfd_len;
			}
			if (curr_proc.state == EXTPROCESS_STATE_RUNNING || curr_proc.state == EXTPROCESS_STATE_STOPPING_FDCLOSED || curr_proc.state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
				running_process_count += 1;
			}
		}
		m_running_process_count = running_process_count;
	} else {
		pollfd_len = m_poll_fds.size();
	}
	// this should never happen as there should always be m_sfd
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
		int rc = poll(m_poll_fds.data(), pollfd_len, m_timeout);
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
		if (m_poll_fds[pollfd_idx].revents & POLLIN) {
			ExtProcessBuffer * curr_buf = m_fdbuffers.at(pollfd_idx - 1).second;
			auto [ptr, ptr_sz] = curr_buf->prepare_write();
			int rc = read(m_poll_fds[pollfd_idx].fd, ptr, ptr_sz);
			if (rc > 0) {
				curr_buf->commit_write(rc);
			}
//			debug("read() %d from %d\n", rc, curr_ctx->pid);
		} else
		if (m_poll_fds[pollfd_idx].revents & POLLHUP) {
			std::shared_ptr<ExtProcess>& curr_ctx = m_processes.at(m_fdbuffers.at(pollfd_idx - 1).first);
			// a signal could have already set this FD to -1, don't try
			// and close it again
			// this is still required though in the event that a child
			// closes their end of the pipe without terminating
			debug("HUP %d %d %s\n", curr_ctx->pid, m_poll_fds[pollfd_idx].fd, curr_ctx->state == EXTPROCESS_STATE_STOPPING_PROCESSDIED ? "DEFUNCT" : "RUNNING");
			if (curr_ctx->stderrbuf && curr_ctx->stderrbuf->m_fds[0] == m_poll_fds[pollfd_idx].fd) {
				curr_ctx->stderrbuf->close_read();
			}
			if (curr_ctx->stdoutbuf && curr_ctx->stdoutbuf->m_fds[0] == m_poll_fds[pollfd_idx].fd) {
				curr_ctx->stdoutbuf->close_read();
			}
			if (curr_ctx->heartbeatbuf && curr_ctx->heartbeatbuf->m_fds[0] == m_poll_fds[pollfd_idx].fd) {
				curr_ctx->heartbeatbuf->close_read();
			}
			if ((curr_ctx->stdoutbuf == nullptr || curr_ctx->stdoutbuf->m_fds[0] == -1) &&
				(curr_ctx->stderrbuf == nullptr || curr_ctx->stderrbuf->m_fds[0] == -1) &&
				(curr_ctx->heartbeatbuf == nullptr || curr_ctx->heartbeatbuf->m_fds[0] == -1)) {
				if (curr_ctx->state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
					curr_ctx->state = EXTPROCESS_STATE_STOPPED;
				} else {
					curr_ctx->state = EXTPROCESS_STATE_STOPPING_FDCLOSED;
				}
			}
			m_dirty = 1;
		}
	}
	if (m_poll_fds[0].revents & POLLIN) {
		ssize_t len = read(m_sfd, &siginfo, sizeof(struct signalfd_siginfo));
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
			size_t processes_len = m_processes.size();
			for (size_t i = 0; i < processes_len; ++ i) {
				ExtProcess * curr_ctx = m_processes.at(i).get();
				if (static_cast<pid_t>(siginfo.ssi_pid) == curr_ctx->pid) {
					int pstatus = 0;
					pid_t chldpid = waitpid(curr_ctx->pid, &pstatus, WNOHANG | WUNTRACED | WCONTINUED);
					if (chldpid < 0) {
						debug("waitpid %s\n", strerror(errno));
					}
					if (chldpid > 0) {
						if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {
							if (curr_ctx->state == EXTPROCESS_STATE_STOPPING_FDCLOSED) {
								curr_ctx->state = EXTPROCESS_STATE_STOPPED;
								running_process_count --;
								m_dirty = 1;
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
	for (const std::shared_ptr<ExtProcess>& proc : m_processes) {
		if (proc->state == EXTPROCESS_STATE_RUNNING || proc->state == EXTPROCESS_STATE_STOPPING_FDCLOSED || proc->state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
			count ++;
		}
	}
	return count;
}

void ExtProcesses::clear() {
	m_processes.clear();
}

