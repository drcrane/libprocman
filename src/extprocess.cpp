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

//#define debug(a, ...) fprintf(stderr, a "\n", ##__VA_ARGS__)
#define debug(...)

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

static int extprocess_setupsignalhandler() {
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

static int extprocess_releasesignalhandler(int sfd) {
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

std::string ExtProcessBuffer::drain_to_string() {
	std::string output;
	output.resize(this->size());
	size_t pos = 0;
	while (this->size() > 0) {
		auto [ptr, ptr_sz] = this->prepare_read();
		if (ptr == nullptr) {
			throw new std::runtime_error("ExtProcessBuffer: size() > 0 but prepare_read() NULL");
		}
		memcpy(output.data() + pos, ptr, ptr_sz);
		pos += ptr_sz;
		this->commit_read(ptr_sz);
	}
	return output;
}

ExtProcess::ExtProcess(uint32_t flags) {
	this->m_pid = -1;
	this->m_state = EXTPROCESS_STATE_INIT;
	if (flags & EXTPROCESS_INIT_FLAG_CAPTURESTDOUT) {
		this->m_stdoutbuf = std::make_unique<ExtProcessBuffer>();
	}
	if (flags & EXTPROCESS_INIT_FLAG_CAPTURESTDERR) {
		this->m_stderrbuf = std::make_unique<ExtProcessBuffer>();
	}
	if (flags & EXTPROCESS_INIT_FLAG_CREATEHEARTBEAT) {
		this->m_heartbeatbuf = std::make_unique<ExtProcessBuffer>();
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
	assert(m_state == EXTPROCESS_STATE_INIT);
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
		if (m_stdoutbuf != nullptr && m_stdoutbuf->m_fds[1] != -1) {
			int rc = close(m_stdoutbuf->m_fds[0]);
			fprintf(stderr, "close() parent fd %d: %d %d %s\n", m_stdoutbuf->m_fds[0], rc, errno, strerror(errno));
			m_stdoutbuf->m_fds[0] = -1;
			dup2(m_stdoutbuf->m_fds[1], 1);
			close(m_stdoutbuf->m_fds[1]);
		}
		if (m_stderrbuf != nullptr && m_stderrbuf->m_fds[1] != -1) {
			int rc = close(m_stderrbuf->m_fds[0]);
			fprintf(stderr, "close() parent fd %d: %d %d %s\n", m_stderrbuf->m_fds[0], rc, errno, strerror(errno));
			m_stderrbuf->m_fds[0] = -1;
			dup2(m_stderrbuf->m_fds[1], 2);
			close(m_stderrbuf->m_fds[1]);
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
	if (m_stdoutbuf && m_stdoutbuf->m_fds[1] != -1) {
		rc = close(m_stdoutbuf->m_fds[1]);
		m_stdoutbuf->m_fds[1] = -1;
	}
	if (m_stderrbuf && m_stderrbuf->m_fds[1] != -1) {
		rc = close(m_stderrbuf->m_fds[1]);
		m_stderrbuf->m_fds[1] = -1;
	}
	if (m_heartbeatbuf && m_heartbeatbuf->m_fds[1] != -1) {
		rc = close(m_heartbeatbuf->m_fds[1]);
		m_heartbeatbuf->m_fds[1] = -1;
	}
	this->m_pid = pid;
	m_state = EXTPROCESS_STATE_RUNNING;
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
	if (m_sfd != -1) {
		extprocess_releasesignalhandler(m_sfd);
		m_sfd = -1;
	}
}

ExtProcesses::ExtProcesses(ExtProcesses&& other) noexcept {
	this->m_sfd = other.m_sfd;
	this->m_processes = std::move(other.m_processes);
}

ExtProcesses& ExtProcesses::operator=(ExtProcesses&& other) {
	this->m_processes.clear();
	this->m_processes = std::move(other.m_processes);
	this->m_sfd = other.m_sfd;
	other.m_sfd = -1;
	this->m_dirty = other.m_dirty;
	return *this;
}

std::weak_ptr<ExtProcess> ExtProcesses::create(uint8_t flags) {
	for (std::shared_ptr<ExtProcess>& proc : m_processes) {
		if (proc.get()->m_state == EXTPROCESS_STATE_FINISHED) {
			//
			//return std::weak_ptr(proc);
		}
	}
	m_dirty = 1;
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
		debug("ExtProcesses: rebuilding pollfd vector");
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
			if (curr_proc.m_stdoutbuf && curr_proc.m_stdoutbuf->m_fds[0] != -1) {
				add_fd(m_fdbuffers, m_poll_fds, process_idx, curr_proc.m_stdoutbuf->m_fds[0], curr_proc.m_stdoutbuf.get());
				++ pollfd_len;
			}
			if (curr_proc.m_stderrbuf && curr_proc.m_stderrbuf->m_fds[0] != -1) {
				add_fd(m_fdbuffers, m_poll_fds, process_idx, curr_proc.m_stderrbuf->m_fds[0], curr_proc.m_stderrbuf.get());
				++ pollfd_len;
			}
			if (curr_proc.m_heartbeatbuf && curr_proc.m_heartbeatbuf->m_fds[0] != -1) {
				add_fd(m_fdbuffers, m_poll_fds, process_idx, curr_proc.m_heartbeatbuf->m_fds[0], curr_proc.m_heartbeatbuf.get());
				++ pollfd_len;
			}
			if (curr_proc.m_state == EXTPROCESS_STATE_RUNNING || curr_proc.m_state == EXTPROCESS_STATE_STOPPING_FDCLOSED || curr_proc.m_state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
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
		debug("ExtProcesses: running_process_count == 0");
		goto finish;
	}
	{
		int rc = poll(m_poll_fds.data(), pollfd_len, m_timeout);
		if (rc < 0) {
			if (errno == EINTR) {
				debug("ExtProcesses: poll() EINTR");
			}
			throw std::runtime_error(std::string("ExtProcesses: maintain() poll() ") + strerror(errno));
			res = -1;
			goto finish;
		}
		debug("ExtProcesses: poll() %d my pid: %d", rc, getpid());
	}
	for (size_t pollfd_idx = 1; pollfd_idx < pollfd_len; ++ pollfd_idx) {
		if (m_poll_fds[pollfd_idx].revents & POLLIN) {
			ExtProcessBuffer * curr_buf = m_fdbuffers.at(pollfd_idx - 1).second;
			auto [ptr, ptr_sz] = curr_buf->prepare_write();
			int rc = read(m_poll_fds[pollfd_idx].fd, ptr, ptr_sz);
			if (rc > 0) {
				curr_buf->commit_write(rc);
			}
			#ifdef DEBUG_VERBOSE
			debug("ExtProcesses: read() %d from %d", rc, (int)pollfd_idx);
			#endif
		} else
		if (m_poll_fds[pollfd_idx].revents & POLLHUP) {
			std::shared_ptr<ExtProcess>& curr_ctx = m_processes.at(m_fdbuffers.at(pollfd_idx - 1).first);
			// a signal could have already set this FD to -1, don't try
			// and close it again
			// this is still required though in the event that a child
			// closes their end of the pipe without terminating
			debug("ExtProcesses: HUP %d %d %s", curr_ctx->pid, m_poll_fds[pollfd_idx].fd, curr_ctx->state == EXTPROCESS_STATE_STOPPING_PROCESSDIED ? "DEFUNCT" : "RUNNING");
			if (curr_ctx->m_stderrbuf && curr_ctx->m_stderrbuf->m_fds[0] == m_poll_fds[pollfd_idx].fd) {
				curr_ctx->m_stderrbuf->close_read();
			}
			if (curr_ctx->m_stdoutbuf && curr_ctx->m_stdoutbuf->m_fds[0] == m_poll_fds[pollfd_idx].fd) {
				curr_ctx->m_stdoutbuf->close_read();
			}
			if (curr_ctx->m_heartbeatbuf && curr_ctx->m_heartbeatbuf->m_fds[0] == m_poll_fds[pollfd_idx].fd) {
				curr_ctx->m_heartbeatbuf->close_read();
			}
			if ((curr_ctx->m_stdoutbuf == nullptr || curr_ctx->m_stdoutbuf->m_fds[0] == -1) &&
				(curr_ctx->m_stderrbuf == nullptr || curr_ctx->m_stderrbuf->m_fds[0] == -1) &&
				(curr_ctx->m_heartbeatbuf == nullptr || curr_ctx->m_heartbeatbuf->m_fds[0] == -1)) {
				if (curr_ctx->m_state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
					curr_ctx->m_state = EXTPROCESS_STATE_FINISHED;
				} else {
					curr_ctx->m_state = EXTPROCESS_STATE_STOPPING_FDCLOSED;
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
			debug("ExtProcesses: SIGCHLD for %d", siginfo.ssi_pid);
			size_t processes_len = m_processes.size();
			for (size_t i = 0; i < processes_len; ++ i) {
				ExtProcess * curr_ctx = m_processes.at(i).get();
				if (static_cast<pid_t>(siginfo.ssi_pid) == curr_ctx->m_pid) {
					int pstatus = 0;
					pid_t chldpid = waitpid(curr_ctx->m_pid, &pstatus, WNOHANG | WUNTRACED | WCONTINUED);
					if (chldpid < 0) {
						debug("ExtProcesses: WAITPID %s", strerror(errno));
					}
					if (chldpid > 0) {
						if (WIFSIGNALED(pstatus) || WIFEXITED(pstatus)) {
							if (curr_ctx->m_state == EXTPROCESS_STATE_STOPPING_FDCLOSED) {
								curr_ctx->m_state = EXTPROCESS_STATE_FINISHED;
								running_process_count --;
								m_dirty = 1;
							} else {
								curr_ctx->m_state = EXTPROCESS_STATE_STOPPING_PROCESSDIED;
							}
						}
						if (WIFSTOPPED(pstatus)) {
							debug("ExtProcesses: STOPPED");
						}
						if (WIFCONTINUED(pstatus)) {
							debug("ExtProcesses: CONTINUED");
						}
						curr_ctx->m_exitstatus = pstatus;
						if (running_process_count == 0) {
							res = 1;
						}
					}
				}
			}
		} else if (siginfo.ssi_signo == SIGINT) {
			debug("ExtProcesses: SIGINT");
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
		if (proc->m_state == EXTPROCESS_STATE_RUNNING || proc->m_state == EXTPROCESS_STATE_STOPPING_FDCLOSED || proc->m_state == EXTPROCESS_STATE_STOPPING_PROCESSDIED) {
			count ++;
		}
	}
	return count;
}

void ExtProcesses::clear() {
	m_processes.clear();
}

