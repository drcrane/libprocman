#ifndef EXTPROCESS_H
#define EXTPROCESS_H

#define _POSIX_C_SOURCE 200809L
#include "circularbuffer.hpp"
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <poll.h>

#define EXTPROCESS_STATE_INIT 1
#define EXTPROCESS_STATE_RUNNING 2
#define EXTPROCESS_STATE_STOPPING_FDCLOSED 3
#define EXTPROCESS_STATE_STOPPING_PROCESSDIED 4
#define EXTPROCESS_STATE_FINISHED 5

#define EXTPROCESS_BUFFER_INIT_SIZE 4096
#define EXTPROCESS_BUFFER_CHUNK_SIZE 512
#define EXTPROCESS_BUFFER_MAX_SIZE 4096 * 8

#define EXTPROCESS_SPAWN_ERROR_SETPGID 101
#define EXTPROCESS_SPAWN_ERROR_PRCTL 102
#define EXTPROCESS_SPAWN_ERROR_PARENT_DEAD 103

#define EXTPROCESS_INIT_FLAG_CAPTURESTDOUT 1
#define EXTPROCESS_INIT_FLAG_CAPTURESTDERR 2
#define EXTPROCESS_INIT_FLAG_SUPPLYSTDIN 4
#define EXTPROCESS_INIT_FLAG_CREATEHEARTBEAT 8

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}

#include <string>
#include <vector>
#include <memory>

class ExtProcessBuffer : public CircularBuffer<EXTPROCESS_BUFFER_INIT_SIZE> {
public:
	ExtProcessBuffer();
	~ExtProcessBuffer();
	void close_read();
	int get_read_fd() { return m_fds[0]; }
	int get_write_fd() { return m_fds[1]; }
	std::string drain_to_string();
private:
	friend class ExtProcess;
	friend class ExtProcesses;
	int m_fds[2];
};

class ExtProcess {
public:
	ExtProcess(uint32_t flags);
	~ExtProcess();
	ExtProcess(const ExtProcess& other) = delete;
	ExtProcess& operator=(const ExtProcess& other) = delete;
	ExtProcess(ExtProcess&& other) noexcept;
	ExtProcess& operator=(ExtProcess& other);
	void spawn(std::string cmd, std::vector<std::string> argv);
	template<typename... ArgV>
	void spawn(std::string cmd, ArgV... args) {
		std::vector<std::string> argv;
		(argv.push_back(args), ...);
		return spawn(cmd, argv);
	}
	pid_t m_pid;
//private:
	friend class ExtProcesses;
	int m_state;
	int m_exitstatus;
	std::string m_cmd;
	std::vector<std::string> m_argv;
	std::unique_ptr<ExtProcessBuffer> m_stdoutbuf;
	std::unique_ptr<ExtProcessBuffer> m_stderrbuf;
	std::unique_ptr<ExtProcessBuffer> m_heartbeatbuf;
};

class ExtProcesses {
public:
	ExtProcesses(int sfd);
	~ExtProcesses();
	ExtProcesses(const ExtProcesses& other) = delete;
	ExtProcesses& operator=(const ExtProcesses& other) = delete;
	ExtProcesses(ExtProcesses&& other) noexcept;
	ExtProcesses& operator=(ExtProcesses&& other);
	std::weak_ptr<ExtProcess> create(uint8_t flags);
	int maintain();
	void clear();
	const int runningcount() const;

	static void add_fd(std::vector<std::pair<size_t, ExtProcessBuffer *>>& bufs, std::vector<struct pollfd>& pollfds, size_t process_idx, int fd, ExtProcessBuffer * buf);
	std::vector<std::shared_ptr<ExtProcess>> m_processes;
	std::vector<struct pollfd> m_poll_fds;
	std::vector<std::pair<size_t, ExtProcessBuffer *>> m_fdbuffers;
	int m_sfd;
	int m_timeout;
	int m_dirty;
	size_t m_running_process_count;
};
#endif

#endif // EXTPROCESS_H

