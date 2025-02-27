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
#define EXTPROCESS_STATE_SPAWNED 2
#define EXTPROCESS_STATE_RUNNING 3
#define EXTPROCESS_STATE_STOPPING_FDCLOSED 4
#define EXTPROCESS_STATE_STOPPING_PROCESSDIED 5
#define EXTPROCESS_STATE_STOPPED 6
#define EXTPROCESS_STATE_FINISHED 7

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

//using ExtProcessBuffer = CircularBuffer<EXTPROCESS_BUFFER_INIT_SIZE>;

class ExtProcessBuffer : public CircularBuffer<EXTPROCESS_BUFFER_INIT_SIZE> {
public:
	ExtProcessBuffer();
	~ExtProcessBuffer();
	void close_read();
private:
	friend class ExtProcess;
	friend class ExtProcesses;
	int m_fds[2];
};

int extprocess_setupsignalhandler();
int extprocess_releasesignalhandler(int sfd);

#ifdef __cplusplus
}

#include <string>
#include <vector>
#include <memory>

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
	pid_t pid;
private:
	friend class ExtProcesses;
	int state;
	int exitstatus;
	std::string cmd;
	std::vector<std::string> argv;
	std::unique_ptr<ExtProcessBuffer> stdoutbuf;
	std::unique_ptr<ExtProcessBuffer> stderrbuf;
	std::unique_ptr<ExtProcessBuffer> heartbeatbuf;
};

class ExtProcesses {
public:
	ExtProcesses(int sfd);
	~ExtProcesses();
	ExtProcesses(const ExtProcesses& other) = delete;
	ExtProcesses& operator=(const ExtProcesses& other) = delete;
	ExtProcesses(ExtProcesses&& other) noexcept;
	ExtProcesses& operator=(ExtProcesses&& other);
	std::weak_ptr<ExtProcess> create_ex(uint8_t flags);
	int maintain();
	int cleanup();
	const int runningcount() const;

	static void add_fd(std::vector<std::pair<size_t, ExtProcessBuffer *>>& bufs, std::vector<struct pollfd>& pollfds, size_t process_idx, int fd, ExtProcessBuffer * buf);
	std::vector<std::shared_ptr<ExtProcess>> m_processes;
	std::vector<struct pollfd> poll_fds_;
	std::vector<std::pair<size_t, ExtProcessBuffer *>> fdbuffers_;
	int sfd_;
	int timeout_;
};
#endif

#endif // EXTPROCESS_H

