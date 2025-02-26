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

#ifdef __cplusplus
extern "C" {
#endif

using ExtProcessBuffer = CircularBuffer<EXTPROCESS_BUFFER_INIT_SIZE>;

typedef struct extprocess_context {
	pid_t pid;
	int state;
	int exitstatus;
	int redirectfd;
	int stdoutfds[2];
	int stderrfds[2];
	std::string cmd;
	std::vector<std::string> argv;
	ExtProcessBuffer stdoutbuf;
	ExtProcessBuffer stderrbuf;
} extprocess_context;

int extprocess_init(extprocess_context * ctx, uint32_t flags);
int extprocess_spawn(extprocess_context * ctx, const char * cmd, char * argv[]);
int extprocess_setupsignalhandler();
int extprocess_releasesignalhandler(int sfd);

#ifdef __cplusplus
}

#include <string>
#include <vector>

class ExtProcesses {
public:
	ExtProcesses(int sfd);
	~ExtProcesses();
	ExtProcesses(const ExtProcesses& other) = delete;
	ExtProcesses& operator=(const ExtProcesses& other) = delete;
	ExtProcesses(ExtProcesses&& other) noexcept;
	ExtProcesses& operator=(ExtProcesses&& other);
	extprocess_context * create(uint8_t flags);
	int spawn(extprocess_context * proc, std::string cmd, std::vector<std::string> argv);
	template<typename... ArgV>
	int spawn(extprocess_context * proc, std::string cmd, ArgV... args) {
		std::vector<std::string> argv;
		//argv.push_back(cmd);
		(argv.push_back(args), ...);
		return spawn(proc, cmd, argv);
	}
	int maintain();
	int cleanup();
	const int runningcount() const;

	std::vector<extprocess_context> processes_;
	std::vector<struct pollfd> process_fds_;
	std::vector<size_t> processpollfd_idxs_;
	std::vector<std::pair<size_t, ExtProcessBuffer &>> fdbuffers_;
	int sfd_;
	int timeout_;
};
#endif

#endif // EXTPROCESS_H

