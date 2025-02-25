#include "circularbuffer.hpp"
#include <utility>
#include <tuple>
#include <malloc.h>
#include <string.h>
#include <errno.h>

CircularBuffer<64> cb;

int main(int argc, char *argv[]) {
	char * buf = static_cast<char *>(malloc(128));
	auto [ptr, ptr_sz] = cb.prepare_write();
	cb.commit_write(32);
	cb.dump();
	cb.prepare_write();
	cb.commit_write(32);
	cb.dump();
	std::tie(ptr, ptr_sz) = cb.prepare_write();
	cb.dump();
	cb.commit_write(ptr_sz);
	cb.dump();
	free(buf);
	return 0;
}

