#include <vector>
#include <utility>
#include <algorithm>
#include <stdexcept>

#define CIRCULARBUFFER_MIN_SIZE 64
#define CIRCULARBUFFER_CHUNK_SIZE 8

template <size_t CircularBufferCapacity>
class CircularBuffer {
	/*
	static_assert(CircularBufferCapacity >= CIRCULARBUFFER_MIN_SIZE &&
			(CircularBufferCapacity & (CircularBufferCapacity - 1)) == 0,
			"CircularBufferCapacity must be a power of two and at least 1024");
	*/
	static_assert((CircularBufferCapacity & (CircularBufferCapacity - 1)) == 0, "CircularBufferCapacity must be a power of 2");

	public:
	CircularBuffer() : buffer_(CircularBufferCapacity), head_(0), tail_(0) {}

	std::pair<char *, size_t> prepare_read() {
		size_t size = this->size();
		if (size == 0) return {nullptr, 0};

		const size_t contiguous = std::min(size, CircularBufferCapacity - head_);
		return {buffer_.data() + head_, contiguous};
	}

	void commit_read(size_t bytes) {
		size_t size = this->size();
		if (bytes > size) throw std::runtime_error("Overread size: " + std::to_string(size));
		head_ = (head_ + bytes) & (CircularBufferCapacity - 1);
	}

	std::pair<char *, size_t> prepare_write() {
		size_t size = this->size();
		if (size == CircularBufferCapacity) {
			head_ = (head_ + CIRCULARBUFFER_CHUNK_SIZE) & (CircularBufferCapacity - 1);
			full_ = 0;
			//if (head_ > CircularBufferCapacity - CIRCULARBUFFER_CHUNK_SIZE) {
			//	head_ = 0;
			//}
			size = this->size();
		}

		const size_t available = CircularBufferCapacity - size;
		size_t contiguous = std::min(available, CircularBufferCapacity - tail_);
		if (contiguous == CircularBufferCapacity) {
			contiguous = contiguous / 2;
		}
		return {buffer_.data() + tail_, contiguous};
	}

	std::pair<char *, size_t> prepare_write(size_t reserve) {
		size_t size = this->size();
		if (size == CircularBufferCapacity) {
			head_ = (head_ + CIRCULARBUFFER_CHUNK_SIZE) & (CircularBufferCapacity - 1);
			full_ = 0;
			//if (head_ > CircularBufferCapacity - CIRCULARBUFFER_CHUNK_SIZE) {
			//	head_ = 0;
			//}
			size = this->size();
		}

		const size_t available = CircularBufferCapacity - size;
		if (reserve > available) {
			throw std::runtime_error("reserve " + std::to_string(reserve) + " when " + std::to_string(available));
		}
		size_t contiguous = std::min(available, CircularBufferCapacity - tail_);
		if (contiguous == CircularBufferCapacity) {
			contiguous = contiguous / 2;
		}
		return {buffer_.data() + tail_, contiguous};
	}

	void commit_write(size_t bytes) {
		size_t available_space = CircularBufferCapacity - size();
		if (bytes > available_space) throw std::runtime_error("Overwrite available_space: " + std::to_string(available_space));
		tail_ = (tail_ + bytes) & (CircularBufferCapacity - 1);
		if (size() == 0 && bytes) { full_ = 1; } else { full_ = 0; }
	}

	size_t size() const {
		//size_t size = (tail_ >= head_) ? (tail_ - head_) : (CircularBufferCapacity - head_ + tail_);
		size_t size = ((tail_ - head_ + CircularBufferCapacity) & (CircularBufferCapacity - 1)) + (full_ * CircularBufferCapacity);
		return size;
	}
	constexpr size_t capacity() const { return CircularBufferCapacity; }
	void dump() {
		fprintf(stderr, "head_ %d tail_ %d full_ %d size() %d\n", (int)head_, (int)tail_, (int)full_, (int)size());
	}

private:
	std::vector<char> buffer_;
	size_t head_;
	size_t tail_;
	size_t full_;
};

