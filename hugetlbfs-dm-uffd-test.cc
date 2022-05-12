// vim: set ft=cpp noet sw=8 ts=8
/* g++ -static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive \
 *   hugetlbfs-dm-uffd-test.cc -o hugetlb-dm-test -Wall -Wextra \
 *  -Wno-unused-parameter -g
 */

/*
 * Before running this test, create a hugetlbfs mount called hugetlbfs-mount
 * in the directory you're running this in.
 */

#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/poll.h>

#include <linux/userfaultfd.h>
#include <sys/mman.h>

#include <thread>
#include <functional>
#include <iostream>
#include <cstring>
#include <vector>

#ifndef UFFD_FEATURE_MINOR_HUGETLBFS
#define UFFD_FEATURE_MINOR_HUGETLBFS (1 << 9)
#endif

#ifndef UFFDIO_REGISTER_MODE_MINOR
#define UFFDIO_REGISTER_MODE_MINOR ((__u64)1 << 2)
#endif

#ifndef UFFD_PAGEFAULT_FLAG_MINOR
#define UFFD_PAGEFAULT_FLAG_MINOR (1 << 2)
#endif

// #define MAP_HUGETLB_DOUBLE_MAP	0x200000

#define MADV_COLLAPSE	24

#define BUG(msg) do { puts("BUG: " msg); std::abort(); } while(0)

int userfaultfd(int flags) {
	return syscall(__NR_userfaultfd, flags);
}

static std::vector<char> fake_data(4096);

void fix_fault_with_continue(int uffd, char *addr, char *dest_addr) {
	printf("copying %c into %p\n", fake_data[0], dest_addr);
	memcpy(dest_addr, fake_data.data(), 4096);
	struct uffdio_continue cont {
		.range = (struct uffdio_range) {
			.start = reinterpret_cast<uint64_t>(addr),
			.len = 4096
		},
		.mode = 0,
		.mapped = 0,
	};
	if (ioctl(uffd, UFFDIO_CONTINUE, &cont) < 0) {
		perror("UFFDIO_CONTINUE failed");
		BUG("UFFDIO_CONTINUE failed");
	}
}

void handle_userfaults(int uffd, int pipe, char *primary_map, char *secondary_map) {
	puts("started...");
	int faults = 0;
	const int expected_faults = 2;
	while (faults++ < expected_faults) {
		struct pollfd pollfds[2] = {
			{.fd = uffd, .events = POLLIN,. revents = 0},
			{.fd = pipe, .events = POLLIN,. revents = 0}
		};
		puts("about to call poll");
		int nready = poll(pollfds, 2, -1);
		puts("finished poll");
		if (nready == -1) {
			perror("nready = -1");
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			BUG("nready is bad");
		}
		const struct pollfd *uffd_poll = &pollfds[0];
		const struct pollfd *pipe_poll = &pollfds[1];
		if (!(pipe_poll->events & POLLIN)) {
			puts("did not get POLLIN on pipe");
			break;
		}
		if (!(uffd_poll->events & POLLIN)) {
			BUG("inconsistent nready");
		}
		struct uffd_msg msg;
		int s = read(uffd, &msg, sizeof(msg));
		if (s != sizeof(msg)) {
			perror("read failed");
			BUG("read failed");
		}
		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			BUG("got non-pagefault event from userfaultfd");
		}
		printf("Got page fault at address %llx\n", msg.arg.pagefault.address);
		auto *addr = reinterpret_cast<char*>(msg.arg.pagefault.address);
		fix_fault_with_continue(uffd, addr, (addr - primary_map) + secondary_map);
	}
	if (faults >= expected_faults) {
		puts("handled max faults");
	}
	puts("handle_userfaults is closing");
}


int main(void) {
	int fd = open("hugetlbfs-mount", O_TMPFILE | O_RDWR | S_IRUSR | S_IWUSR);
	if (fd < 0) {
		perror("could not open hugetlbfs file");
		return -1;
	}

	constexpr size_t len_hugepage = 512 * 4096; // 2MB
	constexpr size_t len = 2 * len_hugepage;
	if (ftruncate(fd, len) < 0) {
		perror("ftruncate failed");
		return -1;
	}
	int uffd = userfaultfd(O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("uffd not created");
		return -1;
	}

	int flags = MAP_SHARED | MAP_HUGETLB; // | MAP_HUGETLB_DOUBLE_MAP;
	printf("Using flags: 0x%x\n", flags);
	auto *primary_map = static_cast<char*>(mmap(NULL, len, PROT_READ | PROT_WRITE, flags, fd, 0));
	if (primary_map == MAP_FAILED) {
		perror("mmap failed [2]");
		return -1;
	}
	auto *secondary_map = static_cast<char*>(mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
	if (secondary_map == MAP_FAILED) {
		perror("mmap failed [3]");
		return -1;
	}

	printf("Got primary mapping: %p\n", primary_map);
	printf("Got secondary mapping: %p\n", secondary_map);

	struct uffdio_api api;
	api.api = UFFD_API;
	api.features = UFFD_FEATURE_MINOR_HUGETLBFS | UFFD_FEATURE_MISSING_HUGETLBFS;
	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		perror("UFFDIO_API failed");
		return -1;
	}

	struct uffdio_register reg;
	reg.range.start = (unsigned long)primary_map;
	reg.range.len = len;
	reg.mode = UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_MISSING;
	reg.ioctls = 0;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		perror("register failed");
		return -1;
	}

	int pipefds[2];
	if (pipe2(pipefds, O_NONBLOCK) < 0) {
		perror("pipe failed");
		return -1;
	}

	std::thread thd([uffd, pipefd=pipefds[0], primary_map, secondary_map] {
		handle_userfaults(uffd, pipefd, primary_map, secondary_map);
	});

	memset(fake_data.data(), 'a', fake_data.size());

	// Trigger page fault
	puts("triggering page fault [1]");
	if (*primary_map != 'a') {
		BUG("memory was not populated correctly");
	}

	memset(fake_data.data(), 'b', fake_data.size());

	if (*primary_map != 'a') {
		BUG("got second fault somehow");
	}

	puts("first page populated successfully!");

	// Trigger page fault
	if (*(primary_map + 4096) != 'b') {
		printf("+4096 got byte: %x\n", *(primary_map+4096));
		BUG("+4096 was not populated correctly");
	}

	memset(fake_data.data(), 'c', fake_data.size());

	if (*(primary_map + 4096) != 'b') {
		BUG("+4096 got second fault somehow");
	}

	puts("second page populated successfully!");

	// Collapse is still buggy.
	// puts("about to collapse");
	// if (madvise(primary_map, len, MADV_COLLAPSE) < 0) {
	// 	perror("collapse failed");
	// 	BUG("collapse failed");
	// }
	// puts("collapse done");

	// if (*primary_map != 'a') {
	// 	BUG("got invalid value after collapse");
	// }

	// if (*(primary_map + 4096 * 2) != '\0') {
	// 	BUG("did not get zero bytes");
	// }

	write(pipefds[1], "", 1);

	puts("waiting to join...");

	thd.join();

	close(pipefds[1]);
	close(pipefds[0]);
	close(uffd);
	close(fd);

	puts("attempting mprotect...");
	int err = mprotect(primary_map, len, PROT_READ);
	if (err < 0)
		perror("mprotect on primary map failed");
	err = mprotect(secondary_map, len, PROT_READ);
	if (err < 0)
		perror("mprotect on secondary map failed");

	if (*primary_map != 'a') {
		BUG("got invalid value after mprotect");
	}

	munmap(secondary_map, len);
	munmap(primary_map, len);

	return 0;
}
