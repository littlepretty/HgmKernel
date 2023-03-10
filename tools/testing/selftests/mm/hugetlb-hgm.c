// SPDX-License-Identifier: GPL-2.0
/*
 * Test uncommon cases in HugeTLB high-granularity mapping:
 *  1. Test all supported high-granularity page sizes (with MADV_COLLAPSE).
 *  2. Test MADV_HWPOISON behavior.
 *  3. Test interaction with UFFDIO_WRITEPROTECT.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/poll.h>
#include <stdint.h>
#include <string.h>

#include <linux/userfaultfd.h>
#include <linux/magic.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAGE_SIZE 4096
#define PAGE_MASK ~(PAGE_SIZE - 1)

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

#ifndef MADV_SPLIT
#define MADV_SPLIT 26
#endif

#ifndef NUM_HWPOISON_PAGES
#define NUM_HWPOISON_PAGES 3UL
#endif

#define PREFIX " ... "
#define ERROR_PREFIX " !!! "

static void *sigbus_addr;
bool was_mceerr;
bool got_sigbus;
bool expecting_sigbus;

enum test_status {
	TEST_PASSED = 0,
	TEST_FAILED = 1,
	TEST_SKIPPED = 2,
};

static char *status_to_str(enum test_status status)
{
	switch (status) {
	case TEST_PASSED:
		return "TEST_PASSED";
	case TEST_FAILED:
		return "TEST_FAILED";
	case TEST_SKIPPED:
		return "TEST_SKIPPED";
	default:
		return "TEST_???";
	}
}

static int userfaultfd(int flags)
{
	return syscall(__NR_userfaultfd, flags);
}

static int map_range(int uffd, char *addr, uint64_t length)
{
	struct uffdio_continue cont = {
		.range = (struct uffdio_range) {
			.start = (uint64_t)addr,
			.len = length,
		},
		.mode = 0,
		.mapped = 0,
	};

	if (ioctl(uffd, UFFDIO_CONTINUE, &cont) < 0) {
		perror(ERROR_PREFIX "UFFDIO_CONTINUE failed");
		return -1;
	}
	return 0;
}

static int userfaultfd_writeprotect(int uffd, char *addr, uint64_t length,
				    bool protect)
{
	struct uffdio_writeprotect wp = {
		.range = (struct uffdio_range) {
			.start = (uint64_t)addr,
			.len = length,
		},
		.mode = UFFDIO_WRITEPROTECT_MODE_DONTWAKE,
	};

	if (protect)
		wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

	printf(PREFIX "UFFDIO_WRITEPROTECT: %p -> %p (%sprotected)\n", addr,
			addr + length, protect ? "" : "un");

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) < 0) {
		perror(ERROR_PREFIX "UFFDIO_WRITEPROTECT failed");
		return -1;
	}
	return 0;
}

static int check_equal(char *mapping, size_t length, char value)
{
	size_t i;

	for (i = 0; i < length; ++i)
		if (mapping[i] != value) {
			printf(ERROR_PREFIX "mismatch at %p (%d != %d)\n",
					&mapping[i], mapping[i], value);
			return -1;
		}

	return 0;
}

static int test_continues(int uffd, char *primary_map, char *secondary_map,
			  size_t len, bool verify)
{
	size_t offset = 0;
	unsigned char iter = 0;
	unsigned long pagesize = getpagesize();
	uint64_t size;

	for (size = len/2; size >= pagesize;
			offset += size, size /= 2) {
		iter++;
		memset(secondary_map + offset, iter, size);
		printf(PREFIX "UFFDIO_CONTINUE: %p -> %p = %d%s\n",
				primary_map + offset,
				primary_map + offset + size,
				iter,
				verify ? " (and verify)" : "");
		if (map_range(uffd, primary_map + offset, size))
			return -1;
		if (verify && check_equal(primary_map + offset, size, iter))
			return -1;
	}
	return 0;
}

static int verify_contents(char *map, size_t len, bool last_page_zero)
{
	size_t offset = 0;
	int i = 0;
	uint64_t size;

	for (size = len/2; size > PAGE_SIZE; offset += size, size /= 2)
		if (check_equal(map + offset, size, ++i))
			return -1;

	if (last_page_zero)
		if (check_equal(map + len - PAGE_SIZE, PAGE_SIZE, 0))
			return -1;

	return 0;
}

static int test_collapse(char *primary_map, size_t len, bool verify)
{
	int ret = 0;

	printf(PREFIX "collapsing %p -> %p\n", primary_map, primary_map + len);
	if (madvise(primary_map, len, MADV_COLLAPSE) < 0) {
		perror(ERROR_PREFIX "collapse failed");
		return -1;
	}

	if (verify) {
		printf(PREFIX "verifying %p -> %p\n", primary_map,
				primary_map + len);
		ret = verify_contents(primary_map, len, true);
	}
	return ret;
}

static void sigbus_handler(int signo, siginfo_t *info, void *context)
{
	if (!expecting_sigbus)
		printf(ERROR_PREFIX "unexpected sigbus: %p\n", info->si_addr);

	got_sigbus = true;
	was_mceerr = info->si_code == BUS_MCEERR_AR;
	sigbus_addr = info->si_addr;

	pthread_exit(NULL);
}

static void *access_mem(void *addr)
{
	volatile char *ptr = addr;

	/*
	 * Do a write without changing memory contents, as other routines will
	 * need to verify that mapping contents haven't changed.
	 *
	 * We do a write so that we trigger uffd-wp SIGBUSes. To test that we
	 * get HWPOISON SIGBUSes, we would only need to read.
	 */
	*ptr = *ptr;
	return NULL;
}

static int test_sigbus(char *addr, bool poison)
{
	int ret;
	pthread_t pthread;

	sigbus_addr = (void *)0xBADBADBAD;
	was_mceerr = false;
	got_sigbus = false;
	expecting_sigbus = true;
	ret = pthread_create(&pthread, NULL, &access_mem, addr);
	if (ret) {
		printf(ERROR_PREFIX "failed to create thread: %s\n",
				strerror(ret));
		goto out;
	}

	pthread_join(pthread, NULL);

	ret = -1;
	if (!got_sigbus)
		printf(ERROR_PREFIX "didn't get a SIGBUS: %p\n", addr);
	else if (sigbus_addr != addr)
		printf(ERROR_PREFIX "got incorrect sigbus address: %p vs %p\n",
				sigbus_addr, addr);
	else if (poison && !was_mceerr)
		printf(ERROR_PREFIX "didn't get an MCEERR?\n");
	else if (!poison && was_mceerr)
		printf(ERROR_PREFIX "got BUS_MCEERR_AR sigbus on expected healthy address: %p\n",
		       sigbus_addr);
	else
		ret = 0;
out:
	expecting_sigbus = false;
	return ret;
}

static void *read_from_uffd_thd(void *arg)
{
	int uffd = *(int *)arg;
	struct uffd_msg msg;
	/* opened without O_NONBLOCK */
	if (read(uffd, &msg, sizeof(msg)) != sizeof(msg))
		printf(ERROR_PREFIX "reading uffd failed\n");

	return NULL;
}

static int read_event_from_uffd(int *uffd, pthread_t *pthread)
{
	int ret = 0;

	ret = pthread_create(pthread, NULL, &read_from_uffd_thd, (void *)uffd);
	if (ret) {
		printf(ERROR_PREFIX "failed to create thread: %s\n",
				strerror(ret));
		return ret;
	}
	return 0;
}

struct range_exclude_pages {
	/* Starting address of the buffer. */
	char *mapping;
	/* Length of the buffer in bytes. */
	size_t length;
	/* The value that each byte in buffer should equal to. */
	char value;
	/*
	 * PAGESIZE aligned addresses excluded from the checking,
	 * e.g. if PAGE_SIZE=4k, for each addr in excludes,
	 * skips checking on [addr, addr + 4096).
	 */
	unsigned long excluded[NUM_HWPOISON_PAGES];
};

static int check_range_exclude_pages(struct range_exclude_pages *range)
{
	const unsigned long pagesize = getpagesize();
	unsigned long excluded_index;
	unsigned long page_index;
	bool should_skip;
	size_t i = 0;
	size_t j = 0;

	while (i < range->length) {
		page_index = ((unsigned long)(range->mapping + i)) / pagesize;
		should_skip = false;
		for (j = 0; j < NUM_HWPOISON_PAGES; ++j) {
			excluded_index = range->excluded[j] / pagesize;
			if (page_index == excluded_index) {
				should_skip = true;
				break;
			}
		}
		if (should_skip) {
			printf(PREFIX "skip excluded addr range [%#lx, %#lx)\n",
				(unsigned long)(range->mapping + i),
				(unsigned long)(range->mapping + i + pagesize));
			i += pagesize;
			continue;
		}
		if (range->mapping[i] != range->value) {
			printf(ERROR_PREFIX "mismatch at %p (%d != %d)\n",
			       &range->mapping[i], range->mapping[i], range->value);
			return -1;
		}
		++i;
	}

	return 0;
}

enum test_status verify_raw_pages(char *map, size_t len,
				  unsigned long excluded[NUM_HWPOISON_PAGES])
{
	const unsigned long pagesize = getpagesize();
	unsigned long size, offset, value;
	size_t j = 0;

	for (size = len / 2, offset = 0, value = 1; size > pagesize;
	     offset += size, size /= 2, ++value) {
		struct range_exclude_pages range = {
			.mapping = map + offset,
			.length = size,
			.value = value,
		};
		for (j = 0; j < NUM_HWPOISON_PAGES; ++j)
			range.excluded[j] = excluded[j];

		printf(PREFIX "checking non-poisoned range [%p, %p) "
			"(len=%#lx) per-byte value=%lu\n",
			range.mapping, range.mapping + range.length,
			range.length, value);
		if (check_range_exclude_pages(&range))
			return TEST_FAILED;

		printf(PREFIX PREFIX "good\n");
	}

	return TEST_PASSED;
}

static int read_hwpoison_pages(unsigned long *nr_hwp_pages)
{
	const unsigned long pagesize = getpagesize();
	char buffer[256] = {0};
	char *cmd = "cat /proc/meminfo | grep -i HardwareCorrupted | grep -o '[0-9]*'";
	FILE *cmdfile = popen(cmd, "r");

	if (!(fgets(buffer, sizeof(buffer), cmdfile))) {
		perror("failed to read HardwareCorrupted from /proc/meminfo\n");
		return -1;
	}
	pclose(cmdfile);
	*nr_hwp_pages = atoll(buffer) * 1024 / pagesize;

	return 0;
}

static enum test_status test_hwpoison_one_raw_page(char *hwpoison_addr)
{
	const unsigned long pagesize = getpagesize();

	printf(PREFIX "poisoning [%p, %p) (len=%#lx)\n",
	       hwpoison_addr, hwpoison_addr + pagesize, pagesize);
	if (madvise(hwpoison_addr, pagesize, MADV_HWPOISON) < 0) {
		perror(ERROR_PREFIX "MADV_HWPOISON failed");
		return TEST_SKIPPED;
	}

	printf(PREFIX "checking poisoned range [%p, %p) (len=%#lx)\n",
	       hwpoison_addr, hwpoison_addr + pagesize, pagesize);
	if (test_sigbus(hwpoison_addr, true) < 0)
		return TEST_FAILED;

	return TEST_PASSED;
}

static enum test_status test_hwpoison_present(char *map, size_t len,
					      bool already_injected)
{
	const unsigned long pagesize = getpagesize();
	const unsigned long hwpoison_next = 128;
	unsigned long nr_hwpoison_pages_before, nr_hwpoison_pages_after;
	enum test_status ret;
	size_t i;
	char *hwpoison_addr = map;
	unsigned long hwpoison_addrs[NUM_HWPOISON_PAGES];

	if (hwpoison_next * (NUM_HWPOISON_PAGES - 1) >= (len / pagesize)) {
		printf(ERROR_PREFIX "max hwpoison_addr out of range");
		return TEST_SKIPPED;
	}

	for (i = 0; i < NUM_HWPOISON_PAGES; ++i) {
		hwpoison_addrs[i] = (unsigned long)hwpoison_addr;
		hwpoison_addr += hwpoison_next * pagesize;
	}

	if (already_injected)
		return verify_raw_pages(map, len, hwpoison_addrs);

	if (read_hwpoison_pages(&nr_hwpoison_pages_before)) {
		printf(ERROR_PREFIX "check #HWPOISON pages\n");
		return TEST_SKIPPED;
	}
	printf(PREFIX "Before injections, #HWPOISON pages = %ld\n", nr_hwpoison_pages_before);

	for (i = 0; i < NUM_HWPOISON_PAGES; ++i) {
		ret = test_hwpoison_one_raw_page((char *)hwpoison_addrs[i]);
		if (ret != TEST_PASSED)
			return ret;
	}

	if (read_hwpoison_pages(&nr_hwpoison_pages_after)) {
		printf(ERROR_PREFIX "check #HWPOISON pages\n");
		return TEST_SKIPPED;
	}
	printf(PREFIX "After injections, #HWPOISON pages = %ld\n", nr_hwpoison_pages_after);

	if (nr_hwpoison_pages_after - nr_hwpoison_pages_before != NUM_HWPOISON_PAGES) {
		printf(ERROR_PREFIX "delta #HWPOISON pages != %ld",
			NUM_HWPOISON_PAGES);
		return TEST_FAILED;
	}

	return verify_raw_pages(map, len, hwpoison_addrs);
}

int test_fork(int uffd, char *primary_map, size_t len)
{
	int status;
	int ret = 0;
	pid_t pid;
	pthread_t uffd_thd;

	/*
	 * UFFD_FEATURE_EVENT_FORK will put fork event on the userfaultfd,
	 * which we must read, otherwise we block fork(). Setup a thread to
	 * read that event now.
	 *
	 * Page fault events should result in a SIGBUS, so we expect only a
	 * single event from the uffd (the fork event).
	 */
	if (read_event_from_uffd(&uffd, &uffd_thd))
		return -1;

	pid = fork();

	if (!pid) {
		/*
		 * Because we have UFFDIO_REGISTER_MODE_WP and
		 * UFFD_FEATURE_EVENT_FORK, the page tables should be copied
		 * exactly.
		 *
		 * Check that everything except that last 4K has correct
		 * contents, and then check that the last 4K gets a SIGBUS.
		 */
		printf(PREFIX "child validating...\n");
		ret = verify_contents(primary_map, len, false) ||
			test_sigbus(primary_map + len - 1, false);
		ret = 0;
		exit(ret ? 1 : 0);
	} else if (pid > 0) {
		/* wait for the child to finish. */
		waitpid(pid, &status, 0);
		ret = WEXITSTATUS(status);
		if (!ret) {
			printf(PREFIX "parent validating...\n");
			/* Same check as the child. */
			ret = verify_contents(primary_map, len, false) ||
				test_sigbus(primary_map + len - 1, false);
			ret = 0;
		}
	} else {
		perror(ERROR_PREFIX "fork failed");
		return -1;
	}

	pthread_join(uffd_thd, NULL);
	return ret;
}

static int uffd_register(int uffd, char *primary_map, unsigned long len,
			 int mode)
{
	struct uffdio_register reg;

	reg.range.start = (unsigned long)primary_map;
	reg.range.len = len;
	reg.mode = mode;

	reg.ioctls = 0;
	return ioctl(uffd, UFFDIO_REGISTER, &reg);
}

static int setup_present_map(char *present_map, size_t len)
{
	size_t offset = 0;
	unsigned char iter = 0;
	unsigned long pagesize = getpagesize();
	uint64_t size;

	for (size = len/2; size >= pagesize;
			offset += size, size /= 2) {
		iter++;
		memset(present_map + offset, iter, size);
	}
	return 0;
}

static enum test_status test_hwpoison_absent_uffd_wp(int fd, size_t hugepagesize, size_t len)
{
	int uffd;
	char *absent_map, *present_map;
	struct uffdio_api api;
	int register_args;
	struct sigaction new, old;
	enum test_status status = TEST_SKIPPED;
	const unsigned long pagesize = getpagesize();
	const unsigned long hwpoison_index = 128;
	char *hwpoison_addr;

	if (hwpoison_index >= (len / pagesize)) {
		printf(ERROR_PREFIX "hwpoison_index out of range");
		return TEST_FAILED;
	}

	if (ftruncate(fd, len) < 0) {
		perror(ERROR_PREFIX "ftruncate failed");
		return TEST_FAILED;
	}

	uffd = userfaultfd(O_CLOEXEC);
	if (uffd < 0) {
		perror(ERROR_PREFIX "uffd not created");
		return TEST_FAILED;
	}

	absent_map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (absent_map == MAP_FAILED) {
		perror(ERROR_PREFIX "mmap for ABSENT mapping failed");
		goto close_uffd;
	}
	printf(PREFIX "ABSENT mapping: %p\n", absent_map);

	api.api = UFFD_API;
	api.features = UFFD_FEATURE_SIGBUS | UFFD_FEATURE_EXACT_ADDRESS |
		UFFD_FEATURE_EVENT_FORK;
	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		perror(ERROR_PREFIX "UFFDIO_API failed");
		goto unmap_absent;
	}

	/*
	 * Register with UFFDIO_REGISTER_MODE_WP to have UFFD WP bit on
	 * the HugeTLB page table entry.
	 */
	register_args = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
	if (uffd_register(uffd, absent_map, len, register_args)) {
		perror(ERROR_PREFIX "UFFDIO_REGISTER failed");
		goto unmap_absent;
	}

	new.sa_sigaction = &sigbus_handler;
	new.sa_flags = SA_SIGINFO;
	if (sigaction(SIGBUS, &new, &old) < 0) {
		perror(ERROR_PREFIX "could not setup SIGBUS handler");
		goto unmap_absent;
	}

	/*
	 * Set WP markers to the absent huge mapping. With HGM enabled in
	 * kernel CONFIG, memory_failure will enabled HGM in kernel,
	 * so no need to enable HGM from userspace.
	 */
	if (userfaultfd_writeprotect(uffd, absent_map, len, true) < 0) {
		status = TEST_FAILED;
		goto unmap_absent;
	}

	status = TEST_PASSED;

	/*
	 * With MAP_SHARED hugetlb memory, we cna inject memory error to
	 * not-yet-faulted mapping (absent_map) by injecting memory error
	 * to a already faulted mapping (present_map).
	 */
	present_map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (present_map == MAP_FAILED) {
		perror(ERROR_PREFIX "mmap for non present mapping failed");
		goto close_uffd;
	}
	printf(PREFIX "PRESENT mapping: %p\n", present_map);
	setup_present_map(present_map, len);

	hwpoison_addr = present_map + hwpoison_index * pagesize;
	if (madvise(hwpoison_addr, pagesize, MADV_HWPOISON)) {
		perror(PREFIX "MADV_HWPOISON a page in PRESENT mapping failed");
		status = TEST_FAILED;
		goto unmap_present;
	}

	printf(PREFIX "checking poisoned range [%p, %p) (len=%#lx) in PRESENT mapping\n",
	       hwpoison_addr, hwpoison_addr + pagesize, pagesize);
	if (test_sigbus(hwpoison_addr, true) < 0) {
		status = TEST_FAILED;
		goto done;
	}
	printf(PREFIX "checking healthy pages in PRESENT mapping\n");
	unsigned long hwpoison_addrs[] = {
		(unsigned long)hwpoison_addr,
		(unsigned long)hwpoison_addr,
		(unsigned long)hwpoison_addr
	};
	status = verify_raw_pages(present_map, len, hwpoison_addrs);
	if (status != TEST_PASSED) {
		printf(ERROR_PREFIX "checking healthy pages failed\n");
		goto done;
	}

	for (int i = 0; i < len; i += pagesize) {
		if (i == hwpoison_index * pagesize) {
			printf(PREFIX "checking poisoned range [%p, %p) (len=%#lx) in ABSENT mapping\n",
				absent_map + i, absent_map + i + pagesize, pagesize);
			if (test_sigbus(absent_map + i, true) < 0) {
				status = TEST_FAILED;
				break;
			}
		} else {
			/*
			 * With UFFD_FEATURE_SIGBUS, we should get a SIGBUS for
			 * every not faulted (non present) page/byte.
			 */
			if (test_sigbus(absent_map + i, false) < 0) {
				printf(PREFIX "checking healthy range [%p, %p) (len=%#lx) in ABSENT mapping failed\n",
					absent_map + i, absent_map + i + pagesize, pagesize);
				status = TEST_FAILED;
				break;
			}
		}
	}
done:
	if (ftruncate(fd, 0) < 0) {
		perror(ERROR_PREFIX "ftruncate back to 0 failed");
		status = TEST_FAILED;
	}
unmap_present:
	printf(PREFIX "Unmap PRESENT mapping=%p\n", absent_map);
	munmap(present_map, len);
unmap_absent:
	printf(PREFIX "Unmap ABSENT mapping=%p\n", absent_map);
	munmap(absent_map, len);
close_uffd:
	printf(PREFIX "Close UFFD\n");
	close(uffd);
	return status;
}

enum test_type {
	TEST_DEFAULT,
	TEST_UFFDWP,
	TEST_HWPOISON
};

static enum test_status
test_hgm(int fd, size_t hugepagesize, size_t len, enum test_type type)
{
	int uffd;
	char *primary_map, *secondary_map;
	struct uffdio_api api;
	struct sigaction new, old;
	enum test_status status = TEST_SKIPPED;
	bool hwpoison = type == TEST_HWPOISON;
	bool uffd_wp = type == TEST_UFFDWP;
	bool verify = type == TEST_DEFAULT;
	int register_args;
	enum test_status hwp_status = TEST_SKIPPED;

	if (ftruncate(fd, len) < 0) {
		perror(ERROR_PREFIX "ftruncate failed");
		return status;
	}

	uffd = userfaultfd(O_CLOEXEC);
	if (uffd < 0) {
		perror(ERROR_PREFIX "uffd not created");
		return status;
	}

	primary_map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (primary_map == MAP_FAILED) {
		perror(ERROR_PREFIX "mmap for primary mapping failed");
		goto close_uffd;
	}
	secondary_map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (secondary_map == MAP_FAILED) {
		perror(ERROR_PREFIX "mmap for secondary mapping failed");
		goto unmap_primary;
	}

	printf(PREFIX "primary mapping: %p\n", primary_map);
	printf(PREFIX "secondary mapping: %p\n", secondary_map);

	api.api = UFFD_API;
	api.features = UFFD_FEATURE_SIGBUS | UFFD_FEATURE_EXACT_ADDRESS |
		UFFD_FEATURE_EVENT_FORK;
	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		perror(ERROR_PREFIX "UFFDIO_API failed");
		goto out;
	}

	if (madvise(primary_map, len, MADV_SPLIT)) {
		perror(ERROR_PREFIX "MADV_SPLIT failed");
		goto out;
	}

	/*
	 * Register with UFFDIO_REGISTER_MODE_WP to force fork() to copy page
	 * tables (also need UFFD_FEATURE_EVENT_FORK, which we have).
	 */
	register_args = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
	if (!uffd_wp)
		/*
		 * If we're testing UFFDIO_WRITEPROTECT, then we don't want
		 * minor faults. With minor faults enabled, we'll get SIGBUSes
		 * for any minor fault, wheresa without minot faults enabled,
		 * writes will verify that uffd-wp PTE markers were installed
		 * properly.
		 */
		register_args |= UFFDIO_REGISTER_MODE_MINOR;

	if (uffd_register(uffd, primary_map, len, register_args)) {
		perror(ERROR_PREFIX "UFFDIO_REGISTER failed");
		goto out;
	}


	new.sa_sigaction = &sigbus_handler;
	new.sa_flags = SA_SIGINFO;
	if (sigaction(SIGBUS, &new, &old) < 0) {
		perror(ERROR_PREFIX "could not setup SIGBUS handler");
		goto out;
	}

	status = TEST_FAILED;

	if (uffd_wp) {
		/*
		 * Install uffd-wp PTE markers now. They should be preserved
		 * as we split the mappings with UFFDIO_CONTINUE later.
		 */
		if (userfaultfd_writeprotect(uffd, primary_map, len, true))
			goto done;
		/* Verify that we really are write-protected. */
		if (test_sigbus(primary_map, false))
			goto done;
	}

	/*
	 * Main piece of the test: map primary_map at all the possible
	 * page sizes. Starting at the hugepage size and going down to
	 * PAGE_SIZE. This leaves the final PAGE_SIZE piece of the mapping
	 * unmapped.
	 */
	if (test_continues(uffd, primary_map, secondary_map, len, verify))
		goto done;

	/*
	 * Verify that MADV_HWPOISON is able to properly poison the entire
	 * mapping.
	 */
	if (hwpoison) {
		/* test_hwpoison can fail with TEST_SKIPPED. */
		hwp_status = test_hwpoison_present(primary_map, len, false);
		if (hwp_status != TEST_PASSED) {
			status = hwp_status;
			goto done;
		}
	}

	if (uffd_wp) {
		/*
		 * Check that the uffd-wp marker we installed initially still
		 * exists in the unmapped 4K piece at the end the mapping.
		 *
		 * test_sigbus() will do a write. When this happens:
		 *  1. The page fault handler will find the uffd-wp marker and
		 *     create a read-only PTE.
		 *  2. The memory access is retried, and the page fault handler
		 *     will find that a write was attempted in a UFFD_WP VMA
		 *     where a RO mapping exists, so SIGBUS
		 *     (we have UFFD_FEATURE_SIGBUS).
		 *
		 * We only check the final pag because UFFDIO_CONTINUE will
		 * have cleared the write-protection on all the other pieces
		 * of the mapping.
		 */
		printf(PREFIX "verifying that we can't write to final page\n");
		if (test_sigbus(primary_map + len - 1, false))
			goto done;
	}

	if (!hwpoison)
		/*
		 * test_fork() will verify memory contents. We can't do
		 * that if memory has been poisoned.
		 */
		if (test_fork(uffd, primary_map, len))
			goto done;

	/*
	 * Check that MADV_COLLAPSE functions properly. That is:
	 *  - the PAGE_SIZE hole we had is no longer unmapped.
	 *  - poisoned regions are still poisoned.
	 *
	 *  Verify the data is correct if we haven't poisoned.
	 */
	if (test_collapse(primary_map, len, !hwpoison))
		goto done;
	/*
	 * Verify that memory is still poisoned.
	 */
	if (hwpoison && test_hwpoison_present(primary_map, len, true))
		goto done;

	status = TEST_PASSED;

done:
	if (ftruncate(fd, 0) < 0) {
		perror(ERROR_PREFIX "ftruncate back to 0 failed");
		status = TEST_FAILED;
	}

out:
	munmap(secondary_map, len);
unmap_primary:
	munmap(primary_map, len);
close_uffd:
	close(uffd);
	return status;
}

int main(void)
{
	int fd;
	struct statfs file_stat;
	size_t hugepagesize;
	size_t len;
	enum test_status status;
	int ret = 0;

	fd = memfd_create("hugetlb_tmp", MFD_HUGETLB);
	if (fd < 0) {
		perror(ERROR_PREFIX "could not open hugetlbfs file");
		return -1;
	}

	memset(&file_stat, 0, sizeof(file_stat));
	if (fstatfs(fd, &file_stat)) {
		perror(ERROR_PREFIX "fstatfs failed");
		goto close;
	}
	if (file_stat.f_type != HUGETLBFS_MAGIC) {
		printf(ERROR_PREFIX "not hugetlbfs file\n");
		goto close;
	}

	hugepagesize = file_stat.f_bsize;
	len = 2 * hugepagesize;

	printf("HGM regular test...\n");
	status = test_hgm(fd, hugepagesize, len, TEST_DEFAULT);
	printf("HGM regular test:  %s\n", status_to_str(status));
	if (status == TEST_FAILED)
		ret = -1;

	printf("HGM uffd-wp test...\n");
	status = test_hgm(fd, hugepagesize, len, TEST_UFFDWP);
	printf("HGM uffd-wp test:  %s\n", status_to_str(status));
	if (status == TEST_FAILED)
		ret = -1;

	printf("HGM hwpoison test...\n");
	status = test_hgm(fd, hugepagesize, len, TEST_HWPOISON);
	printf("HGM hwpoison test: %s\n", status_to_str(status));
	if (status == TEST_FAILED)
		ret = -1;

	printf("HGM hwpoison UFFD-WP marker test...\n");
	status = test_hwpoison_absent_uffd_wp(fd, hugepagesize, len);
	printf("HGM hwpoison UFFD-WP marker test: %s\n",
		status_to_str(status));
	if (status == TEST_FAILED)
		ret = -1;
close:
	close(fd);

	return ret;
}
