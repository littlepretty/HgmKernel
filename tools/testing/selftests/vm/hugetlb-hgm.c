// SPDX-License-Identifier: GPL-2.0
/*
 * Test uncommon cases in HugeTLB high-granularity mapping:
 *  1. Test all supported high-granularity page sizes (with MADV_COLLAPSE).
 *  2. Test MADV_HWPOISON behavior.
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

#define PAGE_MASK ~(4096 - 1)

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

#define PREFIX " ... "
#define ERROR_PREFIX " !!! "

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

int userfaultfd(int flags)
{
	return syscall(__NR_userfaultfd, flags);
}

int map_range(int uffd, char *addr, uint64_t length)
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

int check_equal(char *mapping, size_t length, char value)
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

int test_continues(int uffd, char *primary_map, char *secondary_map, size_t len,
		   bool verify)
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

int verify_contents(char *map, size_t len, bool last_4k_zero)
{
	size_t offset = 0;
	int i = 0;
	uint64_t size;

	for (size = len/2; size > 4096; offset += size, size /= 2)
		if (check_equal(map + offset, size, ++i))
			return -1;

	if (last_4k_zero)
		/* expect the last 4K to be zero. */
		if (check_equal(map + len - 4096, 4096, 0))
			return -1;

	return 0;
}

int test_collapse(char *primary_map, size_t len, bool hwpoison)
{
	printf(PREFIX "collapsing %p -> %p\n", primary_map, primary_map + len);
	if (madvise(primary_map, len, MADV_COLLAPSE) < 0) {
		if (errno == EHWPOISON && hwpoison) {
			/* this is expected for the hwpoison test. */
			printf(PREFIX "could not collapse due to poison\n");
			return 0;
		}
		perror(ERROR_PREFIX "collapse failed");
		return -1;
	}

	printf(PREFIX "verifying %p -> %p\n", primary_map, primary_map + len);
	return verify_contents(primary_map, len, true);
}

static void *sigbus_addr;
bool was_mceerr;
bool got_sigbus;

void sigbus_handler(int signo, siginfo_t *info, void *context)
{
	got_sigbus = true;
	was_mceerr = info->si_code == BUS_MCEERR_AR;
	sigbus_addr = info->si_addr;

	pthread_exit(NULL);
}

void *access_mem(void *addr)
{
	volatile char *ptr = addr;

	*ptr;
	return NULL;
}

int test_sigbus(char *addr, bool poison)
{
	int ret = 0;
	pthread_t pthread;

	sigbus_addr = (void *)0xBADBADBAD;
	was_mceerr = false;
	got_sigbus = false;
	ret = pthread_create(&pthread, NULL, &access_mem, addr);
	if (ret) {
		printf(ERROR_PREFIX "failed to create thread: %s\n",
				strerror(ret));
		return ret;
	}

	pthread_join(pthread, NULL);
	if (!got_sigbus) {
		printf(ERROR_PREFIX "didn't get a SIGBUS\n");
		return -1;
	} else if (sigbus_addr != addr) {
		printf(ERROR_PREFIX "got incorrect sigbus address: %p vs %p\n",
				sigbus_addr, addr);
		return -1;
	} else if (poison && !was_mceerr) {
		printf(ERROR_PREFIX "didn't get an MCEERR?\n");
		return -1;
	}
	return 0;
}

void *read_from_uffd_thd(void *arg)
{
	int uffd = *(int *)arg;
	struct uffd_msg msg;
	/* opened without O_NONBLOCK */
	if (read(uffd, &msg, sizeof(msg)) != sizeof(msg))
		printf(ERROR_PREFIX "reading uffd failed\n");

	return NULL;
}

int read_event_from_uffd(int *uffd, pthread_t *pthread)
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

enum test_status test_hwpoison(char *primary_map, size_t len)
{
	const unsigned long pagesize = getpagesize();
	const int num_poison_checks = 512;
	unsigned long bytes_per_check = len/num_poison_checks;
	int i;

	printf(PREFIX "poisoning %p -> %p\n", primary_map, primary_map + len);
	if (madvise(primary_map, len, MADV_HWPOISON) < 0) {
		perror(ERROR_PREFIX "MADV_HWPOISON failed");
		return TEST_SKIPPED;
	}

	printf(PREFIX "checking that it was poisoned "
	       "(%d addresses within %p -> %p)\n",
	       num_poison_checks, primary_map, primary_map + len);

	if (pagesize > bytes_per_check)
		bytes_per_check = pagesize;

	for (i = 0; i < len; i += bytes_per_check)
		if (test_sigbus(primary_map + i, true) < 0)
			return TEST_FAILED;
	/* check very last byte, because we left it unmapped */
	if (test_sigbus(primary_map + len - 1, true))
		return TEST_FAILED;

	return TEST_PASSED;
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
	} else {
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
	}

	pthread_join(uffd_thd, NULL);
	return ret;

}

enum test_status
test_hgm(int fd, size_t hugepagesize, size_t len, bool hwpoison)
{
	int uffd;
	char *primary_map, *secondary_map;
	struct uffdio_api api;
	struct uffdio_register reg;
	struct sigaction new, old;
	enum test_status status = TEST_SKIPPED;

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
	api.features = UFFD_FEATURE_MINOR_HUGETLBFS |
		UFFD_FEATURE_MISSING_HUGETLBFS |
		UFFD_FEATURE_MINOR_HUGETLBFS_HGM | UFFD_FEATURE_SIGBUS |
		UFFD_FEATURE_EXACT_ADDRESS | UFFD_FEATURE_EVENT_FORK;
	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		perror(ERROR_PREFIX "UFFDIO_API failed");
		goto out;
	}
	if (!(api.features & UFFD_FEATURE_MINOR_HUGETLBFS_HGM)) {
		puts("UFFD_FEATURE_MINOR_HUGETLBFS_HGM not present");
		goto out;
	}

	reg.range.start = (unsigned long)primary_map;
	reg.range.len = len;
	/*
	 * Register with UFFDIO_REGISTER_MODE_WP to force fork() to copy page
	 * tables (also need UFFD_FEATURE_EVENT_FORK, which we have).
	 */
	reg.mode = UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_MISSING |
		UFFDIO_REGISTER_MODE_WP;
	reg.ioctls = 0;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		perror(ERROR_PREFIX "register failed");
		goto out;
	}

	new.sa_sigaction = &sigbus_handler;
	new.sa_flags = SA_SIGINFO;
	if (sigaction(SIGBUS, &new, &old) < 0) {
		perror(ERROR_PREFIX "could not setup SIGBUS handler");
		goto out;
	}

	status = TEST_FAILED;

	if (test_continues(uffd, primary_map, secondary_map, len, !hwpoison))
		goto done;
	if (hwpoison) {
		/* test_hwpoison can fail with TEST_SKIPPED. */
		enum test_status new_status = test_hwpoison(primary_map, len);

		if (new_status != TEST_PASSED) {
			status = new_status;
			goto done;
		}
	} else if (test_fork(uffd, primary_map, len))
		goto done;
	if (test_collapse(primary_map, len, hwpoison))
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
	printf("HGM regular test:  %s\n",
			status_to_str(test_hgm(fd, hugepagesize, len, false)));
	printf("HGM hwpoison test...\n");
	printf("HGM hwpoison test: %s\n",
			status_to_str(test_hgm(fd, hugepagesize, len, true)));
close:
	close(fd);

	return 0;
}
