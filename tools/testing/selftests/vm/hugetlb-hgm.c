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

#define PAGE_MASK ~(4096 - 1)

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

#define PREFIX " ... "

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
		perror("UFFDIO_CONTINUE failed");
		return -1;
	}
	return 0;
}

int check_equal(char *mapping, size_t length, char value)
{
	size_t i;

	for (i = 0; i < length; ++i)
		if (mapping[i] != value) {
			printf("mismatch at %p (%d != %d)\n", &mapping[i],
					mapping[i], value);
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

int test_collapse(char *primary_map, size_t len, bool hwpoison)
{
	size_t offset;
	int i;
	uint64_t size;

	printf(PREFIX "collapsing %p -> %p\n", primary_map, primary_map + len);
	if (madvise(primary_map, len, MADV_COLLAPSE) < 0) {
		if (errno == EHWPOISON && hwpoison) {
			/* this is expected for the hwpoison test. */
			printf(PREFIX "could not collapse due to poison\n");
			return 0;
		}
		perror("collapse failed");
		return -1;
	}

	printf(PREFIX "verifying %p -> %p\n", primary_map, primary_map + len);

	offset = 0;
	i = 0;
	for (size = len/2; size > 4096; offset += size, size /= 2) {
		if (check_equal(primary_map + offset, size, ++i))
			return -1;
	}
	/* expect the last 4K to be zero. */
	if (check_equal(primary_map + len - 4096, 4096, 0))
		return -1;

	return 0;
}

static void *poisoned_addr;

void sigbus_handler(int signo, siginfo_t *info, void *context)
{
	if (info->si_code != BUS_MCEERR_AR)
		goto kill;
	poisoned_addr = info->si_addr;
kill:
	pthread_exit(NULL);
}

void *access_mem(void *addr)
{
	volatile char *ptr = addr;

	*ptr;
	return NULL;
}

int test_poison_sigbus(char *addr)
{
	int ret = 0;
	pthread_t pthread;

	poisoned_addr = (void *)0xBADBADBAD;
	ret = pthread_create(&pthread, NULL, &access_mem, addr);
	if (pthread_create(&pthread, NULL, &access_mem, addr)) {
		printf("failed to create thread: %s\n", strerror(ret));
		return ret;
	}

	pthread_join(pthread, NULL);
	if (poisoned_addr != addr) {
		printf("got incorrect poisoned address: %p vs %p\n",
				poisoned_addr, addr);
		return -1;
	}
	return 0;
}

int test_hwpoison(char *primary_map, size_t len)
{
	const unsigned long pagesize = getpagesize();
	const int num_poison_checks = 512;
	unsigned long bytes_per_check = len/num_poison_checks;
	struct sigaction new, old;
	int i;

	printf(PREFIX "poisoning %p -> %p\n", primary_map, primary_map + len);
	if (madvise(primary_map, len, MADV_HWPOISON) < 0) {
		perror("MADV_HWPOISON failed");
		return -1;
	}

	printf(PREFIX "checking that it was poisoned "
	       "(%d addresses within %p -> %p)\n",
	       num_poison_checks, primary_map, primary_map + len);

	new.sa_sigaction = &sigbus_handler;
	new.sa_flags = SA_SIGINFO;
	if (sigaction(SIGBUS, &new, &old) < 0) {
		perror("could not setup SIGBUS handler");
		return -1;
	}

	if (pagesize > bytes_per_check)
		bytes_per_check = pagesize;

	for (i = 0; i < len; i += bytes_per_check)
		if (test_poison_sigbus(primary_map + i) < 0)
			return -1;
	/* check very last byte, because we left it unmapped */
	if (test_poison_sigbus(primary_map + len - 1))
		return -1;

	return 0;
}

int test_hgm(int fd, size_t hugepagesize, size_t len, bool hwpoison)
{
	int ret = 0;
	int uffd;
	char *primary_map, *secondary_map;
	struct uffdio_api api;
	struct uffdio_register reg;

	if (ftruncate(fd, len) < 0) {
		perror("ftruncate failed");
		return -1;
	}

	uffd = userfaultfd(O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("uffd not created");
		return -1;
	}

	primary_map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (primary_map == MAP_FAILED) {
		perror("mmap for primary mapping failed");
		ret = -1;
		goto close_uffd;
	}
	secondary_map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (secondary_map == MAP_FAILED) {
		perror("mmap for secondary mapping failed");
		ret = -1;
		goto unmap_primary;
	}

	printf(PREFIX "primary mapping: %p\n", primary_map);
	printf(PREFIX "secondary mapping: %p\n", secondary_map);

	api.api = UFFD_API;
	api.features = UFFD_FEATURE_MINOR_HUGETLBFS |
		UFFD_FEATURE_MISSING_HUGETLBFS |
		UFFD_FEATURE_MINOR_HUGETLBFS_HGM | UFFD_FEATURE_SIGBUS |
		UFFD_FEATURE_EXACT_ADDRESS;
	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		perror("UFFDIO_API failed");
		ret = -1;
		goto out;
	}
	if (!(api.features & UFFD_FEATURE_MINOR_HUGETLBFS_HGM)) {
		puts("UFFD_FEATURE_MINOR_HUGETLBFS_HGM not present");
		ret = -1;
		goto out;
	}

	reg.range.start = (unsigned long)primary_map;
	reg.range.len = len;
	reg.mode = UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_MISSING;
	reg.ioctls = 0;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		perror("register failed");
		ret = -1;
		goto out;
	}

	if (test_continues(uffd, primary_map, secondary_map, len, !hwpoison)
		|| (hwpoison && test_hwpoison(primary_map, len))
		|| test_collapse(primary_map, len, hwpoison)) {
		ret = -1;
	}

	if (ftruncate(fd, 0) < 0) {
		perror("ftruncate back to 0 failed");
		ret = -1;
	}

out:
	munmap(secondary_map, len);
unmap_primary:
	munmap(primary_map, len);
close_uffd:
	close(uffd);
	return ret;
}

int main(void)
{
	int fd;
	struct statfs file_stat;
	size_t hugepagesize;
	size_t len;

	fd = memfd_create("hugetlb_tmp", MFD_HUGETLB);
	if (fd < 0) {
		perror("could not open hugetlbfs file");
		return -1;
	}

	memset(&file_stat, 0, sizeof(file_stat));
	if (fstatfs(fd, &file_stat)) {
		perror("fstatfs failed");
		goto close;
	}
	if (file_stat.f_type != HUGETLBFS_MAGIC) {
		printf("not hugetlbfs file\n");
		goto close;
	}

	hugepagesize = file_stat.f_bsize;
	len = 2 * hugepagesize;
	printf("HGM regular test...\n");
	printf("HGM regular test:  %s\n",
			test_hgm(fd, hugepagesize, len, false)
			? "FAILED" : "PASSED");
	printf("HGM hwpoison test...\n");
	printf("HGM hwpoison test: %s\n",
			test_hgm(fd, hugepagesize, len, true)
			? "FAILED" : "PASSED");
close:
	close(fd);

	return 0;
}
