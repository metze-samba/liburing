/* SPDX-License-Identifier: MIT */
/*
 * Description: Implicit RWF_NOWAIT bug
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

#define BLOCK	4096

#ifndef RWF_NOWAIT
#define RWF_NOWAIT	8
#endif

static int get_file_fd(void)
{
	ssize_t ret;
	char *buf;
	int fd;

	fd = open("testfile", O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		perror("open file");
		return -1;
	}

	buf = malloc(BLOCK);
	memset(buf, 0xff, BLOCK);
	ret = pwrite(fd, buf, BLOCK, 0);
	if (ret != BLOCK) {
		if (ret < 0)
			perror("write");
		else
			printf("Short write\n");
		goto err;
	}
	ret = pwrite(fd, buf, BLOCK, BLOCK);
	if (ret != BLOCK) {
		if (ret < 0)
			perror("write");
		else
			printf("Short write\n");
		goto err;
	}
	fsync(fd);

	if (posix_fadvise(fd, BLOCK, BLOCK, POSIX_FADV_DONTNEED)) {
		perror("fadvise");
err:
		close(fd);
		free(buf);
		return -1;
	}

	free(buf);
	return fd;
}

static void put_file_fd(int fd)
{
	close(fd);
	unlink("testfile");
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct iovec iov;
	int ret, fd;

	iov.iov_base = malloc(2*BLOCK);
	iov.iov_len = BLOCK;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		printf("ring setup failed\n");
		return 1;

	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		printf("get sqe failed\n");
		return 1;
	}

	fd = get_file_fd();
	if (fd < 0)
		return 1;

	io_uring_prep_readv(sqe, fd, &iov, 1, 0);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)0x11111111);
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		printf("Got submit %d, expected 1\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		printf("Ring wait got %d\n", ret);
		goto err;
	}
	ret = (uintptr_t)io_uring_cqe_get_data(cqe);
	if (ret != 0x11111111) {
		printf("Got invalid data 0x%08x, expected 0x11111111\n", ret);
		goto err;
	}
	io_uring_cq_advance(&ring, 1);

	if (cqe->res != BLOCK) {
		printf("cqe res=%d != %u\n", cqe->res, BLOCK);
		goto err;
	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		printf("get sqe failed\n");
		return 1;
	}

	iov.iov_len = 2*BLOCK;
	io_uring_prep_readv(sqe, fd, &iov, 1, 0);
	// Impliet by broken kernels? sqe->rw_flags = RWF_NOWAIT;
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)0x22222222);
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		printf("Got submit %d, expected 1\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		printf("Ring peek got %d\n", ret);
		goto err;
	}
	ret = (uintptr_t)io_uring_cqe_get_data(cqe);
	if (ret != 0x22222222) {
		printf("Got invalid data 0x%08x, expected 0x22222222\n", ret);
		goto err;
	}
	io_uring_cq_advance(&ring, 1);

	if (cqe->res != 2*BLOCK) {
		printf("cqe res=%d != %u\n", cqe->res, 2*BLOCK);
		goto err;
	}

	put_file_fd(fd);
	return 0;
err:
	put_file_fd(fd);
	return 1;
}
