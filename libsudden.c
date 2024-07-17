#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <linux/limits.h>

#include <SDL2/SDL_audio.h>
#include <SDL2/SDL_events.h>

#define TEXMASTER_FD_NAME "TexMasterFDName"

__attribute__((constructor))
static void texmaster_modify_binary_fix_sudden() {
	// copy /proc/self/exe into a memfd and do byte-level changes before restarting
	char path[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
	assert(len != -1);
	path[len] = '\0'; 

	if (strstr(path, TEXMASTER_FD_NAME) == NULL) {
		int exefd = open(path, O_RDONLY);
		int memfd = memfd_create(TEXMASTER_FD_NAME, MFD_CLOEXEC | MFD_ALLOW_SEALING);

		off_t offset = 0;
		struct stat stat_buf;
		fstat(exefd, &stat_buf);

		assert(sendfile(memfd, exefd, &offset, stat_buf.st_size) >= 0);

		// found after multiple hours in ghidra
		// prevents "sudden" from stopping after level 500
		assert(pwrite(memfd, "\x00", 1, 0xe053) == 1);
		assert(pwrite(memfd, "\x00", 1, 0xe054) == 1);
		assert(pwrite(memfd, "\x00", 1, 0xe05c) == 1);
		assert(pwrite(memfd, "\x00", 1, 0xe05d) == 1);

		// reduce allowed time
		int val = 0;
		val = 15; assert(pwrite(memfd, &val, sizeof(int), 0x265d0) == sizeof(int));
		val = 14; assert(pwrite(memfd, &val, sizeof(int), 0x265d4) == sizeof(int));
		val = 13; assert(pwrite(memfd, &val, sizeof(int), 0x265d8) == sizeof(int));
		val = 12; assert(pwrite(memfd, &val, sizeof(int), 0x265dc) == sizeof(int));
		val = 11; assert(pwrite(memfd, &val, sizeof(int), 0x265e0) == sizeof(int));

		// other tuning data
		// const int offsets[5] = {
		// 	0x00026318,
		// 	0x000263f8,
		// 	0x000264d8,
		// 	0x000265b8,
		// 	0x00026698,
		// };
		// for (int i = 0; i < 5; i++) {
		// 	for (int j = 0; j < 11; j++) {
		// 		offset = offsets[i]+j*sizeof(int);
		//     	int content = 0;
		// 		assert(pread(exefd, &content, sizeof(int), offset) == sizeof(int));
		// 		printf("%p => %d\n", (void*)offset, content);
		// 	}
		// }

		char *const args[] = {program_invocation_name, NULL};
		assert(fexecve(memfd, args, environ) != -1);
	}

}
