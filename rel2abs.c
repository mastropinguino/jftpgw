/*
 * Copyright (C) 1999-2004 Joachim Wieland <joe@mcknight.de>
 * Copyright (c) 1997 Shigio Yamaguchi. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Shigio Yamaguchi.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
/*
 * rel2abs: convert an relative path name into absolute.
 *
 *	i)	path	relative path
 *	i)	base	base directory (must be absolute path)
 *	o)	result	result buffer
 *	i)	size	size of result buffer
 *	r)		!= NULL: absolute path
 *			== NULL: error
 */
char *
rel2abs(path, base, result, size)
	const char *path;
	const char *base;
	char *result;
	const size_t size;
{
	const char *pp, *bp;
	/*
	 * endp points the last position which is safe in the result buffer.
	 */
	const char *endp = result + size - 1;
	char *rp;
	int length;

	if (*path == '/') {
		if (strlen(path) >= size)
			goto erange;
		strcpy(result, path);
		goto finish;
	} else if (*base != '/' || !size) {
		errno = EINVAL;
		return (NULL);
	} else if (size == 1)
		goto erange;
	if (!strcmp(path, ".") || !strcmp(path, "./")) {
		if (strlen(base) >= size)
			goto erange;
		strcpy(result, base);
		/*
		 * rp points the last char.
		 */
		rp = result + strlen(base) - 1;
		if (*rp == '/')
			*rp = 0;
		else
			rp++;
		/* rp point NULL char */
		if (*++path == '/') {
			/*
			 * Append '/' to the tail of path name.
			 */
			*rp++ = '/';
			if (rp > endp)
				goto erange;
			*rp = 0;
		}
		goto finish;
	}
	bp = base + strlen(base);
	if (*(bp - 1) == '/')
		--bp;
	/*
	 * up to root.
	 */
	for (pp = path; *pp && *pp == '.'; ) {
		if (!strncmp(pp, "../", 3)) {
			pp += 3;
			while (bp > base && *--bp != '/')
				;
		} else if (!strncmp(pp, "./", 2)) {
			pp += 2;
		} else if (!strncmp(pp, "..\0", 3)) {
			pp += 2;
			while (bp > base && *--bp != '/')
				;
		} else
			break;
	}
	/*
	 * down to leaf.
	 */
	length = bp - base;
	if (length >= size)
		goto erange;
	strncpy(result, base, length);
	rp = result + length;
	if (*pp || *(pp - 1) == '/' || length == 0)
		*rp++ = '/';
	if (rp + strlen(pp) > endp)
		goto erange;
	strcpy(rp, pp);
finish:
	return result;
erange:
	errno = ERANGE;
	return (NULL);
}


/* the following code is by Joachim Wieland <jwieland@bigfoot.de> for jftpgw
 * */

#ifdef WITH_MAIN

#include <limits.h>
#include <stdio.h>

int main(int argc, char** argv) {
	char buf[PATH_MAX + 1];
	char* ret;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <relativepath> <basepath>\n\n",
				argv[0]);
		return 1;
	}

	ret = rel2abs(argv[1], argv[2], buf, sizeof(buf) - 1);
	if (!ret) {
		/* an error occurred */
		ret = argv[2];
	}
	printf("%s\n", ret);

	return 0;
}

#endif /* WITH_MAIN */
