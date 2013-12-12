/* 
 * Copyright (C) 1999-2004 Joachim Wieland <joe@mcknight.de>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111, USA.
 */

#include <time.h>

#define CACHE_AVAILABLE			0
#define CACHE_NOTAVL_EXIST		1
#define CACHE_NOTAVL_SIZE		2
#define CACHE_NOTAVL_DATE		3
#define CACHE_NOTAVL_CHECKSUM		4
#define CACHE_NOTAVL_DEACTIVATED	5

struct cache_filestruct {
	char* host;
	int port;
	char* user;
	char* filepath;
	char* filename;
	unsigned long size;
	char* checksum;
	time_t date;
};


int cache_add(struct cache_filestruct);
int cache_delete(struct cache_filestruct, int warn);
int cache_readfd(struct cache_filestruct);
int cache_writefd(struct cache_filestruct);
int cache_want(struct cache_filestruct);

struct clientinfo;
int cache_init(struct clientinfo*);
int cache_shutdown(struct clientinfo*);
struct cache_filestruct cache_gather_info(const char* filename,
		struct clientinfo*);

