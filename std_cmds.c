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

#include "jftpgw.h"
#include "cmds.h"

extern int timeout;

/* these two functions reside in cmds.c */
int getuserdest(const char*, struct clientinfo*);
int getpasswd(const char*, struct clientinfo*);

int login(struct clientinfo*, int);

int transfer_initiate(struct conn_info_st* conn_info, int retrieve_from_cache){
	int ret;
	char *t;
	time_t transfer_start;

	ret = transfer_negotiate(conn_info->clntinfo);
	if (ret == -1) {
		/* dramatic error */
		return 1;
	}

	if (ret == 0) {
		/* if there was no error, transfer the file or
		 * listing */
		transfer_start = time(NULL);
		ret = transfer_transmit(conn_info->clntinfo);
		conn_info->lcs->transfer_duration = time(NULL) - transfer_start;
	} else {
		/* there was an error in transfer_negotiate but it
		 * was not dramatic
		 */
		ret = 0;
	}
	if (ret == TRNSMT_SUCCESS) {
		/* the transfer was okay */
		if (retrieve_from_cache) {
			say(conn_info->clntinfo->clientsocket,
					"226 Transfer complete\r\n");
			conn_info->lcs->respcode = 226;
			conn_info->lcs->complete = 1;
		} else {
			t = passall(conn_info->clntinfo->serversocket,
				    conn_info->clntinfo->clientsocket);
			conn_info->lcs->respcode = respcode(t);
			conn_info->lcs->complete = conn_info->lcs->respcode == 226;
			free(t);
		}
	} else {
		if (ret == TRNSMT_ABORTED) {
			/* an aborted transfer, everything's fine */
		}
		if (ret == TRNSMT_NOERRORMSG) {
			/* do not generate an error message */
		}
		if (ret == TRNSMT_ERROR) {
			/* generate error message */
			if (timeout) {
				jlog(2, "Timeout in %s line %d\n", __FILE__
						,__LINE__);
				err_time_readline(
					conn_info->clntinfo->clientsocket);
			} else {
				err_readline(conn_info->clntinfo->serversocket);
			}
			return 1;
		}
	}
	return ret;
}


int std_quit(const char* args, struct conn_info_st* conn_info) {

	int ss = conn_info->clntinfo->serversocket;
	int cs = conn_info->clntinfo->clientsocket;

	/* Are we already connected to a server? */
	if (conn_info->clntinfo->login.stage >= LOGIN_ST_CONNECTED) {
		char* response;
		say(ss, "QUIT\r\n");
		response = passall(ss, cs);
		conn_info->lcs->respcode = respcode(response);
		free(response);
	} else {
		/* Generate an own goodbye message if we are
		 * not yet connected */
		say(cs, "221 Goodbye...\r\n");
	}
	return CMD_QUIT;
}


int std_pasv(const char* args, struct conn_info_st* conn_info) {
	char* answer = 0;
	int ret;

	if (conn_info->clntinfo->servermode == PASSIVE || 
	    conn_info->clntinfo->servermode == ASCLIENT) {
		ret = pasvserver(conn_info->clntinfo);
		if (ret == 0) {
			conn_info->lcs->respcode = 227;
		}
	} else {
		ret = activeserver(&answer, conn_info->clntinfo);
		conn_info->lcs->respcode = respcode(answer);
		free(answer);
	}

	if ( ! ret ) {
		ret |= pasvclient(conn_info->clntinfo);
	}
	if (ret) {
		if (errno == EPIPE) {
			/* The remote server has closed the connection */
			return CMD_ABORT;
		}
		return CMD_ERROR;
	}

	return CMD_HANDLED;
}


int std_port(const char* args, struct conn_info_st* conn_info) {
	int ret = 0;
	size_t sendbufsize;
	int cs = conn_info->clntinfo->clientsocket;
	struct sockaddr_in sin;
	char *answer = 0;
	char *sendbuf = 0;

	if (portcommandcheck(args, &sin, conn_info->clntinfo) < 0) {
		/* an error was already reported */
		return -1;
	}
	conn_info->clntinfo->portcmd = strdup(args);
	enough_mem(conn_info->clntinfo->portcmd);

	if (conn_info->clntinfo->servermode == ACTIVE ||
	    conn_info->clntinfo->servermode == ASCLIENT) {
		ret = activeserver(&answer, conn_info->clntinfo);
		if (ret < 0) {
			free(answer);
			return CMD_ERROR;
		}
		/* Repeat the answer of the server */
		sendbufsize = strlen(answer) + 3;
		sendbuf = (char*) malloc(sendbufsize);
		enough_mem(sendbuf);
		snprintf(sendbuf, sendbufsize, "%s\r\n", answer);
		say(cs, sendbuf);
		conn_info->lcs->respcode = respcode(sendbuf);
		free(sendbuf);
		free(answer);
	} else {
		ret |= pasvserver(conn_info->clntinfo);
		if (!ret) {
			conn_info->lcs->respcode = 200;
			say(cs, "200 PORT command successful.\r\n");
		} else {
			return CMD_ERROR;
		}
	}
	return CMD_HANDLED;
}


int std_stor(const char* args, struct conn_info_st* conn_info) {
	/* chop of the "STOR "/"STOU "/"APPE " prefix */
	char* space = strchr(args, ' ');
	if (space) {
		conn_info->lcs->filename = space + 1;
	} else {
		conn_info->lcs->filename = args;
	}

	conn_info->lcs->direction = 'i';
	conn_info->clntinfo->mode = STOR;

	/* check the transfer mode - if they differ, change the mode to the
	 * server such that it matches the one of the client */

	if (conn_info->clntinfo->transfermode_client !=
			conn_info->clntinfo->transfermode_server) {
		/* switch the transfer mode to TRANSFER_BINARY */
		char type;
		struct message answer;
		if (conn_info->clntinfo->transfermode_client
						== TRANSFER_ASCII) {
			type = 'A';
			conn_info->clntinfo->transfermode_server
							= TRANSFER_ASCII;
		} else {
			type = 'I';
			conn_info->clntinfo->transfermode_server
							= TRANSFER_BINARY;
		}
		sayf(conn_info->clntinfo->serversocket, "TYPE %c\r\n", type);
		answer = readall(conn_info->clntinfo->serversocket);
		jlog(9, "switched type to %c for storing a file: %s", type, answer.lastmsg);
		free(answer.fullmsg);
	}

	if (passcmd(args, conn_info->clntinfo) < 0) {
		return CMD_ERROR;
	}
	if (conn_info->lcs->respcode != 125 && conn_info->lcs->respcode != 150) {
		return CMD_ERROR;
	}
	if (transfer_initiate(conn_info, 0)) {
		return CMD_ERROR;
	}

	return CMD_HANDLED;
}

int std_retr(const char* args, struct conn_info_st* conn_info) {
	struct cache_filestruct cfs;
	struct message answer;
	int retrieve_from_cache = 0;
	int ret;
	char* last = (char*) 0;

	/* chop off the "RETR " prefix */
	char* space = strchr(args, ' ');
	if (space) {
		conn_info->lcs->filename = space + 1;
	} else {
		conn_info->lcs->filename = args;
	}
	conn_info->lcs->direction = 'o';

	/* check the transfer mode */
	/* we always want to have a binary connection to the server if we're
	 * retrieving a file and the cache is used */

	if (conn_info->clntinfo->transfermode_server == TRANSFER_ASCII
		&& config_get_bool("cache") == 1) {
		/* switch the transfer mode to TRANSFER_BINARY */
		say(conn_info->clntinfo->serversocket, "TYPE I\r\n");
		conn_info->clntinfo->transfermode_server = TRANSFER_BINARY;
		answer = readall(conn_info->clntinfo->serversocket);
		jlog(9, "switched type to binary for retrieving a file (cache is set to on): %s", answer.lastmsg);
		free(answer.fullmsg);
	}

	if (conn_info->clntinfo->transfermode_server == TRANSFER_BINARY
		&& config_get_bool("cache") == 0
		&& conn_info->clntinfo->transfermode_client == TRANSFER_ASCII) {
		/* switch the transfer mode to TRANSFER_ASCII on the
		 * server side as well */
		say(conn_info->clntinfo->serversocket, "TYPE A\r\n");
		conn_info->clntinfo->transfermode_server
							= TRANSFER_ASCII;
		answer = readall(conn_info->clntinfo->serversocket);
		jlog(9, "switched type to ascii for retrieving a file (cache is set to off): %s", answer.lastmsg);
		free(answer.fullmsg);
	}

	if (conn_info->clntinfo->transfermode_client == TRANSFER_ASCII
		&& conn_info->clntinfo->transfermode_server == TRANSFER_BINARY) {
		/* we'll have to convert to ascii */
		conn_info->clntinfo->transfermode_havetoconvert
							= CONV_TOASCII;
	} else {
		conn_info->clntinfo->transfermode_havetoconvert
							= CONV_NOTCONVERT;
	}

	if (config_get_bool("cache")) {
		cfs = cache_gather_info(conn_info->lcs->filename,
					conn_info->clntinfo);
		/* try to read the file from the cache */
		if ((conn_info->clntinfo->cachefd = cache_readfd(cfs)) < 0) {
			/* okay, it is not in, so try to create it */
			jlog(9, "File %s not in cache",
						conn_info->lcs->filename);
			conn_info->clntinfo->fromcache = 0;
			if ((conn_info->clntinfo->cachefd
						= cache_writefd(cfs)) < 0) {;
				conn_info->clntinfo->tocache = 0;
			} else {
				conn_info->clntinfo->tocache = 1;
			}
		} else {
			jlog(9, "File %s was in cache",
						conn_info->lcs->filename);
			conn_info->clntinfo->fromcache = 1;
			conn_info->clntinfo->tocache = 0;
		}
		free(cfs.filepath);
		free(cfs.filename);
	} else {
		/* no cache active */
		jlog(9, "caching not active");
		conn_info->clntinfo->fromcache = 0;
		conn_info->clntinfo->tocache = 0;
	}
	if (conn_info->clntinfo->fromcache) {
		/* do not send the RETR command to the server */
	}

	/* pass the request to the server if we do not have the file in the
	 * cache */
	if ( ! conn_info->clntinfo->fromcache ) {
		sayf(conn_info->clntinfo->serversocket, "RETR %s\r\n",
						conn_info->lcs->filename);

		last = passall(conn_info->clntinfo->serversocket,
					conn_info->clntinfo->clientsocket);
		if (last) {
			jlog(9, "Send (client - %d): %s",
				conn_info->clntinfo->clientsocket, last);
		}
		if (!last) {
			if (timeout) {
				jlog(2, "Timeout in %s line %d\n", __FILE__
						,__LINE__);
				err_time_readline(conn_info->clntinfo->clientsocket);
			} else {
				err_readline(conn_info->clntinfo->clientsocket);
			}
			return CMD_ERROR;
		}
		if (!checkdigits(last, 150) && !checkdigits(last, 125)) {
			jlog(4, "Server returned invalid response: %s", last);
			if (conn_info->clntinfo->fromcache) {
				close(conn_info->clntinfo->cachefd);
				conn_info->clntinfo->cachefd = -1;
			} else if (conn_info->clntinfo->tocache) {
				close(conn_info->clntinfo->cachefd);
				conn_info->clntinfo->cachefd = -1;
				cfs = cache_gather_info(
					conn_info->lcs->filename,
					conn_info->clntinfo);
				cache_delete(cfs, 1);
			}
			/* say(conn_info->clntinfo->clientsocket, last); */
			return CMD_ERROR;
		}
	} else {
		/* we pretend to be the server */
		sayf(conn_info->clntinfo->clientsocket,
				"150 Opening data connection for %s\r\n",
					conn_info->lcs->filename);
		retrieve_from_cache = 1;
	}

	/* Okay, everything is fine, establish a connection */

	ret = transfer_initiate(conn_info, retrieve_from_cache);
	if (ret != TRNSMT_SUCCESS && ret != TRNSMT_ABORTED) {
		return CMD_ERROR;
	}

	if (ret == TRNSMT_SUCCESS && conn_info->lcs->respcode == 226) {
		/* add to cache */
		if (conn_info->clntinfo->tocache) {
			struct cache_filestruct cfs;
			cfs = cache_gather_info(conn_info->lcs->filename,
							conn_info->clntinfo);
			cache_add(cfs);
			free(cfs.filepath);
			free(cfs.filename);
		}
	} else {
		if (conn_info->clntinfo->tocache) {
			/* delete again from cache - should not
			 * happen */
			struct cache_filestruct cfs;
			cfs = cache_gather_info(conn_info->lcs->filename,
							conn_info->clntinfo);
			cache_delete(cfs, 1);
			free(cfs.filepath);
			free(cfs.filename);
		}
	}
	conn_info->clntinfo->fromcache  = 0;
	conn_info->clntinfo->tocache    = 0;
	return CMD_HANDLED;
}

int std_list(const char* args, struct conn_info_st* conn_info) {
	if (passcmd(args, conn_info->clntinfo) < 0) {
		return CMD_ERROR;
	}
	if (conn_info->lcs->respcode != 125 && conn_info->lcs->respcode != 150) {
		/* the sockets are closed by transfer_cleanup */
		return CMD_ERROR;
	}
	/* This is a listing of the server that is treated like a transfer
	 * but is not converted from binary to ascii */
	conn_info->clntinfo->serverlisting = 1;
	if (transfer_initiate(conn_info, 0)) {
		return CMD_ERROR;
	}
	return CMD_HANDLED;
}


/* a simple function that determines the transfer mode (ascii or image) */

int std_type(const char* args, struct conn_info_st* conn_info) {
	char* space = strrchr(args, ' ');
	struct message answer;

	/* just register the desired type. If we're downloading we always
	 * keep a binary connection to the server and convert to ascii if
	 * necessary, if we're uploading however we pass the type through
	 * to the server. The reason for this is the cache. All files should
	 * reside in the binary format in the cache */

	if (space) {
		if (*(space + 1) == 'A' || *(space + 1) == 'a') {
			conn_info->clntinfo->transfermode_client
							= TRANSFER_ASCII;
			conn_info->lcs->type = 'a';
		} else {
			conn_info->clntinfo->transfermode_client
							= TRANSFER_BINARY;
			conn_info->lcs->type = 'b';
		}
	}

	if (conn_info->clntinfo->transfermode_client == TRANSFER_ASCII
		&& config_get_bool("cache") == 0) {
		/* switch the server to ASCII as well */
		say(conn_info->clntinfo->serversocket, "TYPE A\r\n");
		conn_info->clntinfo->transfermode_server = TRANSFER_ASCII;
	} else if (conn_info->clntinfo->transfermode_client == TRANSFER_ASCII
		&& config_get_bool("cache") == 1) {
		/* keep a binary connection to the server */
		say(conn_info->clntinfo->serversocket, "TYPE I\r\n");
		conn_info->clntinfo->transfermode_server = TRANSFER_BINARY;
	} else {
		/* default to a binary connection */
		say(conn_info->clntinfo->serversocket, "TYPE I\r\n");
		conn_info->clntinfo->transfermode_server = TRANSFER_BINARY;
	}

	answer = readall(conn_info->clntinfo->serversocket);
	free(answer.fullmsg);
	/* tell the client about the new status */
	sayf(conn_info->clntinfo->clientsocket, "200 Type set to %c\r\n",
			conn_info->lcs->type == 'a' ? 'A' : 'I');
	conn_info->lcs->respcode = 200;
	return CMD_HANDLED;
}

int std_loggedin(const char* args, struct conn_info_st* conn_info) {
	say(conn_info->clntinfo->clientsocket,
			"503 You are already logged in!\r\n");
	return CMD_HANDLED;
}


/* disable EPSV to avoid timeout.
 *        Problem Report by Ken'ichi Fukamachi <fukachan@fml.org>
 *
 * In the following case, ftp tries to run in EPSV mode but jftpgw 
 * cannot understand this, so timeout occurs.
 * 
 *    NetBSD ftpd (lukemftpd) --- jftpgw --- NetBSD ftp (lukemftp)
 * 
 * To avoid EPSV mode, disable this mode by jftpgw.
 *
 */
int std_epsv(const char* args, struct conn_info_st* conn_info) {
  int cs = conn_info->clntinfo->clientsocket;

  conn_info->lcs->respcode = 500;
  say(cs, "500 'EPSV': command not understood.\r\n");

  return CMD_HANDLED;
}
