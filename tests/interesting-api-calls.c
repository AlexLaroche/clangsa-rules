// Marco Ivaldi <raptor@0xdeadbeef.info>
// Ported from semgrep-rules/rules/c/interesting-api-calls.c (made compilable)
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>

char *gets(char *s); /* removed from C11 headers */

/* memory_copy() */
typedef unsigned char Bytef;
unsigned long crc32(unsigned long, const Bytef *, unsigned int);
struct flb_net_setup { int x; };
struct flb_stream { struct flb_net_setup net; } *stream;
struct flb_net_setup *net_setup;
void flb_net_setup_init(struct flb_net_setup *);
void *p_buf, *serialized_context_buffer, *src, *data, *temp, *pcmd;
char *serialized_profiles_context_buffer;
size_t serialization_buffer_offset, serialized_context_size, length, cfl_sds_len(char *);
struct { struct { char *buf; } wrapped; } *str;
struct { char *block_data; size_t used_size; } *c;
uint32_t crc;
size_t outlen, len;
struct { int x; } load_command;
struct sortlist { int x; };
struct { struct sortlist *sortlist; int nsortlist; } *sysconfig, *channel;

/* service_attr_req() */
typedef struct sdp_req sdp_req_t;
typedef struct { uint8_t *data; int data_size; } sdp_buf_t;
typedef struct { struct { int maxBytesSent; } cStateValue; } sdp_cont_state_t;
sdp_buf_t *sdp_get_cached_rsp(sdp_cont_state_t *);
void SDPDBG(const char *, ...);
short MIN(int, int);
int max_rsp_size;
uint8_t *pResponse;

/* call_clone3() */
typedef uint64_t __aligned_u64 __attribute__((aligned(8)));
struct __clone_args { __aligned_u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; };
struct clone_args { __aligned_u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; };
enum test_mode {
	CLONE3_ARGS_NO_TEST,
	CLONE3_ARGS_ALL_0,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_BIG,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_NEG,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_CSIG,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_NSIG,
};
static pid_t sys_clone3(); /* called with two args below, defined with one */
void ksft_print_msg(const char *, ...);

/* test_exec() */
#define ETC_GITATTRIBUTES "/etc/gitattributes"
#define SHELL_PATH "/bin/sh"
void *system_path(const char *);
const char *path;
struct { char *buf; } man_page, shell_cmd;
char **user_argv;

/* test_spawn() */
struct inheritance { int flags; };
pid_t spawn(const char *, int, const int *, const struct inheritance *, const char **, const char **);
pid_t spawnp(const char *, int, const int *, const struct inheritance *, const char **, const char **);

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 256

void drop_priv_perm()
{
	// ruleid: raptor-interesting-api-calls
	setuid(getuid());
}

void drop_priv_temp()
{
	// ruleid: raptor-interesting-api-calls
	seteuid(getuid());
}

void copy_append_string(char *string1, char *string2)
{
	char buf[BUFSIZE];

	// ruleid: raptor-interesting-api-calls
	strcpy(buf, string1);

	// ruleid: raptor-interesting-api-calls
	strcat(buf, string2);
}

void copy_string(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-interesting-api-calls
	stpcpy(buf, string);
}

void copy_string1(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-interesting-api-calls
	strncpy(buf, string, BUFSIZE);
}

void copy_string2(char *string)
{
	char buf[BUFSIZE];

	// ruleid: raptor-interesting-api-calls
	stpncpy(buf, string, BUFSIZE);
}

void get_string()
{
	char buf[BUFSIZE];

	// ruleid: raptor-interesting-api-calls
	gets(buf);
}

void memory_copy()
{

	// ...

	// ruleid: raptor-interesting-api-calls
	memcpy(&(((char *)p_buf)[serialization_buffer_offset]),
		   serialized_context_buffer,
		   serialized_context_size);

	// ...

	// ruleid: raptor-interesting-api-calls
	memcpy(&(((char *)p_buf)[serialization_buffer_offset]),
		   serialized_profiles_context_buffer,
		   cfl_sds_len(serialized_profiles_context_buffer));

	// ...

	// ruleid: raptor-interesting-api-calls
	memcpy((void *)str->wrapped.buf, src, 3 * length + 1);

	// ...

	if (net_setup == NULL)
	{
		flb_net_setup_init(&stream->net);
	}
	else
	{
		// ok: raptor-interesting-api-calls
		memcpy(&stream->net, net_setup, sizeof(struct flb_net_setup));
	}

	// ...

	crc = __bswap_32(crc32(0, (const Bytef *)data, len));
	// ok: raptor-interesting-api-calls
	memcpy((char *)c->block_data + outlen, &crc, 4);
	c->used_size = outlen + 4;

	// ...

	// ok: raptor-interesting-api-calls
	memcpy(&load_command, pcmd, sizeof load_command);

	// ...

	// chose not to use pattern-not: $FUN($_, $_, <... sizeof(...) ...>, ...)
	// ruleid: raptor-interesting-api-calls
	memcpy(temp, sysconfig->sortlist,
		   sizeof(*channel->sortlist) * sysconfig->nsortlist);
}

// https://cc-sw.com/semgrep-guide-for-a-security-engineer-part-6-of-6/
static int service_attr_req(sdp_req_t *req, sdp_buf_t *buf)
{
	sdp_cont_state_t *cstate = NULL;
	// ...
	if (cstate)
	{
		sdp_buf_t *pCache = sdp_get_cached_rsp(cstate);

		SDPDBG("Obtained cached rsp : %p", pCache);

		if (pCache)
		{
			short sent = MIN(max_rsp_size, pCache->data_size - cstate->cStateValue.maxBytesSent);
			pResponse = pCache->data;
			// ruleid: raptor-interesting-api-calls
			memcpy(buf->data, pResponse + cstate->cStateValue.maxBytesSent, sent); // Out-of-bound read here
			buf->data_size += sent;
			cstate->cStateValue.maxBytesSent += sent;
			// ...
		}
		// ...
	}
}

static int call_clone3(uint64_t flags, size_t size, enum test_mode test_mode)
{
	struct __clone_args args = {
		.flags = flags,
		.exit_signal = SIGCHLD,
	};

	struct clone_args_extended
	{
		struct __clone_args args;
		__aligned_u64 excess_space[2];
	} args_ext;

	pid_t pid = -1;
	int status;

	memset(&args_ext, 0, sizeof(args_ext));
	if (size > sizeof(struct __clone_args))
		args_ext.excess_space[1] = 1;

	if (size == 0)
		size = sizeof(struct __clone_args);

	switch (test_mode)
	{
	case CLONE3_ARGS_NO_TEST:
		/*
		 * Uses default 'flags' and 'SIGCHLD'
		 * assignment.
		 */
		break;
	case CLONE3_ARGS_ALL_0:
		args.flags = 0;
		args.exit_signal = 0;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_BIG:
		args.exit_signal = 0xbadc0ded00000000ULL;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_NEG:
		args.exit_signal = 0x0000000080000000ULL;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_CSIG:
		args.exit_signal = 0x0000000000000100ULL;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_NSIG:
		args.exit_signal = 0x00000000000000f0ULL;
		break;
	}

	memcpy(&args_ext.args, &args, sizeof(struct __clone_args));

	// currently commented-out in the rule to avoid too much noise
	// todoruleid: raptor-interesting-api-calls
	pid = sys_clone3((struct __clone_args *)&args_ext, size);
	if (pid < 0)
	{
		ksft_print_msg("%s - Failed to create new process\n",
					   strerror(errno));
		return -errno;
	}

	if (pid == 0)
	{
		ksft_print_msg("I am the child, my PID is %d\n", getpid());
		_exit(EXIT_SUCCESS);
	}

	ksft_print_msg("I am the parent (%d). My child's pid is %d\n",
				   getpid(), pid);

	if (waitpid(-1, &status, __WALL) < 0)
	{
		ksft_print_msg("Child returned %s\n", strerror(errno));
		return -errno;
	}
	if (WEXITSTATUS(status))
		return WEXITSTATUS(status);

	return 0;
}

static pid_t sys_clone3(struct clone_args *args)
{
	// ruleid: raptor-interesting-api-calls
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

int test_exec(void)
{
	// ok: raptor-interesting-api-calls
	void *system_wide = system_path(ETC_GITATTRIBUTES);
	printf("Main program started\n");
	char *argv[] = {"jim", "jams", NULL};
	char *envp[] = {"some", "environment", NULL};
	// ruleid: raptor-interesting-api-calls
	if (execve("./sub", argv, envp) == -1)
		perror("Could not execve");
	// ruleid: raptor-interesting-api-calls
	execlp(path, "emacsclient", "-e", man_page.buf, (char *)NULL);
	// ruleid: raptor-interesting-api-calls
	execl(SHELL_PATH, SHELL_PATH, "-c", shell_cmd.buf, (char *)NULL);
	// ruleid: raptor-interesting-api-calls
	execv(user_argv[0], (char *const *)user_argv);
	// ruleid: raptor-interesting-api-calls
	return system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
	return 1;
}

void test_spawn(int argc, char *argv[])
{
	pid_t child;
	int fd_count, fd_map[10];
	struct inheritance inherit;
	const char *c_argv[10], *c_envp[10];
	char buf[256];
	int nbytes;

	int c_stdin[2], c_stdout[2], c_stderr[2]; /* Pipes for child
											   * communication */

	/* Create pipes to communicate with child via stdin/stdout/stderr */
	// ruleid: raptor-interesting-api-calls
	if (pipe(c_stdin) || pipe(c_stdout) || pipe(c_stderr))
	{
		perror("Bad pipe");
		exit(-1);
	}

	/* Set up file descriptor map for child process */
	fd_map[0] = dup(c_stdin[0]);  /* child stdin is read end of pipe */
	fd_map[1] = dup(c_stdout[1]); /* child stdout is write end of pipe */
	fd_map[2] = dup(c_stderr[1]); /* child stderr is write end of pipe */
	fd_count = 3;

	/* Close unused end of pipes for the parent */
	close(c_stdin[0]);
	close(c_stdout[1]);
	close(c_stderr[1]);

	/* Build the argument structure for child arguments.
	 *  [0] is the program name */
	c_argv[0] = "spawnc";
	c_argv[1] = "arg1";
	c_argv[2] = "arg2";
	c_argv[3] = NULL;

	/* Build the environment structure which defines the child's
	 * environment variables */
	c_envp[0] = "TEST_ENV=YES";
	c_envp[1] = "BPX_SHAREAS=NO";
	c_envp[2] = NULL;

	/* Spawn the child process */
	// ruleid: raptor-interesting-api-calls
	child = spawnp("spawnc", fd_count, fd_map, &inherit, c_argv, c_envp);
	// ruleid: raptor-interesting-api-calls
	child = spawn("/usr/bin/spawnc", fd_count, fd_map, &inherit, c_argv, c_envp);
	if (child == -1)
	{
		perror("Error on spawn");
		exit(-1);
	}
	else
		printf("Spawned %i\n", child);

	/* Test interaction with the child process */
	printf("parent: Asking child, \"what are you doing?\\n\"\n");
	// ruleid: raptor-interesting-api-calls
	strcpy(buf, "child from parent: what are you doing?\n");
	if (write(c_stdin[1], buf, sizeof(buf)) == -1)
	{
		perror("write stdout");
		exit(-1);
	}

	memset(buf, 0, 255); /* Just zeroing out the buffer */
	printf("parent: reading from child now\n");
	// ruleid: raptor-interesting-api-calls
	if ((nbytes = read(c_stdout[0], buf, 255)) == -1)
	{
		perror("read error:");
		exit(-1);
	}
	printf("parent: child says, \"%s\"\n", buf);

	/* Cleanup pipes before exiting */
	close(c_stdin[1]);
	close(c_stdout[0]);
	close(c_stderr[0]);

	exit(0);
}

int main()
{
	printf("Hello, World!");
	return 0;
}
