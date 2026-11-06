#include <stdio.h>
#include <unistd.h>

void drop_priv_perm()
{
	// ruleid: raptor-unchecked-ret-setuid-seteuid
	setuid(getuid());
}

int drop_priv_perm2()
{
	// ok: raptor-unchecked-ret-setuid-seteuid
	if (!setuid(getuid()))
	{
		// ...
		return 0;
	}
	return -1;
}

void drop_priv_temp()
{
	// ruleid: raptor-unchecked-ret-setuid-seteuid
	seteuid(getuid());
}

int drop_priv_temp2()
{
	// ok: raptor-unchecked-ret-setuid-seteuid
	if (seteuid(getuid()) < 0)
		return -1;

	// ...
}

// The call as the condition itself: non-zero means failure (OpenVPN
// `if (setuid(state->uid)) msg(M_ERR, ...)`).
void fatal(const char *msg);
void drop_priv_condition(uid_t uid)
{
	// ok: raptor-unchecked-ret-setuid-seteuid
	if (setuid(uid))
		fatal("setuid");
	// ok: raptor-unchecked-ret-setuid-seteuid
	while (seteuid(uid))
		fatal("seteuid");
	// ruleid: raptor-unchecked-ret-setuid-seteuid
	(void)setuid(uid);
}

int main()
{
	printf("Hello, World!");
	return 0;
}
