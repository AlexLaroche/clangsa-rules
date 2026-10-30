#include <stddef.h>

void die(const char *);
void copy_file(const char *, ...);
struct MvString {
	MvString &operator=(const char *);
	void trimBoth();
	int compare(size_t, size_t, const char *) const;
	size_t find(const char *) const;
	MvString substr(size_t, size_t = (size_t)-1) const;
	const char *c_str() const;
	size_t length() const;
};
struct File { const char *c_str() const; };
extern File file;
struct string { static const size_t npos = (size_t)-1; };
struct GroupList { void push_back(const MvString &); };
extern GroupList group_list;

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define MEMSIZE 256

void bad1()
{
	// ruleid: raptor-insecure-api-access-stat
	int res = access("/tmp/userfile", R_OK);
	if (res != 0)
		die("access");

	int fd = open("/tmp/userfile", O_RDONLY);
	// ...
}

void bad2(char *file)
{
	struct stat statb;
	int fd;

	errno = 0;

	// ruleid: raptor-insecure-api-access-stat
	if (lstat(file, &statb) < 0)
		goto out;

	if (!(statb.st_mode & S_IFREG) || statb.st_mode & 077)
		goto out;
	if ((fd = open(file, O_RDWR | O_SYNC, 0)) < 0)
		goto out;
out:;
}

void bad3(char *fname)
{
	struct stat stbl;
	int fd = open(fname, O_RDONLY);

	if (fd == -1)
		perror("open");
	// ruleid: raptor-insecure-api-access-stat
	if (lstat(fname, &stbl) != 0)
		die("file not there");
	if (!S_ISREG(stbl.st_mode))
		die("its a symlink");
	// ...
}

void test_001()
{
	const char *original_key = "path/to/file/filename";
	const char *mirror_key = "path/to/another/file/filename";

	// ruleid: raptor-insecure-api-access-stat
	if ((access(original_key, F_OK) == 0) && (access(mirror_key, F_OK) == 0))
	{
		copy_file("/bin/cp %s %s", original_key, mirror_key);

		unlink(original_key);
	}
}

void test_002()
{
	const char *original_key = "path/to/file/filename";

	// ruleid: raptor-insecure-api-access-stat
	if (access(original_key, W_OK) == 0)
	{
		FILE *fp = fopen(original_key, "wb");
	}
}

void test_001_stack_overflow()
{
	struct stat buf;
	FILE *fp;
	char data[2560];

	// ruleid: raptor-insecure-api-access-stat
	if (stat(file.c_str(), &buf) == 0)
	{

		// Open the file for reading
		fp = fopen(file.c_str(), "r");
		if (fp == NULL)
		{
			char message[2560];
			sprintf(message, "File '%s' Cound Not be Opened", file.c_str());
			// DISPLAY_MSG_ERROR( this, message, "GetFileContents", "System" );
			throw message;
		}

		// Read the file
		MvString s, ss;
		while (fgets(data, sizeof(data), fp) != (char *)0)
		{
			s = data;
			s.trimBoth();
			if (s.compare(0, 5, "GROUP") == 0)
			{
				// size_t t = s.find_last_of( ":" );
				size_t t = s.find(":");
				if (t != string::npos)
				{
					ss = s.substr(t + 1).c_str();
					ss.trimBoth();
					ss = ss.substr(1, ss.length() - 3).c_str();
					group_list.push_back(ss);
				}
			}
		}

		// Close the file
		fclose(fp);
	}
}

int ok()
{
	int fd = open("file.txt", O_RDONLY);
	if (fd == -1)
	{
		perror("open");
		return -1;
	}

	struct stat st;
	// ok: raptor-insecure-api-access-stat
	if (fstat(fd, &st) == -1)
	{
		perror("fstat");
		close(fd);
		return -1;
	}

	// Now safely use st.st_mode, st.st_size, etc. on the already-open fd
	// ...
}

int main()
{
	printf("Hello, World!");
	return 0;
}
