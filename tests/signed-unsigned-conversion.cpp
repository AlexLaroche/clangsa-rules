#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

// stubs so that the test compiles
typedef int NaClHandle;
struct NaClDesc;
struct NaClDescImcShm { int fd; };
#define dprintf(args) printf args
void NaClDescImcShmCtor(struct NaClDescImcShm *, NaClHandle, off_t);
namespace nacl { NaClHandle CreateMemoryObject(size_t); }
struct Plugin;
struct SharedMemory {
	static SharedMemory *New(Plugin *plugin, off_t length);
	static SharedMemory *New(Plugin *plugin, struct NaClDesc *desc);
};

SharedMemory *SharedMemory::New(Plugin *plugin, off_t length)
{
	void *map_addr = NULL;
	// ruleid: raptor-signed-unsigned-conversion
	size_t size = static_cast<size_t>(length);
	NaClHandle handle = nacl::CreateMemoryObject(size);
	struct NaClDescImcShm *imc_desc = reinterpret_cast<struct NaClDescImcShm *>(malloc(sizeof(*imc_desc)));
	struct NaClDesc *desc = reinterpret_cast<struct NaClDesc *>(imc_desc);
	dprintf(("SharedMemory::New(%p, 0x%08x)\n ", plugin, (unsigned)length));
	NaClDescImcShmCtor(imc_desc, handle, length);
	return New(plugin, desc);
}

int main()
{
	printf("Hello, World!");
	return 0;
}
