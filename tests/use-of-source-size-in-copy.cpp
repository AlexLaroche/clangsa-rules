// raptor.UseOfSourceSizeInCopy, C++ containers: a fixed-size destination
// filled with `v.data()` for `v.size()` bytes. Modelled on CVE-2026-44634
// (SimpleBLE: `memcpy(services->data, service.data().data(),
// service.data().size());` into a 27-byte array, and Dongl's
// `memcpy(write.data.bytes, data.data(), data.size());`); the fixes copy
// `std::min(v.size(), sizeof(dst))` or reject larger payloads first.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

struct service_t {
	char uuid[37];
	size_t data_length;
	uint8_t data[27];
};
struct Service {
	std::vector<uint8_t> data() const;
	std::string uuid() const;
};

void services_get(const Service &service, service_t *services)
{
	services->data_length = service.data().size();
	// ruleid: raptor-use-of-source-size-in-copy
	memcpy(services->data, service.data().data(), service.data().size());
}

void services_get_fixed(const Service &service, service_t *services)
{
	const size_t copy_len = std::min(service.data().size(), sizeof(services->data));
	services->data_length = service.data().size();
	// ok: raptor-use-of-source-size-in-copy
	memcpy(services->data, service.data().data(), copy_len);
}

struct write_cmd {
	struct {
		size_t size;
		uint8_t bytes[512];
	} data;
};

void write(write_cmd &cmd, const std::vector<uint8_t> &data)
{
	cmd.data.size = data.size();
	// ruleid: raptor-use-of-source-size-in-copy
	memcpy(cmd.data.bytes, data.data(), data.size());
}

void write_fixed(write_cmd &cmd, const std::vector<uint8_t> &data)
{
	if (data.size() > sizeof(cmd.data.bytes))
		throw std::length_error("payload too large");
	cmd.data.size = data.size();
	// ok: raptor-use-of-source-size-in-copy
	memcpy(cmd.data.bytes, data.data(), data.size());
}

// A destination sized from the source.
void copy_out(std::vector<uint8_t> &out, const std::string &s)
{
	out.resize(s.size());
	// ok: raptor-use-of-source-size-in-copy
	memcpy(out.data(), s.data(), s.size());
}
