#include "BCRL.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <link.h>
#include <optional>

#include "SignatureScanner.hpp"

BCRL::Session BCRL::Session::Module(const char* moduleName)
{
	void* handle = dlopen(moduleName, RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
	if (!handle)
		return { nullptr };

	link_map* linkMap;
	if (dlinfo(handle, RTLD_DL_LINKMAP, &linkMap) != 0) {
		dlclose(handle);
		return { nullptr };
	}

	void* base = reinterpret_cast<void*>(linkMap->l_addr);

	dlclose(handle);

	return { base };
}

BCRL::Session BCRL::Session::String(const char* string)
{
	std::vector<void*> pointers{};
	const size_t length = std::strlen(string);

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions()) {
		for (std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(&fileMapping.addressSpace.front());
			 addr < reinterpret_cast<std::uintptr_t>(&fileMapping.addressSpace.back()) - length;
			 addr++) {
			char* ptr = reinterpret_cast<char*>(addr);
			if (ptr != string && std::strcmp(ptr, string) == 0) {
				pointers.push_back(reinterpret_cast<void*>(addr));
			}
		}
	}

	return { pointers };
}

BCRL::Session BCRL::Session::Signature(const char* signature)
{
	std::vector<void*> pointers{};
	SignatureScanner::Signature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions()) {
		for (std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(&fileMapping.addressSpace.front());
			 addr < reinterpret_cast<std::uintptr_t>(&fileMapping.addressSpace.back()) - convertedSignature.Size();
			 addr++) {
			if (convertedSignature.DoesMatch(reinterpret_cast<std::byte*>(addr)))
				pointers.push_back(reinterpret_cast<void*>(addr));
		}
	}

	return { pointers };
}

BCRL::Session BCRL::Session::PointerList(std::vector<void*> pointers)
{
	return { pointers };
}

BCRL::Session BCRL::Session::Pointer(void* pointer)
{
	return { pointer };
}

BCRL::Session BCRL::Session::PointerArray(void* pointerArray, std::size_t index)
{
	return { (*reinterpret_cast<void***>(pointerArray))[index] };
}
