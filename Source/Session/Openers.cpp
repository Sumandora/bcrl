#include "BCRL.hpp"

#include "SignatureScanner.hpp"

BCRL::Session BCRL::Session::module(const char* moduleName)
{
	memoryRegionStorage.update();
	std::vector<MemoryRegionStorage::MemoryRegion> memoryRegions = memoryRegionStorage.getMemoryRegions(std::nullopt, std::nullopt, moduleName);
	if (memoryRegions.empty())
		return { nullptr, true };
	return { &memoryRegions[0].addressSpace.front(), true };
}

BCRL::Session BCRL::Session::string(const char* string)
{
	memoryRegionStorage.update();
	std::vector<void*> pointers{};
	SignatureScanner::StringSignature signature{ string };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.getMemoryRegions()) {
		for (void* ptr : signature.findAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			pointers.push_back(ptr);
		}
	}

	return { pointers, true };
}

BCRL::Session BCRL::Session::signature(const char* signature, std::optional<bool> code)
{
	memoryRegionStorage.update();
	std::vector<void*> pointers{};
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.getMemoryRegions(std::nullopt, code)) {
		for (void* ptr : convertedSignature.findAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			pointers.push_back(ptr);
		}
	}

	return { pointers, true };
}

BCRL::Session BCRL::Session::pointerList(std::vector<void*> pointers)
{
	memoryRegionStorage.update();
	return { pointers, true };
}

BCRL::Session BCRL::Session::pointer(void* pointer)
{
	memoryRegionStorage.update();
	return { pointer, true };
}

BCRL::Session BCRL::Session::arrayPointer(void* pointerArray, std::size_t index)
{
	memoryRegionStorage.update();
	return { (*reinterpret_cast<void***>(pointerArray))[index], true };
}
