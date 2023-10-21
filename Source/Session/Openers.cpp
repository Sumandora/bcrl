#include "BCRL.hpp"

#include "SignatureScanner.hpp"

using namespace BCRL;

Session Session::module(const char* moduleName)
{
	memoryRegionStorage.update();
	std::vector<MemoryRegionStorage::MemoryRegion> memoryRegions = memoryRegionStorage.getMemoryRegions(std::nullopt, std::nullopt, moduleName);
	if (memoryRegions.empty())
		return { nullptr, true };
	return { &memoryRegions[0].addressSpace.front(), true };
}

Session Session::string(const char* string)
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

Session Session::signature(const char* signature, std::optional<bool> code)
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

Session Session::pointerList(const std::vector<void*>& pointers)
{
	memoryRegionStorage.update();
	return { pointers, true };
}

Session Session::pointer(void* pointer)
{
	memoryRegionStorage.update();
	return { pointer, true };
}

Session Session::arrayPointer(void* pointerArray, std::size_t index)
{
	memoryRegionStorage.update();
	return { { SafePointer(pointerArray).dereference().add(index * sizeof(void*)).dereference() }, true };
}
