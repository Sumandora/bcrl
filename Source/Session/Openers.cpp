#include "BCRL.hpp"

#include "SignatureScanner.hpp"

BCRL::Session BCRL::Session::Module(const char* moduleName)
{
	memoryRegionStorage.Update();
	std::vector<MemoryRegionStorage::MemoryRegion> memoryRegions = memoryRegionStorage.GetMemoryRegions(std::nullopt, std::nullopt, moduleName);
	if (memoryRegions.empty())
		return { nullptr, true };
	return { &memoryRegions[0].addressSpace.front(), true };
}

BCRL::Session BCRL::Session::String(const char* string)
{
	memoryRegionStorage.Update();
	std::vector<void*> pointers{};
	SignatureScanner::StringSignature signature{ string };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions()) {
		for (void* ptr : signature.findAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			pointers.push_back(ptr);
		}
	}

	return { pointers, true };
}

BCRL::Session BCRL::Session::Signature(const char* signature, std::optional<bool> code)
{
	memoryRegionStorage.Update();
	std::vector<void*> pointers{};
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions(std::nullopt, code)) {
		for (void* ptr : convertedSignature.findAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			pointers.push_back(ptr);
		}
	}

	return { pointers, true };
}

BCRL::Session BCRL::Session::PointerList(std::vector<void*> pointers)
{
	memoryRegionStorage.Update();
	return { pointers, true };
}

BCRL::Session BCRL::Session::Pointer(void* pointer)
{
	memoryRegionStorage.Update();
	return { pointer, true };
}

BCRL::Session BCRL::Session::ArrayPointer(void* pointerArray, std::size_t index)
{
	memoryRegionStorage.Update();
	return { (*reinterpret_cast<void***>(pointerArray))[index], true };
}
