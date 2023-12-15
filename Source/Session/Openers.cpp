#include "BCRL.hpp"

#include <limits>

#include "SignatureScanner.hpp"

using namespace BCRL;

Session Session::module(const char* moduleName)
{
	memoryRegionStorage.update();
	constexpr auto lowestDef = std::numeric_limits<std::uintptr_t>::max();
	std::uintptr_t lowest = lowestDef;
	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions())
		if(region.name.has_value() && region.name->ends_with(moduleName))
			if(lowest == lowestDef || lowest > begin)
				lowest = begin;
	if (lowest == lowestDef)
		return Session{ true };
	return { lowest, true };
}

Session Session::string(const char* string)
{
	memoryRegionStorage.update();
	std::vector<std::uintptr_t> pointers{};
	SignatureScanner::StringSignature signature{ string };

	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if(region.executable) continue; // Strings are not in executable regions

		for (std::uintptr_t ptr : signature.findAll(begin, begin + region.length)) {
			pointers.push_back(ptr);
		}
	}

	return { pointers, true };
}

Session Session::signature(const char* signature, std::optional<bool> code)
{
	memoryRegionStorage.update();
	std::vector<std::uintptr_t> pointers{};
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if(code.has_value() && region.executable != code)
			continue;

		for (std::uintptr_t ptr : convertedSignature.findAll(begin, begin + region.length)) {
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
	return { reinterpret_cast<std::uintptr_t>(pointer), true };
}

Session Session::arrayPointer(void* pointerArray, std::size_t index)
{
	memoryRegionStorage.update();
	return { { SafePointer(pointerArray).dereference().add(index * sizeof(void*)).dereference() }, true };
}
