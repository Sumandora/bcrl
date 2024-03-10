#include "BCRL.hpp"

#include <limits>

#include "SignatureScanner.hpp"

using namespace BCRL;

Session Session::module(const std::string& moduleName)
{
	memoryRegionStorage.update();
	std::uintptr_t lowest = 0;
	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions())
		if(region.name.has_value() && region.name->ends_with(moduleName))
			if(lowest == 0 || lowest > begin)
				lowest = begin;
	if (lowest == 0)
		return Session{ true };
	return { lowest, true };
}

Session Session::string(const std::string& string, std::optional<char> wildcard)
{
	memoryRegionStorage.update();
	std::vector<std::uintptr_t> pointers{};
	SignatureScanner::StringSignature signature{ string, wildcard };

	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if(region.executable) continue; // Strings are not in executable regions

		for (std::uintptr_t ptr : signature.findAll(begin, begin + region.length)) {
			pointers.push_back(ptr);
		}
	}

	return { pointers, true };
}

Session Session::signature(const std::string& signature, char wildcard, std::optional<bool> code)
{
	memoryRegionStorage.update();
	std::vector<std::uintptr_t> pointers{};
	SignatureScanner::ByteSignature convertedSignature{ signature, wildcard };

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

Session Session::pointerArray(void* pointerArray, std::size_t index)
{
	memoryRegionStorage.update();
	return { std::initializer_list<SafePointer>{ SafePointer(pointerArray).dereference().add(index * sizeof(void*)).dereference() }, true };
}
