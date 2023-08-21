#include "BCRL.hpp"

#include <ranges>

#include "SignatureScanner.hpp"

BCRL::SafePointer BCRL::SafePointer::PrevStringOccurence(const std::string& string, std::optional<bool> code) const
{
	SignatureScanner::StringSignature signature{ string };

	for (const MemoryRegionStorage::MemoryRegion& memoryRegion : std::ranges::views::reverse(memoryRegionStorage.GetMemoryRegions(std::nullopt, code))) {
		if (&memoryRegion.addressSpace.front() > pointer)
			continue;

		void* hit = signature.findPrev<void*>(std::min(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(&memoryRegion.addressSpace.back())), &memoryRegion.addressSpace.front());

		if (!hit)
			continue;

		return { hit, IsSafe() };
	}

	return Invalidate();
}

BCRL::SafePointer BCRL::SafePointer::NextStringOccurence(const std::string& string, std::optional<bool> code) const
{
	SignatureScanner::StringSignature signature{ string };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions(std::nullopt, code)) {
		if (&fileMapping.addressSpace.back() < pointer)
			continue;

		void* hit = signature.findNext<void*>(std::max(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(&fileMapping.addressSpace.front())), &fileMapping.addressSpace.back());

		if (!hit)
			continue;

		return { hit, IsSafe() };
	}

	return Invalidate();
}
