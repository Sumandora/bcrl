#include "BCRL.hpp"

#include <ranges>

#include "SignatureScanner.hpp"

BCRL::SafePointer BCRL::SafePointer::PrevByteOccurence(const std::string& signature, std::optional<bool> code) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& memoryRegion : std::ranges::views::reverse(memoryRegionStorage.GetMemoryRegions(std::nullopt, code))) {
		if (&memoryRegion.addressSpace.front() > pointer)
			continue;

		void* hit = convertedSignature.FindPrev<void*>(std::min(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(&memoryRegion.addressSpace.back())), &memoryRegion.addressSpace.front());

		if (!hit)
			continue;

		return { hit, IsSafe() };
	}

	return Invalidate();
}

BCRL::SafePointer BCRL::SafePointer::NextByteOccurence(const std::string& signature, std::optional<bool> code) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions(std::nullopt, code)) {
		if (&fileMapping.addressSpace.back() < pointer)
			continue;

		void* hit = convertedSignature.FindNext<void*>(std::max(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(&fileMapping.addressSpace.front())), &fileMapping.addressSpace.back());

		if (!hit)
			continue;

		return { hit, IsSafe() };
	}

	return Invalidate();
}

bool BCRL::SafePointer::DoesMatch(const std::string& signature) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature };
	if (IsValid(convertedSignature.Length()))
		return convertedSignature.DoesMatch<void*>(pointer);
	return false;
}