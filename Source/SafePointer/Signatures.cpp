#include "BCRL.hpp"

#include <ranges>

#include "SignatureScanner.hpp"

using namespace BCRL;

SafePointer SafePointer::prevByteOccurrence(const std::string& signature, std::optional<bool> code) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& memoryRegion : std::ranges::views::reverse(memoryRegionStorage.getMemoryRegions(std::nullopt, code))) {
		if (&memoryRegion.addressSpace.front() > pointer)
			continue;

		void* hit = convertedSignature.findPrev<void*>(std::min(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(&memoryRegion.addressSpace.back())), &memoryRegion.addressSpace.front());

		if (!hit)
			continue;

		return SafePointer{ hit, false };
	}

	return invalidate();
}

SafePointer SafePointer::nextByteOccurrence(const std::string& signature, std::optional<bool> code) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature };

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.getMemoryRegions(std::nullopt, code)) {
		if (&fileMapping.addressSpace.back() < pointer)
			continue;

		void* hit = convertedSignature.findNext<void*>(std::max(reinterpret_cast<char*>(pointer), reinterpret_cast<char*>(&fileMapping.addressSpace.front())), &fileMapping.addressSpace.back());

		if (!hit)
			continue;

		return SafePointer{ hit, false };
	}

	return invalidate();
}

bool SafePointer::doesMatch(const std::string& signature) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature };
	if (isValid(convertedSignature.length()))
		return convertedSignature.doesMatch<void*>(pointer);
	return false;
}