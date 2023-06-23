#include "BCRL.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "SignatureScanner.hpp"

BCRL::SafePointer BCRL::SafePointer::PrevOccurence(const std::string& signature) const
{
	SignatureScanner::Signature convertedSignature{ signature };

	const MemoryRegionStorage::MemoryRegion* memoryRegion = memoryRegionStorage.AddressRegion(pointer);
	if (!memoryRegion)
		return Invalidate();

	void* hit = convertedSignature.FindLastOccurrence(
		reinterpret_cast<void*>(std::min(
			reinterpret_cast<std::uintptr_t>(&memoryRegion->addressSpace.back()),
			reinterpret_cast<std::uintptr_t>(pointer))),
		&memoryRegion->addressSpace.front());

	if (!hit)
		return Invalidate();

	return { hit, IsSafe() };
}

BCRL::SafePointer BCRL::SafePointer::NextOccurence(const std::string& signature) const
{
	SignatureScanner::Signature convertedSignature{ signature };

	const MemoryRegionStorage::MemoryRegion* memoryRegion = memoryRegionStorage.AddressRegion(pointer);
	if (!memoryRegion)
		return Invalidate();

	void* hit = convertedSignature.FindNextOccurrence(
		reinterpret_cast<void*>(std::max(
			reinterpret_cast<std::uintptr_t>(&memoryRegion->addressSpace.front()),
			reinterpret_cast<std::uintptr_t>(pointer))),
		&memoryRegion->addressSpace.back() - convertedSignature.Size());

	if (!hit)
		return Invalidate();

	return { hit, IsSafe() };
}

bool BCRL::SafePointer::DoesMatch(const std::string& signature) const
{
	return SignatureScanner::Signature(signature).DoesMatch(pointer);
}