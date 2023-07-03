#include "BCRL.hpp"

#include "SignatureScanner.hpp"

#if defined(__x86_64) || defined(i386)

BCRL::SafePointer BCRL::SafePointer::RelativeToAbsolute() const
{
#ifdef __x86_64
	std::optional<int32_t> offset = Read<int32_t>();
	if (!offset.has_value())
		return Invalidate();
	return Add(sizeof(int32_t)).Add(offset.value());
#else
	std::optional<int16_t> offset = Read<int16_t>();
	if (!offset.has_value())
		return Invalidate();
	return Add(sizeof(int16_t)).Add(offset.value());
#endif
}

#ifndef BCLR_DISABLE_LDE

#include "ldisasm.h"

constexpr std::size_t longestX86Insn = 15;

BCRL::SafePointer BCRL::SafePointer::PrevInstruction() const
{
	// What I am doing here has no scientific backing, it just happens to work **most** of the time.
	for (std::size_t offset = longestX86Insn * 2 /* Ensure we will pass a few instructions */; offset > 0; offset--) {
		// The longer this for goes on, the worse/inaccurate the results will get
		SafePointer addr = this->Sub(offset);
		std::size_t insnLength; // The last disassembled instruction
		while (addr.pointer < this && IsValid(longestX86Insn))
			addr = addr.Add(insnLength = ldisasm(pointer, sizeof(void*) == 8));
		if ((*this == addr) == 0) {
			// Apparently we found a point where instructions will end up exactly hitting
			// our function, this seems good. This does not ensure correctness.
			return Sub(insnLength);
		}
	}

	return Invalidate();
}

BCRL::SafePointer BCRL::SafePointer::NextInstruction() const
{
	if (IsValid(longestX86Insn))
		return Add(ldisasm(pointer, sizeof(void*) == 8));
	else
		return Invalidate();
}
#endif

std::vector<BCRL::SafePointer> BCRL::SafePointer::FindXREFs(bool relative, bool absolute) const
{
	std::vector<BCRL::SafePointer> newPointers{};

	SignatureScanner::XRefSignature signature(this->pointer);
	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions(std::nullopt, true)) {
		for (void* ptr : signature.FindAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			newPointers.push_back(SafePointer{ ptr, IsSafe() });
		}
	}

	return newPointers;
}

std::vector<BCRL::SafePointer> BCRL::SafePointer::FindXREFs(const std::string& moduleName, bool relative, bool absolute) const
{
	std::vector<BCRL::SafePointer> newPointers{};

	SignatureScanner::XRefSignature signature(this->pointer);
	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions(std::nullopt, true, moduleName)) {
		for (void* ptr : signature.FindAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			newPointers.push_back(SafePointer{ ptr, IsSafe() });
		}
	}

	return newPointers;
}

#endif