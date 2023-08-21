#include "BCRL.hpp"

#include "SignatureScanner.hpp"

using namespace BCRL;

#if defined(__x86_64) || defined(i386)

SafePointer SafePointer::relativeToAbsolute() const
{
#ifdef __x86_64
	std::optional<int32_t> offset = read<int32_t>();
	if (!offset.has_value())
		return invalidate();
	return add(sizeof(int32_t)).add(offset.value());
#else
	std::optional<int16_t> offset = read<int16_t>();
	if (!offset.has_value())
		return invalidate();
	return add(sizeof(int16_t)).add(offset.value());
#endif
}

#ifndef BCLR_DISABLE_LDE

#include "ldisasm.h"

constexpr std::size_t longestX86Insn = 15;

SafePointer SafePointer::prevInstruction() const
{
	// What I am doing here has no scientific backing, it just happens to work **most** of the time.
	for (std::size_t offset = longestX86Insn * 2 /* Ensure we will pass a few instructions */; offset > 0; offset--) {
		// The longer this for goes on, the worse/inaccurate the results will get
		SafePointer addr = this->sub(offset);
		std::size_t insnLength; // The last disassembled instruction
		while (addr.pointer < this && isValid(longestX86Insn))
			addr = addr.add(insnLength = ldisasm(pointer, sizeof(void*) == 8));
		if ((*this == addr) == 0) {
			// Apparently we found a point where instructions will end up exactly hitting
			// our function, this seems good. This does not ensure correctness.
			return sub(insnLength);
		}
	}

	return invalidate();
}

SafePointer SafePointer::nextInstruction() const
{
	if (isValid(longestX86Insn))
		return add(ldisasm(pointer, sizeof(void*) == 8));
	else
		return invalidate();
}
#endif

std::vector<SafePointer> SafePointer::findXREFs(bool relative, bool absolute) const
{
	std::vector<SafePointer> newPointers{};

	SignatureScanner::XRefSignature signature(this->pointer);
	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.getMemoryRegions(std::nullopt, true)) {
		for (void* ptr : signature.findAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			newPointers.push_back(SafePointer{ ptr, isSafe() });
		}
	}

	return newPointers;
}

std::vector<SafePointer> SafePointer::findXREFs(const std::string& moduleName, bool relative, bool absolute) const
{
	std::vector<SafePointer> newPointers{};

	SignatureScanner::XRefSignature signature(this->pointer);
	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.getMemoryRegions(std::nullopt, true, moduleName)) {
		for (void* ptr : signature.findAll<void*>(&fileMapping.addressSpace.front(), &fileMapping.addressSpace.back())) {
			newPointers.push_back(SafePointer{ ptr, isSafe() });
		}
	}

	return newPointers;
}

#endif