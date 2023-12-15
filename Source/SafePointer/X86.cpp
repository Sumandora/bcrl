#include "BCRL.hpp"

#include "SignatureScanner.hpp"

using namespace BCRL;

#if defined(__x86_64) || defined(i386)

constexpr bool is64Bit = sizeof(void*) == 8;

SafePointer SafePointer::relativeToAbsolute() const
{
#ifdef __x86_64
	using RelAddrType = int32_t;
#else
	using RelAddrType = int16_t;
#endif
	std::optional<RelAddrType> offset = read<RelAddrType>();
	if (!offset.has_value())
		return invalidate();
	return add(sizeof(RelAddrType)).add(offset.value());
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
		while (addr < *this && isValid(longestX86Insn))
			addr = addr.add(insnLength = ldisasm(reinterpret_cast<const void*>(pointer), is64Bit));
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
		return add(ldisasm(reinterpret_cast<const void*>(pointer), is64Bit));
	else
		return invalidate();
}
#endif

std::vector<SafePointer> SafePointer::findXREFs(bool relative, bool absolute) const
{
	std::vector<SafePointer> newPointers{};

	SignatureScanner::XRefSignature signature(this->pointer, relative, absolute);
	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if(!region.executable)
			continue;

		for (std::uintptr_t ptr : signature.findAll(begin, begin + region.length)) {
			newPointers.emplace_back(ptr, false);
		}
	}

	return newPointers;
}

std::vector<SafePointer> SafePointer::findXREFs(const std::string& moduleName, bool relative, bool absolute) const
{
	std::vector<SafePointer> newPointers{};

	SignatureScanner::XRefSignature signature(this->pointer, relative, absolute);
	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if(!region.executable)
			continue;

		if(!region.name.has_value() || !region.name->ends_with(moduleName))
			continue;

		for (std::uintptr_t ptr : signature.findAll(begin, begin + region.length)) {
			newPointers.emplace_back(ptr, false);
		}
	}

	return newPointers;
}

#endif