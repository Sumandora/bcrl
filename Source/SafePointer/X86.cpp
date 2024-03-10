#include "BCRL.hpp"

#include "SignatureScanner.hpp"

using namespace BCRL;

#if defined(__x86_64) || defined(i386)

constexpr bool is64Bit = sizeof(void*) == 8;
using RelAddrType = std::conditional_t<is64Bit, int32_t, int16_t>;

SafePointer& SafePointer::relativeToAbsolute()
{
	std::optional<RelAddrType> offset = read<RelAddrType>();
	if (!offset.has_value())
		return invalidate();
	auto& s = add(sizeof(RelAddrType));
	if(offset.value() < 0)
		s.sub(-offset.value());
	else
		s.add(offset.value());
	return s;
}

#ifndef BCLR_DISABLE_LDE

#include "ldisasm.h"

constexpr std::size_t longestX86Insn = 15;

SafePointer& SafePointer::prevInstruction()
{
	// What I am doing here has no scientific backing, it just happens to work **most** of the time.
	for (std::size_t offset = longestX86Insn * 2 /* Ensure we will pass a few instructions */; offset > 0; offset--) {
		// The longer this for goes on, the worse/inaccurate the results will get
		SafePointer& addr = this->sub(offset);
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

SafePointer& SafePointer::nextInstruction()
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