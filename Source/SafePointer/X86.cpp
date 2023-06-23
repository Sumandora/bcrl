#include "BCRL.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

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

std::vector<BCRL::SafePointer> BCRL::SafePointer::FindXREFs(const BCRL::XREFTypes& types) const
{
	std::vector<BCRL::SafePointer> newPointers{};

	for (const MemoryRegionStorage::MemoryRegion& fileMapping : memoryRegionStorage.GetMemoryRegions(std::nullopt, true)) {
		std::uintptr_t back = reinterpret_cast<std::uintptr_t>(&fileMapping.addressSpace.back());
		for (std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(&fileMapping.addressSpace.front()); addr < back; addr++) {
			std::size_t distance = std::abs(reinterpret_cast<char*>(addr) - reinterpret_cast<char*>(pointer));
#ifdef __x86_64
			bool in32bit = distance < INT32_MAX && back - addr > sizeof(int32_t);
			if (types.search32bit && in32bit && reinterpret_cast<std::uintptr_t>(addr + sizeof(int32_t) + *reinterpret_cast<int32_t*>(addr)) == reinterpret_cast<std::uintptr_t>(this->pointer)) {
				newPointers.push_back({ addr, IsSafe() });
				continue;
			}
			// When addressing in 64 bit there is no reason for a relative address
			if (types.search64bit && *reinterpret_cast<std::uintptr_t*>(addr) == reinterpret_cast<std::uintptr_t>(this->pointer)) {
				newPointers.push_back({ addr, IsSafe() });
				continue;
			}
#else
			bool in16bit = distance < INT16_MAX && back - addr > sizeof(int16_t);
			if (types.search16bit && in16bit && reinterpret_cast<std::uintptr_t>(addr + sizeof(int16_t) + *reinterpret_cast<int16_t*>(addr)) == reinterpret_cast<std::uintptr_t>(this->pointer)) {
				newPointers.push_back({ addr, IsSafe() });
				continue;
			}
			// When addressing in 32 bit there is no reason for a relative address
			if (types.search32bit && *reinterpret_cast<std::uintptr_t*>(addr) == reinterpret_cast<std::uintptr_t>(this->pointer)) {
				newPointers.push_back({ addr, IsSafe() });
				continue;
			}
#endif
		}
	}

	return newPointers;
}

#endif