#ifndef BCRL_X86_HPP
#define BCRL_X86_HPP

#include "BCRL.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include "ldisasm.h"

namespace BCRL {

	// Since there can be multiple xrefs, this returns multiple addresses
	template <bool Relative, bool Absolute, std::endian Endianness = std::endian::native>
	[[nodiscard]] auto findXREFs(const std::optional<std::string>& moduleName = std::nullopt)
	{
		return [moduleName](const SafePointer& safePointer) {
			std::vector<SafePointer> newPointers{};

			SignatureScanner::XRefSignature<Relative, Absolute, Endianness> signature(safePointer.getPointer());
			for (const auto& region : safePointer.getMemoryManager()->getLayout()) {
				if (!region.getFlags().isReadable() || !region.getFlags().isExecutable() || region.isSpecial())
					continue;

				if (!region.getName().has_value() || !moduleName.has_value() || !region.getName()->ends_with(moduleName.value()))
					continue;

				if(safePointer.getMemoryManager()->isRemoteAddressSpace()) {
					const auto& cache = region.cache();
					signature.all(cache->cbegin(), cache->cend(), detail::LambdaInserter<MemoryManager::CachedRegion::CacheIterator>([&](MemoryManager::CachedRegion::CacheIterator ptr) {
						newPointers.emplace_back(safePointer.getMemoryManager(), &*ptr);
					}));
				} else {
					signature.all(reinterpret_cast<std::byte*>(region.getBeginAddress()), reinterpret_cast<std::byte*>(region.getEndAddress()), detail::LambdaInserter<std::byte*>([&](std::byte* ptr) {
						newPointers.emplace_back(safePointer.getMemoryManager(), ptr);
					}));
				}
			}

			return newPointers;
		};
	}

	using namespace BCRL;

	constexpr bool is64Bit = sizeof(void*) == 8;
	using RelAddrType = std::conditional_t<is64Bit, int32_t, int16_t>;

	void relativeToAbsolute(SafePointer& safePointer)
	{
		std::optional<RelAddrType> offset = safePointer.template read<RelAddrType>();
		if (!offset.has_value()) {
			safePointer.invalidate();
			return;
		}
		safePointer.add(sizeof(RelAddrType));
		if(offset.value() < 0)
			safePointer.sub(-offset.value());
		else
			safePointer.add(offset.value());
	}

	constexpr std::size_t longestX86Insn = 15;

	void nextInstruction(SafePointer& safePointer)
	{
		if (safePointer.isValid(longestX86Insn)) {
			std::array<std::byte, longestX86Insn> bytes{};
			if(!safePointer.read(&bytes, longestX86Insn))
				safePointer.invalidate();
			else
				safePointer.add(ldisasm(&bytes, is64Bit));
		} else
			safePointer.invalidate();
	}


}

#endif
