#include "BCRL.hpp"

#include <ranges>

#include "SignatureScanner.hpp"

using namespace BCRL;

SafePointer SafePointer::prevStringOccurrence(const std::string& string, std::optional<bool> code) const
{
	SignatureScanner::StringSignature signature{ string };

	for (const auto& [begin, region] : std::ranges::reverse_view(memoryRegionStorage.getMemoryRegions())) {
		if (begin > pointer)
			continue;

		if(code.has_value() && region.executable != code.value())
			continue;

		auto hit = signature.findPrev(std::min(pointer, begin + region.length), { begin });

		if (!hit.has_value())
			continue;

		return SafePointer{ hit.value(), false };
	}

	return invalidate();
}

SafePointer SafePointer::nextStringOccurrence(const std::string& string, std::optional<bool> code) const
{
	SignatureScanner::StringSignature signature{ string };

	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if (begin + region.length < pointer)
			continue;

		if(code.has_value() && region.executable != code.value())
			continue;

		auto hit = signature.findNext(std::max(pointer, begin), { begin + region.length });

		if (!hit.has_value())
			continue;

		return SafePointer{ hit.value(), false };
	}

	return invalidate();
}
