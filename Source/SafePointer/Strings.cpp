#include "BCRL.hpp"

#include <ranges>

#include "SignatureScanner.hpp"

using namespace BCRL;

SafePointer& SafePointer::prevStringOccurrence(const std::string& string, std::optional<char> wildcard)
{
	SignatureScanner::StringSignature signature{ string, wildcard };

	for (const auto& [begin, region] : std::ranges::reverse_view(memoryRegionStorage.getMemoryRegions())) {
		if (begin > pointer)
			continue;

		if(region.executable)
			continue; // Strings are not in executable regions

		auto hit = signature.findPrev(std::min(pointer, begin + region.length), { begin });

		if (!hit.has_value())
			continue;

		pointer = hit.value();
		return revalidate();
	}

	return invalidate();
}

SafePointer& SafePointer::nextStringOccurrence(const std::string& string, std::optional<char> wildcard)
{
	SignatureScanner::StringSignature signature{ string, wildcard };

	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if (begin + region.length < pointer)
			continue;

		if(region.executable)
			continue; // Strings are not in executable regions

		auto hit = signature.findNext(std::max(pointer, begin), { begin + region.length });

		if (!hit.has_value())
			continue;

		pointer = hit.value();
		return revalidate();
	}

	return invalidate();
}
