#include "BCRL.hpp"

#include <ranges>

#include "SignatureScanner.hpp"

using namespace BCRL;

SafePointer& SafePointer::prevByteOccurrence(const std::string& signature, char wildcard, std::optional<bool> code)
{
	SignatureScanner::ByteSignature convertedSignature{ signature, wildcard };

	for (const auto& [begin, region] : std::ranges::reverse_view(memoryRegionStorage.getMemoryRegions())) {
		if (begin > pointer)
			continue;

		if (code.has_value() && region.executable != code.value())
			continue;

		auto hit = convertedSignature.findPrev(std::min(pointer, begin + region.length), { begin });

		if (!hit.has_value())
			continue;

		pointer = hit.value();
		return revalidate();
	}

	return invalidate();
}

SafePointer& SafePointer::nextByteOccurrence(const std::string& signature, char wildcard, std::optional<bool> code)
{
	SignatureScanner::ByteSignature convertedSignature{ signature, wildcard };

	for (const auto& [begin, region] : memoryRegionStorage.getMemoryRegions()) {
		if (begin + region.length < pointer)
			continue;

		if (code.has_value() && region.executable != code.value())
			continue;

		auto hit = convertedSignature.findNext(std::max(pointer, begin), { begin + region.length });

		if (!hit.has_value())
			continue;

		pointer = hit.value();
		return revalidate();
	}

	return invalidate();
}

bool SafePointer::doesMatch(const std::string& signature, char wildcard) const
{
	SignatureScanner::ByteSignature convertedSignature{ signature, wildcard };
	if (isValid(convertedSignature.length()))
		return convertedSignature.doesMatch(pointer);
	return false;
}
