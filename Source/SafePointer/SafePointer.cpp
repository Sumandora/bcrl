#include "BCRL.hpp"

using namespace BCRL;

bool SafePointer::isValid(std::size_t length) const
{
	if (invalid)
		return false; // It was already eliminated

	auto optRegion = memoryRegionStorage.addressRegion(pointer);
	if (!optRegion.has_value())
		return false;
	auto region = optRegion->get();
	for (std::size_t i = 0; i < length; i++) {
		std::uintptr_t cPointer = pointer + i;
		if (cPointer >= region.begin && cPointer < region.begin + region.length)
			continue;
		optRegion = memoryRegionStorage.addressRegion(cPointer);
		if (!optRegion.has_value())
			return false;
		region = optRegion->get();
	}
	return true;
}

SafePointer& SafePointer::invalidate()
{
	invalid = true;
	return *this;
}

SafePointer& SafePointer::revalidate()
{
	invalid = false;
	return *this;
}

SafePointer& SafePointer::add(std::size_t operand)
{
	pointer += operand;
	return *this;
}

SafePointer& SafePointer::sub(std::size_t operand)
{
	pointer -= operand;
	return *this;
}

SafePointer& SafePointer::dereference()
{
	std::optional<std::uintptr_t> deref = read<std::uintptr_t>();
	if (deref.has_value()) {
		pointer = deref.value();
		return revalidate();
	} else
		return invalidate();
}
