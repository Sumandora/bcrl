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
		std::uintptr_t cPointer = i == 0 ? pointer : add(i).pointer;
		if (region.begin <= cPointer && cPointer < region.begin + region.length)
			continue;
		optRegion = memoryRegionStorage.addressRegion(cPointer);
		if (!optRegion.has_value())
			return false;
		region = optRegion->get();
	}
	return true;
}

SafePointer SafePointer::invalidate() const
{
	return SafePointer{ pointer, true };
}

SafePointer SafePointer::revalidate() const
{
	return SafePointer{ pointer, false };
}

SafePointer SafePointer::add(std::size_t operand) const
{
	return SafePointer{ reinterpret_cast<std::uintptr_t>(pointer) + operand, invalid };
}

SafePointer SafePointer::sub(std::size_t operand) const
{
	return SafePointer{ reinterpret_cast<std::uintptr_t>(pointer) - operand, invalid };
}

SafePointer SafePointer::dereference() const
{
	std::optional<std::uintptr_t> deref = read<std::uintptr_t>();
	if (deref.has_value())
		return SafePointer{ deref.value(), false };

	return invalidate();
}
