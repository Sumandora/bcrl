#include "BCRL.hpp"

using namespace BCRL;

bool SafePointer::isValid(std::size_t length) const
{
	if (invalid)
		return false; // It was already eliminated
	const MemoryRegionStorage::MemoryRegion* region = memoryRegionStorage.addressRegion(pointer);
	if (region == nullptr)
		return false;
	for (std::size_t i = 0; i < length; i++) {
		void* cPointer = i == 0 ? pointer : add(i).pointer;
		if (&region->addressSpace.front() <= cPointer && cPointer < &region->addressSpace.back())
			continue;
		region = memoryRegionStorage.addressRegion(cPointer);
		if (region == nullptr)
			return false;
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
	std::optional<void*> deref = read<void*>();
	if (deref.has_value())
		return SafePointer{ deref.value(), false };

	return invalidate();
}
