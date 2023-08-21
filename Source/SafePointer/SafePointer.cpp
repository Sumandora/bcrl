#include "BCRL.hpp"

using namespace BCRL;

bool SafePointer::isValid(std::size_t length) const
{
	if (invalid)
		return false; // It was already eliminated
	if (!safe)
		return true; // The user wants it this way
	const MemoryRegionStorage::MemoryRegion* region = memoryRegionStorage.addressRegion(pointer);
	for (std::size_t i = 0; i < length; i++) {
		void* pointer = add(i).pointer;
		if (&region->addressSpace.front() <= pointer && pointer < &region->addressSpace.back())
			continue;
		region = memoryRegionStorage.addressRegion(pointer);
		if (region == nullptr)
			return false;
	}
	return true;
}

SafePointer SafePointer::invalidate() const
{
	SafePointer safePointer = { pointer, isSafe() };
	safePointer.invalid = true;
	return safePointer;
}

SafePointer SafePointer::add(std::size_t operand) const
{
	return { reinterpret_cast<std::uintptr_t>(pointer) + operand, isSafe() };
}

SafePointer SafePointer::sub(std::size_t operand) const
{
	return { reinterpret_cast<std::uintptr_t>(pointer) - operand, isSafe() };
}

SafePointer SafePointer::dereference() const
{
	std::optional<void*> deref = read<void*>();
	if (deref.has_value())
		return { deref.value(), isSafe() };

	return invalidate();
}
