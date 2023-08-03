#include "BCRL.hpp"

BCRL::SafePointer BCRL::SafePointer::Invalidate() const
{
	SafePointer safePointer = { pointer, IsSafe() };
	safePointer.invalid = true;
	return safePointer;
}

BCRL::SafePointer BCRL::SafePointer::Add(std::size_t operand) const
{
	return { reinterpret_cast<std::uintptr_t>(pointer) + operand, IsSafe() };
}

BCRL::SafePointer BCRL::SafePointer::Sub(std::size_t operand) const
{
	return { reinterpret_cast<std::uintptr_t>(pointer) - operand, IsSafe() };
}

BCRL::SafePointer BCRL::SafePointer::Dereference() const
{
	std::optional<void*> deref = Read<void*>();
	if (deref.has_value())
		return { deref.value(), IsSafe() };

	return Invalidate();
}

bool BCRL::SafePointer::IsValid(std::size_t length) const
{
	if (invalid)
		return false; // It was already eliminated
	if (!safe)
		return true; // The user wants it this way
	const BCRL::MemoryRegionStorage::MemoryRegion* region = memoryRegionStorage.AddressRegion(pointer);
	for (std::size_t i = 0; i < length; i++) {
		void* pointer = Add(i).pointer;
		if (&region->addressSpace.front() <= pointer && pointer < &region->addressSpace.back())
			continue;
		region = memoryRegionStorage.AddressRegion(pointer);
		if (region == nullptr)
			return false;
	}
	return true;
}
