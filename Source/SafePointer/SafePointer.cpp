#include "BCRL.hpp"

#include <cstdint>
#include <optional>

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