#include "BCRL.hpp"

#include <optional>

std::vector<void*> BCRL::Session::Pointers()
{
	std::vector<void*> pointers;
	for (BCRL::SafePointer safePointer : this->pointers)
		pointers.push_back(safePointer.GetPointer());
	return pointers;
}
std::optional<void*> BCRL::Session::Choose(std::function<bool(SafePointer)> predicate)
{
	for (BCRL::SafePointer safePointer : this->pointers)
		if (predicate(safePointer))
			return safePointer.GetPointer();

	return std::nullopt;
}
std::optional<void*> BCRL::Session::Pointer()
{
	if (this->Size() == 1)
		return pointers.at(0).GetPointer();

	return std::nullopt;
}
