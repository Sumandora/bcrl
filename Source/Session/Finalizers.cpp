#include "BCRL.hpp"

std::vector<void*> BCRL::Session::getPointers()
{
	std::vector<void*> pointers;
	for (BCRL::SafePointer safePointer : this->pointers)
		pointers.push_back(safePointer.getPointer());
	return pointers;
}
std::optional<void*> BCRL::Session::choose(std::function<bool(SafePointer)> predicate)
{
	for (BCRL::SafePointer safePointer : this->pointers)
		if (predicate(safePointer))
			return safePointer.getPointer();

	return std::nullopt;
}
std::optional<void*> BCRL::Session::getPointer()
{
	if (size() == 1)
		return pointers.at(0).getPointer();

	return std::nullopt;
}
