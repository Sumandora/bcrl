#include "BCRL.hpp"

#include <stdexcept>

using namespace BCRL;

std::vector<void*> Session::getPointers()
{
	std::vector<void*> pointers{};
	for (SafePointer safePointer : this->pointers)
		pointers.push_back(safePointer.getPointer());
	return pointers;
}

std::optional<void*> Session::first(const std::function<bool(SafePointer)>& predicate)
{
	for (SafePointer safePointer : this->pointers)
		if (predicate(safePointer))
			return safePointer.getPointer();

	return std::nullopt;
}

std::optional<void*> Session::getPointer()
{
	if (size() == 1)
		return pointers.at(0).getPointer();

	return std::nullopt;
}

void* Session::expect(const std::string& message)
{
	std::optional<void*> optional = getPointer();

	if(optional.has_value())
		return optional.value();

	throw std::runtime_error(message);
}