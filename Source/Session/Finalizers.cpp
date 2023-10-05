#include "BCRL.hpp"

#include <stdexcept>

using namespace BCRL;

std::vector<void*> Session::getPointers() const
{
	std::vector<void*> rawPointers{};
	for (SafePointer safePointer : pointers)
		rawPointers.push_back(safePointer.getPointer());
	return { rawPointers.begin(), rawPointers.end() };
}

std::optional<void*> Session::first(const std::function<bool(SafePointer)>& predicate) const
{
	for (SafePointer safePointer : this->pointers)
		if (predicate(safePointer))
			return safePointer.getPointer();

	return std::nullopt;
}

std::optional<void*> Session::getPointer() const
{
	if (size() == 1)
		return pointers.at(0).getPointer();

	return std::nullopt;
}

void* Session::expect(const std::string& message) const
{
	std::optional<void*> optional = getPointer();

	if (optional.has_value())
		return optional.value();

	throw std::runtime_error(message);
}