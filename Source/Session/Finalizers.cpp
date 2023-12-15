#include "BCRL.hpp"

#include <stdexcept>

using namespace BCRL;

std::size_t Session::size() const
{
	return pointers.size();
}

std::vector<void*> Session::getPointers() const
{
	std::vector<void*> rawPointers{};
	for (SafePointer safePointer : pointers)
		rawPointers.push_back(reinterpret_cast<void*>(safePointer.getPointer()));
	return rawPointers;
}

std::optional<void*> Session::getPointer() const
{
	if (size() == 1)
		return reinterpret_cast<void*>(pointers.begin()->getPointer());

	return std::nullopt;
}

void* Session::expect(const std::string& message) const
{
	std::optional<void*> optional = getPointer();

	if (optional.has_value())
		return optional.value();

	throw std::runtime_error(message);
}