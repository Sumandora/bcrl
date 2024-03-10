#include "BCRL.hpp"

#include <unordered_set>

using namespace BCRL;

Session& Session::purgeInvalid(std::size_t length)
{
	return forEach([length](SafePointer& safePointer) {
		if (!safePointer.isValid(length))
			safePointer.invalidate();
	});
}

Session& Session::forEach(const std::function<void(SafePointer&)>& body)
{
	// This looks a bit scuffed, but I'm pretty sure it is the most memory-efficient way of doing it
	auto it = pointers.begin();
	while (it != pointers.end()) {
		SafePointer& safePointer = *it;
		body(safePointer);
		if (isSafe() && !safePointer.isValid())
			it = pointers.erase(it); // We are in safe mode and the pointer isn't valid, remove it
		else
			it++;
	}
	return *this;
}

Session& Session::repeater(const std::function<bool(SafePointer&)>& action)
{
	return forEach([action](SafePointer& safePointer) {
		while (action(safePointer))
			;
	});
}

Session& Session::repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action)
{
	return forEach([iterations, action](SafePointer& safePointer) {
		for (std::size_t i = 0; i < iterations; i++)
			action(safePointer);
	});
}

Session& Session::filter(const std::function<bool(const SafePointer&)>& predicate)
{
	return forEach([predicate](SafePointer& safePointer) {
		if (!predicate(safePointer))
			safePointer.invalidate();
	});
}

Session& Session::flatMap(const std::function<std::vector<SafePointer>(const SafePointer&)>& transformer)
{
	std::vector<SafePointer> newSafePointers;
	for (SafePointer& safePointer : pointers) {
		auto transformed = transformer(safePointer);
		for(SafePointer& newSafePointer : transformed) {
			if(isSafe() && !newSafePointer.isValid())
				continue;

			newSafePointers.emplace_back(newSafePointer);
		}
	}
	pointers = newSafePointers;
	return *this;
}
