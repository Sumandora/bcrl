#include "BCRL.hpp"

#include <unordered_set>

using namespace BCRL;

Session Session::purgeInvalid(std::size_t length) const
{
	return map([length](const SafePointer& safePointer) {
		if (safePointer.isValid(length))
			return safePointer;
		return safePointer.invalidate();
	});
}

Session Session::forEach(const std::function<void(SafePointer&)>& action) const
{
	return repeater([action](SafePointer& safePointer) {
		action(safePointer);
		return false;
	});
}

Session Session::repeater(const std::function<bool(SafePointer&)>& action) const
{
	return map([action](SafePointer safePointer) {
		while (action(safePointer))
			;
		return safePointer;
	});
}

Session Session::repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action) const
{
	return map([iterations, action](SafePointer safePointer) {
		for (std::size_t i = 0; i < iterations; i++)
			action(safePointer);
		return safePointer;
	});
}

Session Session::filter(const std::function<bool(const SafePointer&)>& predicate) const
{
	return map([predicate](const SafePointer& safePointer) {
		if (predicate(safePointer))
			return safePointer;
		return safePointer.invalidate();
	});
}

Session Session::map(const std::function<SafePointer(const SafePointer&)>& transformer) const
{
	std::unordered_set<SafePointer, SafePointer::Hash> safePointerSet;
	for (SafePointer safePointer : pointers) {
		SafePointer newSafePointer = transformer(safePointer);
		if (isSafe() && !newSafePointer.isValid())
			continue; // We are in safe mode and the pointer isn't valid, remove it

		safePointerSet.insert(newSafePointer);
	}
	return { safePointerSet, isSafe() };
}

Session Session::flatMap(const std::function<std::vector<SafePointer>(const SafePointer&)>& transformer) const
{
	std::unordered_set<SafePointer, SafePointer::Hash> safePointerSet;
	for (SafePointer safePointer : pointers) {
		std::vector<SafePointer> newSafePointers = transformer(safePointer);
		for (const SafePointer& newSafePointer : newSafePointers) {
			if (isSafe() && !newSafePointer.isValid())
				continue; // We are in safe mode and the pointer isn't valid, remove it

			safePointerSet.insert(newSafePointer);
		}
	}
	return { safePointerSet, isSafe() };
}
