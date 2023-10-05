#include "BCRL.hpp"

#include <unordered_set>

using namespace BCRL;

Session Session::purgeInvalid(std::size_t length) const
{
	return map([length](SafePointer safePointer) -> std::optional<SafePointer> {
		if (safePointer.isValid(length))
			return safePointer;
		else
			return std::nullopt;
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

Session Session::filter(const std::function<bool(SafePointer)>& predicate) const
{
	return map([predicate](SafePointer safePointer) -> std::optional<SafePointer> {
		if (predicate(safePointer))
			return { safePointer };
		else
			return std::nullopt;
	});
}

Session Session::map(const std::function<std::optional<SafePointer>(SafePointer)>& transformer) const
{
	std::unordered_set<SafePointer, SafePointer::Hash> safePointerSet;
	for (SafePointer safePointer : pointers) {
		std::optional<SafePointer> newSafePointer = transformer(safePointer);
		if (!newSafePointer.has_value())
			continue; // User removed the pointer
		if (safePointerSet.contains(newSafePointer.value())) // Do this check before calling isValid unnecessarily as it is the most expensive operation here
			continue; // Duplicate - ignore it
		if (isSafe() && !newSafePointer->isValid())
			continue; // We are in safe mode and the pointer isn't valid, remove it

		safePointerSet.insert(newSafePointer.value());
	}
	return { std::vector<SafePointer>{ safePointerSet.begin(), safePointerSet.end() }, isSafe() };
}

Session Session::flatMap(const std::function<std::vector<SafePointer>(SafePointer)>& transformer) const
{
	std::unordered_set<SafePointer, SafePointer::Hash> safePointerSet;
	for (SafePointer safePointer : pointers) {
		std::vector<SafePointer> newSafePointers = transformer(safePointer);
		for (const SafePointer& newSafePointer : newSafePointers) {
			if (safePointerSet.contains(newSafePointer)) // Do this check before calling isValid unnecessarily as it is the most expensive operation here
				continue; // Duplicate - ignore it
			if (isSafe() && !newSafePointer.isValid())
				continue; // We are in safe mode and the pointer isn't valid, remove it

			safePointerSet.insert(newSafePointer);
		}
	}
	return { std::vector<SafePointer>{ safePointerSet.begin(), safePointerSet.end() }, isSafe() };
}
