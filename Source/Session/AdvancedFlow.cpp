#include "BCRL.hpp"

#include <unordered_set>

using namespace BCRL;

// We don't use filter for these two, because we need to prevent the infinite loop

Session Session::purgeInvalid(std::size_t length)
{
	return map([length](SafePointer safePointer) -> std::optional<SafePointer> {
		if (safePointer.isValid(length))
			return safePointer;
		else
			return std::nullopt;
	}); // Don't purge invalids after this map call, that would lead to a infinite loop
}

Session Session::forEach(const std::function<void(SafePointer&)>& action)
{
	return repeater([action](SafePointer& safePointer) {
		action(safePointer);
		return false;
	});
}

Session Session::repeater(const std::function<bool(SafePointer&)>& action)
{
	return map([action](SafePointer safePointer) {
		while (action(safePointer))
			;
		return safePointer;
	});
}

Session Session::repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action)
{
	return map([iterations, action](SafePointer safePointer) {
		for (std::size_t i = 0; i < iterations; i++)
			action(safePointer);

		return safePointer;
	});
}

Session Session::filter(const std::function<bool(SafePointer)>& predicate)
{
	return map([predicate](SafePointer safePointer) -> std::optional<SafePointer> {
		if (predicate(safePointer))
			return { safePointer };
		else
			return std::nullopt;
	});
}

Session Session::map(const std::function<std::optional<SafePointer>(SafePointer)>& transformer)
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

Session Session::flatMap(const std::function<std::vector<SafePointer>(SafePointer)>& transformer)
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
