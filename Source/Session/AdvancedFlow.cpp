#include "BCRL.hpp"

using namespace BCRL;

Session Session::purgeInvalid(std::size_t length)
{
	// TODO Purge duplicates
	return map([length](SafePointer safePointer) -> std::optional<SafePointer> {
		if (safePointer.isValid(length))
			return safePointer;
		return std::nullopt;
	},
		false); // Don't purge invalids after this map call, that would lead to a infinite loop
}

Session Session::forEach(std::function<void(SafePointer&)> action)
{
	return repeater([action](SafePointer& safePointer) {
		action(safePointer);
		return false;
	});
}

Session Session::repeater(std::function<bool(SafePointer&)> action)
{
	return map([action](SafePointer safePointer) {
		while (action(safePointer))
			;
		return safePointer;
	});
}

Session Session::repeater(std::size_t iterations, std::function<void(SafePointer&)> action)
{
	return map([iterations, action](SafePointer safePointer) {
		for (std::size_t i = 0; i < iterations; i++)
			action(safePointer);

		return safePointer;
	});
}

Session Session::filter(std::function<bool(SafePointer)> predicate)
{
	return map([predicate](SafePointer safePointer) -> std::optional<SafePointer> {
		if (predicate(safePointer))
			return std::optional<SafePointer>(safePointer);
		else
			return std::nullopt;
	});
}

Session Session::map(std::function<std::optional<SafePointer>(SafePointer)> transformer, bool purgeInvalid)
{
	std::vector<SafePointer> newPointers{};
	for (SafePointer safePointer : pointers) {
		std::optional<SafePointer> newSafePointer = transformer(safePointer);
		if (newSafePointer.has_value())
			newPointers.push_back(newSafePointer.value());
	}
	Session session{ newPointers, isSafe() };
	if (purgeInvalid)
		return session.purgeInvalid();
	return session;
}

Session Session::map(std::function<std::vector<SafePointer>(SafePointer)> transformer, bool purgeInvalid)
{
	std::vector<SafePointer> newPointers{};
	for (SafePointer safePointer : pointers) {
		std::vector<SafePointer> newSafePointers = transformer(safePointer);
		std::for_each(newSafePointers.begin(), newSafePointers.end(), [&newPointers](const SafePointer& safePointer) {
			newPointers.push_back(safePointer);
		});
	}
	Session session{ newPointers, isSafe() };
	if (purgeInvalid)
		return session.purgeInvalid();
	return session;
}
