#include "BCRL.hpp"

BCRL::Session BCRL::Session::purgeInvalid(std::size_t length)
{
	// TODO Purge duplicates
	return map([length](SafePointer safePointer) -> std::optional<BCRL::SafePointer> {
		if (safePointer.isValid(length))
			return safePointer;
		return std::nullopt;
	},
		false); // Don't purge invalids after this map call, that would lead to a infinite loop
}

BCRL::Session BCRL::Session::forEach(std::function<void(BCRL::SafePointer&)> action)
{
	return repeater([action](SafePointer& safePointer) {
		action(safePointer);
		return false;
	});
}

BCRL::Session BCRL::Session::repeater(std::function<bool(SafePointer&)> action)
{
	return map([action](SafePointer safePointer) {
		while (action(safePointer))
			;
		return safePointer;
	});
}

BCRL::Session BCRL::Session::repeater(std::size_t iterations, std::function<void(SafePointer&)> action)
{
	return map([iterations, action](SafePointer safePointer) {
		for (std::size_t i = 0; i < iterations; i++)
			action(safePointer);

		return safePointer;
	});
}

BCRL::Session BCRL::Session::filter(std::function<bool(BCRL::SafePointer)> predicate)
{
	return map([predicate](SafePointer safePointer) -> std::optional<BCRL::SafePointer> {
		if (predicate(safePointer))
			return std::optional<SafePointer>(safePointer);
		else
			return std::nullopt;
	});
}

BCRL::Session BCRL::Session::map(std::function<std::optional<BCRL::SafePointer>(BCRL::SafePointer)> transformer, bool purgeInvalid)
{
	std::vector<BCRL::SafePointer> newPointers{};
	for (BCRL::SafePointer safePointer : pointers) {
		std::optional<BCRL::SafePointer> newSafePointer = transformer(safePointer);
		if (newSafePointer.has_value())
			newPointers.push_back(newSafePointer.value());
	}
	Session session{ newPointers, isSafe() };
	if (purgeInvalid)
		return session.purgeInvalid();
	return session;
}

BCRL::Session BCRL::Session::map(std::function<std::vector<BCRL::SafePointer>(BCRL::SafePointer)> transformer, bool purgeInvalid)
{
	std::vector<BCRL::SafePointer> newPointers{};
	for (BCRL::SafePointer safePointer : pointers) {
		std::vector<BCRL::SafePointer> newSafePointers = transformer(safePointer);
		std::for_each(newSafePointers.begin(), newSafePointers.end(), [&newPointers](const SafePointer& safePointer) {
			newPointers.push_back(safePointer);
		});
	}
	Session session{ newPointers, isSafe() };
	if (purgeInvalid)
		return session.purgeInvalid();
	return session;
}
