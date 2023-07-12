#include "BCRL.hpp"

BCRL::Session BCRL::Session::PurgeInvalid(std::size_t length)
{
	// TODO Purge duplicates
	return Map([length](SafePointer safePointer) -> std::optional<BCRL::SafePointer> {
		if (safePointer.IsValid(length))
			return safePointer;
		return std::nullopt;
	},
		false); // Don't purge invalids after this map call, that would lead to a infinite loop
}

BCRL::Session BCRL::Session::ForEach(std::function<void(BCRL::SafePointer&)> action)
{
	return Repeater([action](SafePointer& safePointer) {
		action(safePointer);
		return false;
	});
}

BCRL::Session BCRL::Session::Repeater(std::function<bool(SafePointer&)> action)
{
	return Map([action](SafePointer safePointer) {
		while (action(safePointer))
			;
		return safePointer;
	});
}

BCRL::Session BCRL::Session::Repeater(std::size_t iterations, std::function<void(SafePointer&)> action)
{
	return Map([iterations, action](SafePointer safePointer) {
		for (std::size_t i = 0; i < iterations; i++) {
			action(safePointer);
		}
		return safePointer;
	});
}

BCRL::Session BCRL::Session::Filter(std::function<bool(BCRL::SafePointer)> predicate)
{
	return Map([predicate](SafePointer safePointer) -> std::optional<BCRL::SafePointer> {
		if (predicate(safePointer))
			return std::optional<SafePointer>(safePointer);
		else
			return std::nullopt;
	});
}

BCRL::Session BCRL::Session::Map(std::function<std::optional<BCRL::SafePointer>(BCRL::SafePointer)> transformer, bool purgeInvalid)
{
	std::vector<BCRL::SafePointer> newPointers{};
	for (BCRL::SafePointer safePointer : pointers) {
		std::optional<BCRL::SafePointer> newSafePointer = transformer(safePointer);
		if (newSafePointer.has_value())
			newPointers.push_back(newSafePointer.value());
	}
	Session session{ newPointers, IsSafe() };
	if (purgeInvalid)
		return session.PurgeInvalid();
	return session;
}

BCRL::Session BCRL::Session::Map(std::function<std::vector<BCRL::SafePointer>(BCRL::SafePointer)> transformer, bool purgeInvalid)
{
	std::vector<BCRL::SafePointer> newPointers{};
	for (BCRL::SafePointer safePointer : pointers) {
		std::vector<BCRL::SafePointer> newSafePointers = transformer(safePointer);
		std::for_each(newSafePointers.begin(), newSafePointers.end(), [&newPointers](const SafePointer& safePointer) {
			newPointers.push_back(safePointer);
		});
	}
	Session session{ newPointers, IsSafe() };
	if (purgeInvalid)
		return session.PurgeInvalid();
	return session;
}
