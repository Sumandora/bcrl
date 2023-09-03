#include "BCRL.hpp"

#include <unordered_set>

using namespace BCRL;

// We don't use filter for these two, because we need to prevent the infinite loop

Session Session::purgeDuplicates()
{
	std::unordered_set<void*> pointers{};
	return map([&pointers](SafePointer safePointer) -> std::optional<SafePointer> {
		if (!pointers.contains(safePointer.getPointer())) {
			pointers.insert(safePointer.getPointer());
			return safePointer;
		} else
			return std::nullopt;
	},
		false, false); // Don't purge duplicates after this map call, that would lead to a infinite loop
}

Session Session::purgeInvalid(std::size_t length)
{
	return map([length](SafePointer safePointer) -> std::optional<SafePointer> {
		if (safePointer.isValid(length))
			return safePointer;
		else
			return std::nullopt;
	},
		false, false); // Don't purge invalids after this map call, that would lead to a infinite loop
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

Session Session::map(const std::function<std::optional<SafePointer>(SafePointer)>& transformer, bool purgeInvalid, bool purgeDuplicates)
{
	std::vector<SafePointer> newPointers{};
	for (SafePointer safePointer : pointers) {
		std::optional<SafePointer> newSafePointer = transformer(safePointer);
		if (newSafePointer.has_value())
			newPointers.push_back(newSafePointer.value());
	}
	Session session{ newPointers, isSafe() };
	if (purgeInvalid)
		session = session.purgeInvalid();
	if (purgeDuplicates)
		session = session.purgeDuplicates();
	return session;
}

Session Session::flatMap(const std::function<std::vector<SafePointer>(SafePointer)>& transformer, bool purgeInvalid, bool purgeDuplicates)
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
		session = session.purgeInvalid();
	if (purgeDuplicates)
		session = session.purgeDuplicates();
	return session;
}
