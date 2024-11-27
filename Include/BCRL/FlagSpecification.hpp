#ifndef BCRL_FLAGSPECIFICATION_HPP
#define BCRL_FLAGSPECIFICATION_HPP

#include "MemoryManager/MemoryManager.hpp"

#include <optional>

namespace BCRL {
	struct FlagSpecification {
		std::optional<bool> readable;
		std::optional<bool> writable;
		std::optional<bool> executable;

	private:
		template <char Default>
		constexpr static void parse(std::optional<bool>& op, char c)
		{
			switch (c) {
			case '-':
				op = false;
				break;
			case Default:
				op = true;
				break;
			default:
				op = std::nullopt;
				break;
			}
		}

		constexpr static bool matches(const std::optional<bool>& op, bool state)
		{
			return !(op && op != state);
		}

	public:
		/**
		 * While this constructor accepts any unknown char as nullopt, the convention is to use an asterisk
		 * Please respect that as it may change in future versions
		 *
		 * Example:
		 * 	r*x specifies a region which is readable and executable, but may or may not be writable
		 * 	rwx specifies a region which is readable, writable and executable
		 * 	**x specifies a region which is definitely executable, but the rest is ignored
		 * 	r-x specifies a region which is readable and executable, but not writable
		 * 	r-- specifies a region which is read-only, meaning readable, but not executable/writable
		 */
		constexpr FlagSpecification(const char rwx[3]) // NOLINT(google-explicit-constructor, hicpp-explicit-conversions)
		{
			parse<'r'>(readable, rwx[0]);
			parse<'w'>(writable, rwx[1]);
			parse<'x'>(executable, rwx[2]);
		}

		[[nodiscard]] bool matchesReadable(bool readable) const
		{
			return matches(this->readable, readable);
		}

		[[nodiscard]] bool matchesWritable(bool writable) const
		{
			return matches(this->writable, writable);
		}
		[[nodiscard]] bool matchesExecutable(bool executable) const
		{
			return matches(this->executable, executable);
		}

		bool operator==(MemoryManager::Flags flags) const
		{
			return matchesReadable(flags.isReadable()) && matchesWritable(flags.isWriteable()) && matchesExecutable(flags.isExecutable());
		}
	};
}

#endif
