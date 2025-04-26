#ifndef BCRL_FLAGSPECIFICATION_HPP
#define BCRL_FLAGSPECIFICATION_HPP

#include "MemoryManager/MemoryManager.hpp"

#include <optional>
#include <utility>

namespace BCRL {
	struct FlagSpecification {
		std::optional<bool> readable;
		std::optional<bool> writable;
		std::optional<bool> executable;

	private:
		template <char Default>
		constexpr static std::optional<bool> parse(char c)
		{
			switch (c) {
			case '-':
				return false;
			case Default:
				return true;
			case '*':
				return std::nullopt;
			default:
				std::unreachable();
			}
		}

		constexpr static bool matches(const std::optional<bool>& op, bool state)
		{
			return !op.has_value() || op.value() == state;
		}

	public:
		/**
		 * 'r/w/x'	-> Enabled
		 * '-'		-> Disabled
		 * '*'		-> Ignored
		 * 
		 * Examples:
		 * 	r*x specifies a region which is readable and executable, but may or may not be writable
		 * 	rwx specifies a region which is readable, writable and executable
		 * 	**x specifies a region which is definitely executable, but the rest is ignored
		 * 	r-x specifies a region which is readable and executable, but not writable
		 * 	r-- specifies a region which is read-only, meaning readable, but not executable/writable
		 */
		constexpr FlagSpecification(const char rwx[3]) // NOLINT(google-explicit-constructor, hicpp-explicit-conversions)
			: readable(parse<'r'>(rwx[0]))
			, writable(parse<'w'>(rwx[1]))
			, executable(parse<'x'>(rwx[2]))
		{
		}

		[[nodiscard]] bool matches_readable(bool readable) const
		{
			return matches(this->readable, readable);
		}

		[[nodiscard]] bool matches_writable(bool writable) const
		{
			return matches(this->writable, writable);
		}
		[[nodiscard]] bool matches_executable(bool executable) const
		{
			return matches(this->executable, executable);
		}

		bool operator==(MemoryManager::Flags flags) const
		{
			return matches_readable(flags.is_readable()) && matches_writable(flags.is_writeable()) && matches_executable(flags.is_executable());
		}
	};
}

#endif
