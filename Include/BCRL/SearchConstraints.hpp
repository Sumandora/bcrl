#ifndef BCRL_SEARCHCONSTRAINTS_HPP
#define BCRL_SEARCHCONSTRAINTS_HPP

#include "detail/ConditionalField.hpp"

#include "FlagSpecification.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace BCRL {
	struct FromAddress {
		std::uintptr_t address = std::numeric_limits<std::uintptr_t>::min();
	};
	struct ToAddress {
		std::uintptr_t address = std::numeric_limits<std::uintptr_t>::max();
	};
	struct Flags {
		// Packed into a single struct for memory efficiency (and simplifying some constexpr gymnastics)
		bool has_readable : 1;
		bool has_writable : 1;
		bool has_executable : 1;
		bool has_shared : 1;

		bool readable : 1;
		bool writable : 1;
		bool executable : 1;
		bool shared : 1;

		[[nodiscard]] constexpr Flags with_readable(bool readable) const
		{
			Flags flags{ *this };
			flags.has_readable = true;
			flags.readable = readable;
			return flags;
		}

		[[nodiscard]] constexpr Flags with_writable(bool writable) const
		{
			Flags flags{ *this };
			flags.has_writable = true;
			flags.writable = writable;
			return flags;
		}

		[[nodiscard]] constexpr Flags with_executable(bool executable) const
		{
			Flags flags{ *this };
			flags.has_executable = true;
			flags.executable = executable;
			return flags;
		}

		[[nodiscard]] constexpr Flags with_shared(bool shared) const
		{
			Flags flags{ *this };
			flags.has_shared = true;
			flags.shared = shared;
			return flags;
		}
	};
	template <typename Function>
	struct Predicate {
		Function function;
	};

	template <typename T>
	concept IsRegionPredicate = requires(T predicate) {
		{
			[]<typename R>(Predicate<R>&) { }(predicate)
		};
	};

	template <typename... Constraints>
	class SearchConstraints {
		std::tuple<Constraints...> constraints;

	public:
		consteval explicit SearchConstraints(Constraints... tags)
			: constraints(std::make_tuple(tags...))
		{
		}

	private:
		template <typename NewConstraint>
		[[nodiscard]] static consteval bool has_type_already()
		{
			return (std::same_as<NewConstraint, Constraints> || ...);
		}

		template <typename NewConstraint, typename... Args>
		consteval auto with(Args... args) const
		{
			if constexpr (has_type_already<NewConstraint>()) {
				static constexpr auto MODIFY_IF_TYPE_MATCHES = []<typename T>(T t, NewConstraint r) -> T {
					if constexpr (std::same_as<T, NewConstraint>)
						return r;
					else
						return t;
				};
				return std::apply([tag = NewConstraint(std::forward<Args>(args)...)](Constraints... tags) {
					return SearchConstraints<Constraints...>(MODIFY_IF_TYPE_MATCHES(tags, tag)...);
				},
					constraints);
			} else
				return std::apply([tag = NewConstraint(std::forward<Args>(args)...)](Constraints... tags) {
					return SearchConstraints<Constraints..., NewConstraint>(std::forward<Constraints>(tags)..., tag);
				},
					constraints);
		}

		template <typename Constraint>
			requires(sizeof...(Constraints) == 0)
		[[nodiscard]] constexpr Constraint get_or_default() const
		{
			return Constraint{};
		}

		template <typename Constraint, std::size_t I = sizeof...(Constraints) - 1>
			requires(sizeof...(Constraints) > 0)
		[[nodiscard]] constexpr Constraint get_or_default() const
		{
			if constexpr (std::same_as<Constraint, std::tuple_element_t<I, std::tuple<Constraints...>>>) {
				return std::get<I>(constraints);
			} else if constexpr (I == 0) {
				return Constraint{};
			} else {
				return get_or_default<Constraint, I - 1>();
			}
		}

		[[nodiscard]] static consteval std::optional<bool> parse_perm(char c, char perm, char not_perm)
		{
			if (c == perm)
				return true;
			if (c == not_perm)
				return false;
			if (c == '*')
				return std::nullopt;
			std::unreachable();
		}

	public:
		template <typename PredicateFunction>
		[[nodiscard]] consteval auto also(PredicateFunction predicate) const
		{
			return with<Predicate<PredicateFunction>>(predicate);
		}

		[[nodiscard]] consteval auto with_name(std::string_view name) const
		{
			return also([name](const MemoryManager::NameAware auto& r) {
				return r.get_name() == name;
			});
		}

		[[nodiscard]] consteval auto with_path(std::string_view path) const
		{
			return also([path](const MemoryManager::PathAware auto& r) {
				return r.get_path() == path;
			});
		}

		[[nodiscard]] consteval auto from(std::uintptr_t address) const
		{
			return with<FromAddress>(address);
		}

		[[nodiscard]] consteval auto to(std::uintptr_t address) const
		{
			return with<ToAddress>(address);
		}

		[[nodiscard]] consteval auto with_flags(const char (&rwx)[4]) const
		{
			const std::optional<bool> readable = parse_perm(rwx[0], 'r', '-');
			const std::optional<bool> writable = parse_perm(rwx[1], 'w', '-');
			const std::optional<bool> executable = parse_perm(rwx[2], 'x', '-');

			const auto prev = get_or_default<Flags>();
			const Flags new_flags{
				.has_readable = readable.has_value(),
				.has_writable = writable.has_value(),
				.has_executable = executable.has_value(),
				.has_shared = prev.has_shared,

				.readable = readable.value_or(false),
				.writable = writable.value_or(false),
				.executable = executable.value_or(false),
				.shared = prev.shared,
			};

			return with<Flags>(new_flags);
		}

		[[nodiscard]] consteval auto with_flags(const char (&rwx)[5]) const
		{
			const std::optional<bool> readable = parse_perm(rwx[0], 'r', '-');
			const std::optional<bool> writable = parse_perm(rwx[1], 'w', '-');
			const std::optional<bool> executable = parse_perm(rwx[2], 'x', '-');
			const std::optional<bool> shared = parse_perm(rwx[2], 's', 'p');

			const Flags new_flags{
				.has_readable = readable.has_value(),
				.has_writable = writable.has_value(),
				.has_executable = executable.has_value(),
				.has_shared = shared.has_value(),

				.readable = readable.value_or(false),
				.writable = writable.value_or(false),
				.executable = executable.value_or(false),
				.shared = shared.value_or(false),
			};

			return with<Flags>(new_flags);
		}

		[[nodiscard]] consteval auto thats_readable() const
		{
			return with<Flags>(get_or_default<Flags>().with_readable(true));
		}
		[[nodiscard]] consteval auto thats_not_readable() const
		{
			return with<Flags>(get_or_default<Flags>().with_readable(false));
		}

		[[nodiscard]] consteval auto thats_writable() const
		{
			return with<Flags>(get_or_default<Flags>().with_writable(true));
		}
		[[nodiscard]] consteval auto thats_not_writable() const
		{
			return with<Flags>(get_or_default<Flags>().with_writable(false));
		}

		[[nodiscard]] consteval auto thats_executable() const
		{
			return with<Flags>(get_or_default<Flags>().with_executable(true));
		}
		[[nodiscard]] consteval auto thats_not_executable() const
		{
			return with<Flags>(get_or_default<Flags>().with_executable(false));
		}

		[[nodiscard]] consteval auto thats_shared() const
		{
			return with<Flags>(get_or_default<Flags>().with_shared(true));
		}
		[[nodiscard]] consteval auto thats_private() const
		{
			return with<Flags>(get_or_default<Flags>().with_shared(false));
		}

		// Past-initialization usage
		[[nodiscard]] constexpr bool allows_address(std::uintptr_t address) const
		{
			std::uintptr_t from_address = get_or_default<FromAddress>().address;
			std::uintptr_t to_address = get_or_default<ToAddress>().address;

			return address >= from_address && address < to_address;
		}

		template <typename Region>
			requires MemoryManager::MemoryRegion<Region>
		constexpr bool allows_region(const Region& region) const
		{
			static constexpr auto INVOKE_OR_TRUE = []<typename T, typename R>(const T& constraint, const R& region) {
				if constexpr (!IsRegionPredicate<T>) {
					return true;
				} else {
					return constraint.function(region);
				}
			};
			const bool all_predicates_yield_true = std::apply([&region](const auto&... constraint) {
				return (INVOKE_OR_TRUE(constraint, region) && ...);
			},
				constraints);
			if (!all_predicates_yield_true)
				return false;

			if constexpr (MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>) {
				const std::uintptr_t from_address = get_or_default<FromAddress>().address;
				const std::uintptr_t to_address = get_or_default<ToAddress>().address;

				if (from_address > region.get_address() + region.get_length() || to_address < region.get_address())
					return false;
			} else if (has_type_already<FromAddress>() || has_type_already<ToAddress>())
				// Unenforceable constraint.
				std::unreachable();

			if constexpr (MemoryManager::FlagAware<Region> || MemoryManager::SharedAware<Region>) {
				const Flags flags = get_or_default<Flags>();

				if constexpr (MemoryManager::FlagAware<Region>) {
					if (flags.has_readable && flags.readable != region.get_flags().is_readable())
						return false;

					if (flags.has_writable && flags.writable != region.get_flags().is_writeable())
						return false;

					if (flags.has_executable && flags.executable != region.get_flags().is_executable())
						return false;
				} else
					// Unenforceable constraint.
					if (flags.has_readable || flags.has_writable || flags.has_executable)
						std::unreachable();

				if constexpr (MemoryManager::SharedAware<Region>) {
					if (flags.has_shared && flags.shared != region.is_shared())
						return false;
				} else
					// Unenforceable constraint.
					if (flags.has_shared)
						std::unreachable();

			} else if (has_type_already<Flags>())
				// Unenforceable constraint.
				std::unreachable();

			return true;
		}

		template <typename Region>
			requires MemoryManager::MemoryRegion<Region>
		constexpr void clamp_to_address_range(const Region& r, const auto& actual_begin, auto& begin, auto& end) const // TODO improve parameters
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			std::uintptr_t pointer_begin = r.get_address() + std::distance(actual_begin, begin);
			std::uintptr_t pointer_end = r.get_address() + std::distance(actual_begin, end);

			std::uintptr_t from_address = get_or_default<FromAddress>().address;
			std::uintptr_t to_address = get_or_default<ToAddress>().address;

			if (pointer_begin < from_address)
				std::advance(begin, from_address - pointer_begin);

			if (pointer_end > to_address)
				std::advance(end, to_address - pointer_end);
		}
	};

	static constexpr SearchConstraints DEFAULT_CONSTRAINTS = SearchConstraints{};
	static constexpr SearchConstraints EVERYTHING_READABLE = DEFAULT_CONSTRAINTS.thats_readable();
}

#endif
