#ifndef BCRL_SEARCHCONSTRAINTS_HPP
#define BCRL_SEARCHCONSTRAINTS_HPP

#include "detail/ConditionalField.hpp"

#include "FlagSpecification.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace BCRL {
	template <typename Region>
		requires MemoryManager::MemoryRegion<Region>
	using MapPredicate = std::function<bool(const Region&)>;

	template <typename Region>
		requires MemoryManager::MemoryRegion<Region>
	class SearchConstraints {
		std::vector<MapPredicate<Region>> predicates;
		// Remove what's not needed
		[[no_unique_address]] detail::ConditionalField<
			MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>,
			std::pair<std::uintptr_t, std::uintptr_t>>
			address_range;
		[[no_unique_address]] detail::ConditionalField<MemoryManager::FlagAware<Region>, FlagSpecification> flags;
		[[no_unique_address]] detail::ConditionalField<MemoryManager::SharedAware<Region>, std::optional<bool>> shared;

	public:
		SearchConstraints()
			: predicates()
			, address_range(detail::conditional_init<decltype(address_range)>(
				  std::numeric_limits<std::uintptr_t>::min(), std::numeric_limits<std::uintptr_t>::max()))
			, flags(detail::conditional_init<decltype(flags)>("***"))
			, shared(detail::conditional_init<decltype(shared)>(std::nullopt))
		{
		}

		SearchConstraints(
			decltype(predicates)&& predicates,
			decltype(address_range)&& address_range,
			decltype(flags) flags)
			: predicates(std::move(predicates))
			, address_range(std::move(address_range))
			, flags(flags)
		{
		}

		SearchConstraints& with_name(const std::string& name)
			requires MemoryManager::NameAware<Region>
		{
			predicates.push_back([name](const Region& r) {
				return r.get_name() == name;
			});

			return *this;
		}

		SearchConstraints& with_path(const std::string& path)
			requires MemoryManager::PathAware<Region>
		{
			predicates.push_back([path](const Region& r) {
				return r.get_path() == path;
			});

			return *this;
		}

		SearchConstraints& from(std::uintptr_t address)
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			address_range.first = address;
			address_range.second = std::max(address_range.first, address_range.second);

			return *this;
		}

		SearchConstraints& to(std::uintptr_t address)
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			address_range.second = address;
			address_range.first = std::min(address_range.first, address_range.second);

			return *this;
		}

		SearchConstraints& with_flags(FlagSpecification specification)
			requires MemoryManager::FlagAware<Region>
		{
			flags = specification;

			return *this;
		}

		SearchConstraints& thats_readable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.readable = true;

			return *this;
		}

		SearchConstraints& thats_not_readable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.readable = false;

			return *this;
		}

		SearchConstraints& thats_writable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.writable = true;

			return *this;
		}

		SearchConstraints& thats_not_writable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.writable = false;

			return *this;
		}

		SearchConstraints& thats_executable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.executable = true;

			return *this;
		}

		SearchConstraints& thats_not_executable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.executable = false;

			return *this;
		}

		SearchConstraints& thats_shared()
			requires MemoryManager::SharedAware<Region>
		{
			shared = true;

			return *this;
		}

		SearchConstraints& thats_private()
			requires MemoryManager::SharedAware<Region>
		{
			shared = false;

			return *this;
		}

		SearchConstraints& also(MapPredicate<Region>&& predicate)
		{
			predicates.emplace_back(std::move(predicate));

			return *this;
		}

		// Past-initialization usage
		[[nodiscard]] bool allows_address(std::uintptr_t address) const
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			return address >= address_range.first && address < address_range.second;
		}

		bool allows_region(const Region& region) const
		{
			for (MapPredicate<Region> predicate : predicates) {
				if (!predicate(region))
					return false;
			}

			if constexpr (MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>)
				if (address_range.first > region.get_address() + region.get_length() || address_range.second < region.get_address())
					return false;

			if constexpr (MemoryManager::FlagAware<Region>)
				if (region.get_flags() != flags)
					return false;

			if constexpr (MemoryManager::SharedAware<Region>)
				if (shared.has_value() && region.is_shared() != shared.value())
					return false;

			return true;
		}

		void clamp_to_address_range(const Region& r, const auto& actual_begin, auto& begin, auto& end) const // TODO improve parameters
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			std::uintptr_t pointer_begin = r.get_address() + std::distance(actual_begin, begin);
			std::uintptr_t pointer_end = r.get_address() + std::distance(actual_begin, end);
			if (pointer_begin < address_range.first)
				std::advance(begin, address_range.first - pointer_begin);

			if (pointer_end > address_range.second)
				std::advance(end, address_range.second - pointer_end);
		}
	};

	template <typename MemMgr>
	static SearchConstraints<typename MemMgr::RegionT> everything()
	{
		return SearchConstraints<typename MemMgr::RegionT>{};
	}

	template <typename MemMgr>
	static SearchConstraints<typename MemMgr::RegionT> everything([[maybe_unused]] const MemMgr& _) // Deduction helper
	{
		return everything<MemMgr>();
	}
}
	
#endif
