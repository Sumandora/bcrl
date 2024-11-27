#ifndef BCRL_SEARCHCONSTRAINTS_HPP
#define BCRL_SEARCHCONSTRAINTS_HPP

#include "detail/ConditionalField.hpp"

#include "FlagSpecification.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include <cstdint>
#include <functional>
#include <limits>
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
			addressRange;
		[[no_unique_address]] detail::ConditionalField<MemoryManager::FlagAware<Region>, FlagSpecification> flags;

	public:
		SearchConstraints()
			: predicates()
			, addressRange(detail::conditionalInit<decltype(addressRange)>(
				  std::numeric_limits<std::uintptr_t>::min(), std::numeric_limits<std::uintptr_t>::max()))
			, flags(detail::conditionalInit<decltype(flags)>("***"))
		{
		}

		SearchConstraints(
			decltype(predicates)&& predicates,
			decltype(addressRange)&& addressRange,
			decltype(flags) flags)
			: predicates(std::move(predicates))
			, addressRange(std::move(addressRange))
			, flags(flags)
		{
		}

		SearchConstraints& withName(const std::string& name)
			requires MemoryManager::NameAware<Region>
		{
			predicates.push_back([name](const Region& r) {
				return r.getName() == name;
			});

			return *this;
		}

		SearchConstraints& withPath(const std::string& path)
			requires MemoryManager::PathAware<Region>
		{
			predicates.push_back([path](const Region& r) {
				return r.getPath() == path;
			});

			return *this;
		}

		SearchConstraints& from(std::uintptr_t address)
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			addressRange.first = address;
			addressRange.second = std::max(addressRange.first, addressRange.second);

			return *this;
		}

		SearchConstraints& to(std::uintptr_t address)
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			addressRange.second = address;
			addressRange.first = std::min(addressRange.first, addressRange.second);

			return *this;
		}

		SearchConstraints& withFlags(FlagSpecification specification)
			requires MemoryManager::FlagAware<Region>
		{
			flags = specification;

			return *this;
		}

		SearchConstraints& thatsReadable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.readable = true;

			return *this;
		}

		SearchConstraints& thatsNotReadable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.readable = false;

			return *this;
		}

		SearchConstraints& thatsWritable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.writable = true;

			return *this;
		}

		SearchConstraints& thatsNotWritable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.writable = false;

			return *this;
		}

		SearchConstraints& thatsExecutable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.executable = true;

			return *this;
		}

		SearchConstraints& thatsNotExecutable()
			requires MemoryManager::FlagAware<Region>
		{
			flags.executable = false;

			return *this;
		}

		SearchConstraints& also(MapPredicate<Region>&& predicate)
		{
			predicates.emplace_back(std::move(predicate));

			return *this;
		}

		// Past-initialization usage
		[[nodiscard]] bool allowsAddress(std::uintptr_t address) const
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			return address >= addressRange.first && address < addressRange.second;
		}

		bool allowsRegion(const Region& region) const
		{
			for (MapPredicate<Region> predicate : predicates) {
				if (!predicate(region))
					return false;
			}

			if constexpr (MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>)
				if (addressRange.first > region.getAddress() + region.getLength() || addressRange.second < region.getAddress())
					return false;

			if constexpr (MemoryManager::FlagAware<Region>)
				if (region.getFlags() != flags)
					return false;

			return true;
		}

		void clampToAddressRange(const Region& r, const auto& actualBegin, auto& begin, auto& end) const // TODO improve parameters
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			std::uintptr_t pBegin = r.getAddress() + std::distance(actualBegin, begin);
			std::uintptr_t pEnd = r.getAddress() + std::distance(actualBegin, end);
			if (pBegin < addressRange.first)
				std::advance(begin, addressRange.first - pBegin);

			if (pEnd > addressRange.second)
				std::advance(end, addressRange.second - pEnd);
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
		return SearchConstraints<typename MemMgr::RegionT>{};
	}
}
	
#endif
