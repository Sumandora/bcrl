#ifndef BCRL_HPP
#define BCRL_HPP

#include "detail/LambdaInserter.hpp"

#include "SafePointer.hpp"
#include "SearchConstraints.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include "LengthDisassembler/LengthDisassembler.hpp"

#include <alloca.h>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <initializer_list>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace BCRL {
	enum class FinalizationError : std::uint8_t {
		NO_POINTERS_LEFT,
		TOO_MANY_POINTERS_LEFT,
	};

	template <typename MemMgr>
	class Session {
		using InnerSafePointer = SafePointer<MemMgr>;

		const MemMgr* memory_manager;
		std::vector<InnerSafePointer> pointers;

	public:
		constexpr Session(const MemMgr& memory_manager, std::vector<InnerSafePointer>&& pointers)
			: memory_manager(&memory_manager)
			, pointers(std::move(pointers))
		{
		}

		constexpr Session(const MemMgr& memory_manager, const std::ranges::range auto& pointers)
			: memory_manager(&memory_manager)
			, pointers()
		{
			this->pointers.reserve(pointers.size());
			for (auto pointer : pointers) {
				this->pointers.emplace_back(memory_manager, pointer);
			}
		}

		Session() = delete;

		// Manipulation
		Session& add(std::integral auto operand) // Advances all pointers forward
		{
			return for_each([operand](InnerSafePointer& safe_pointer) {
				safe_pointer.add(operand);
			});
		}

		Session& sub(std::integral auto operand) // Inverse of above
		{
			return for_each([operand](InnerSafePointer& safe_pointer) {
				safe_pointer.sub(operand);
			});
		}

		Session& dereference() // Follows a pointer
		{
			return for_each([](InnerSafePointer& safe_pointer) {
				safe_pointer.dereference();
			});
		}

		// Signatures
		// Prev occurrence of signature
		Session& prev_signature_occurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
		{
			return for_each([&signature, &search_constraints](InnerSafePointer& safe_pointer) {
				safe_pointer.prev_signature_occurrence(signature, search_constraints);
			});
		}

		// Next occurrence of signature
		Session& next_signature_occurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
		{
			return for_each([&signature, &search_constraints](InnerSafePointer& safe_pointer) {
				safe_pointer.next_signature_occurrence(signature, search_constraints);
			});
		}

		// Filters
		Session& filter(const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
		{
			return filter([&search_constraints](const InnerSafePointer& safe_pointer) {
				return safe_pointer.filter(search_constraints);
			});
		}

		// X86
		Session& find_xrefs(SignatureScanner::XRefTypes types, const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
		{
			return flat_map([types, &search_constraints](const InnerSafePointer& safe_pointer) {
				return safe_pointer.find_xrefs(types, search_constraints);
			});
		}

		Session& relative_to_absolute()
		{
			return for_each([](InnerSafePointer& safe_pointer) {
				safe_pointer.relative_to_absolute();
			});
		}

		Session& next_instruction(LengthDisassembler::MachineMode mode = (sizeof(void*) == 8)
				? LengthDisassembler::MachineMode::LONG_MODE
				: LengthDisassembler::MachineMode::LONG_COMPATIBILITY_MODE)
		{
			return for_each([mode](InnerSafePointer& safe_pointer) {
				safe_pointer.next_instruction(mode);
			});
		}

		// Advanced Flow
		template <typename F>
			requires std::invocable<F, InnerSafePointer&>
		Session& for_each(const F& body) // Calls action on each pointer
		{
			// This looks a bit weird, but it basically acts as a for loop which can also delete invalid entries
			std::erase_if(pointers, [&body](InnerSafePointer& safe_pointer) {
				body(safe_pointer);
				return !safe_pointer.is_valid();
			});
			return *this;
		}
		template <typename F>
			requires std::is_invocable_r_v<bool, F, InnerSafePointer&>
		Session& repeater(const F& action) // Repeats action until false is returned
		{
			return for_each([&action](InnerSafePointer& safe_pointer) {
				while (action(safe_pointer))
					;
			});
		}
		template <typename F>
			requires std::invocable<F, InnerSafePointer&>
		Session& repeater(std::size_t iterations, const F& action) // Repeats action `iterations` times
		{
			return for_each([iterations, &action](InnerSafePointer& safe_pointer) {
				for (std::size_t i = 0; i < iterations; i++)
					action(safe_pointer);
			});
		}
		template <typename F>
			requires std::is_invocable_r_v<bool, F, const InnerSafePointer&>
		Session& filter(const F& predicate) // Filters out non-conforming pointers
		{
			return for_each([&predicate](InnerSafePointer& safe_pointer) {
				if (!predicate(safe_pointer))
					safe_pointer.invalidate();
			});
		}
		template <typename F>
			requires std::is_invocable_r_v<std::vector<InnerSafePointer>, F, const InnerSafePointer&>
		Session& flat_map(const F& transformer) // Maps pointer to other pointers
		{
			std::vector<InnerSafePointer> new_safe_pointers;
			for (InnerSafePointer& safe_pointer : pointers) {
				auto transformed = transformer(safe_pointer);
				for (InnerSafePointer& new_safe_pointer : transformed) {
					if (!new_safe_pointer.is_valid())
						continue;

					new_safe_pointers.emplace_back(new_safe_pointer);
				}
			}
			pointers = std::move(new_safe_pointers);
			return *this;
		}

		[[nodiscard]] constexpr Session clone() const
		{
			return *this;
		}

		[[nodiscard]] constexpr const MemMgr& get_memory_manager() const
		{
			return *memory_manager;
		}

		// Finalizing
		[[nodiscard]] const std::vector<InnerSafePointer>& peek() const // Allows to peek at all remaining pointers
		{
			return pointers;
		}

		[[nodiscard]] std::expected<std::uintptr_t, FinalizationError> finalize() const // Returns a std::expected based on if there is a clear result
		{
			if (pointers.size() == 1)
				return pointers.begin()->get_pointer();

			if (pointers.empty())
				return std::unexpected(FinalizationError::NO_POINTERS_LEFT);

			return std::unexpected(FinalizationError::TOO_MANY_POINTERS_LEFT);
		}

		template <typename T = std::uintptr_t>
		[[nodiscard]] std::expected<T, FinalizationError> finalize() const
		{
			return finalize().transform([](std::uintptr_t p) {
				return T(p);
			});
		}

		// Gets the last remaining pointer, but throws a std::runtime_error with a user-defined message if the pool doesn't contain exactly one pointer
		template <typename T = std::uintptr_t>
		[[nodiscard]] T expect(const std::string& none, const std::string& too_many) const
		{
			auto result = finalize<T>();

			if (!result.has_value())
				throw std::runtime_error{ [&none, &too_many, error = result.error()]() {
					switch (error) {
					case FinalizationError::NO_POINTERS_LEFT:
						return none;
					case FinalizationError::TOO_MANY_POINTERS_LEFT:
						return too_many;
					}
					std::unreachable();
				}() };

			return result.value();
		}

		// Same as expect with a uniform exception message
		template <typename T = std::uintptr_t>
		[[nodiscard]] T expect(const std::string& message) const
		{
			return expect<T>(message, message);
		}
	};

	// Openers/Initializers
	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointer_list(const MemMgr& memory_manager, const std::ranges::range auto& pointers)
	{
		return { memory_manager, pointers };
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointer(const MemMgr& memory_manager, std::uintptr_t pointer)
	{
		return pointer_list(memory_manager, std::initializer_list<std::uintptr_t>{ pointer });
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointer_array(const MemMgr& memory_manager, std::uintptr_t array, std::size_t index) // e.g. Virtual function tables
	{
		return { memory_manager, std::vector<SafePointer<MemMgr>>{ SafePointer(memory_manager, array).dereference().add(index * sizeof(std::uintptr_t)).dereference() } };
	}

	template <typename MemMgr>
		requires MemoryManager::LayoutAware<MemMgr> && MemoryManager::AddressAware<typename MemMgr::RegionT> && MemoryManager::NameAware<typename MemMgr::RegionT> && MemoryManager::FlagAware<typename MemMgr::RegionT>
	[[nodiscard]] inline Session<MemMgr> regions(
		const MemMgr& memory_manager,
		const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
	{
		std::vector<std::uintptr_t> bases;
		for (const auto& region : memory_manager.get_layout())
			if (search_constraints.allows_region(region))
				bases.push_back(region.get_address());
		return pointer_list(memory_manager, bases);
	}

	template <typename MemMgr>
		requires MemoryManager::Viewable<typename MemMgr::RegionT>
	[[nodiscard]] inline Session<MemMgr> signature(
		const MemMgr& memory_manager,
		const SignatureScanner::PatternSignature& signature,
		const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
	{
		std::vector<std::uintptr_t> pointers{};

		for (const auto& region : memory_manager.get_layout()) {
			if (!search_constraints.allows_region(region))
				continue;

			auto view = region.view();

			auto begin = view.cbegin();
			auto end = view.cend();

			search_constraints.clamp_to_address_range(region, view.cbegin(), begin, end);

			signature.all(begin, end, detail::LambdaInserter([&](decltype(begin) p) {
				pointers.push_back(region.get_address() + std::distance(view.cbegin(), p));
			}));
		}

		return { memory_manager, pointers };
	}
}

#endif
