#ifndef BCRL_HPP
#define BCRL_HPP

#include "detail/LambdaInserter.hpp"

#include "SafePointer.hpp"
#include "SearchConstraints.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

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
		NoPointersLeft,
		TooManyPointersLeft,
	};

	template <typename MemMgr>
	class Session {
		using InnerSafePointer = SafePointer<MemMgr>;

		const MemMgr* memoryManager;
		std::vector<InnerSafePointer> pointers;

	public:
		constexpr Session(const MemMgr& memoryManager, std::vector<InnerSafePointer>&& pointers)
			: memoryManager(&memoryManager)
			, pointers(std::move(pointers))
		{
		}

		constexpr Session(const MemMgr& memoryManager, const std::ranges::range auto& pointers)
			: memoryManager(&memoryManager)
			, pointers()
		{
			this->pointers.reserve(pointers.size());
			for (auto pointer : pointers) {
				this->pointers.emplace_back(memoryManager, pointer);
			}
		}

		Session() = delete;

		// Manipulation
		Session& add(std::integral auto operand) // Advances all pointers forward
		{
			return forEach([operand](InnerSafePointer& safePointer) {
				safePointer.add(operand);
			});
		}

		Session& sub(std::integral auto operand) // Inverse of above
		{
			return forEach([operand](InnerSafePointer& safePointer) {
				safePointer.sub(operand);
			});
		}

		Session& dereference() // Follows a pointer
		{
			return forEach([](InnerSafePointer& safePointer) {
				safePointer.dereference();
			});
		}

		// Signatures
		// Prev occurrence of signature
		Session& prevSignatureOccurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return forEach([&signature, &searchConstraints](InnerSafePointer& safePointer) {
				safePointer.prevSignatureOccurrence(signature, searchConstraints);
			});
		}

		// Next occurrence of signature
		Session& nextSignatureOccurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return forEach([&signature, &searchConstraints](InnerSafePointer& safePointer) {
				safePointer.nextSignatureOccurrence(signature, searchConstraints);
			});
		}

		// Filters
		Session& filter(const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return filter([&searchConstraints](const InnerSafePointer& safePointer) {
				return safePointer.filter(searchConstraints);
			});
		}

		// X86
		Session& findXREFs(SignatureScanner::XRefTypes types, const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return flatMap([types, &searchConstraints](const InnerSafePointer& safePointer) {
				return safePointer.findXREFs(types, searchConstraints);
			});
		}

		Session& relativeToAbsolute()
		{
			return forEach([](InnerSafePointer& safePointer) {
				safePointer.relativeToAbsolute();
			});
		}

		Session& nextInstruction()
		{
			return forEach([](InnerSafePointer& safePointer) {
				safePointer.nextInstruction();
			});
		}

		// Advanced Flow
		template <typename F>
			requires std::invocable<F, InnerSafePointer&>
		Session& forEach(const F& body) // Calls action on each pointer
		{
			// This looks a bit weird, but it basically acts as a for loop which can also delete invalid entries
			std::erase_if(pointers, [&body](InnerSafePointer& safePointer) {
				body(safePointer);
				return !safePointer.isValid();
			});
			return *this;
		}
		template <typename F>
			requires std::is_invocable_r_v<bool, F, InnerSafePointer&>
		Session& repeater(const F& action) // Repeats action until false is returned
		{
			return forEach([&action](InnerSafePointer& safePointer) {
				while (action(safePointer))
					;
			});
		}
		template <typename F>
			requires std::invocable<F, InnerSafePointer&>
		Session& repeater(std::size_t iterations, const F& action) // Repeats action `iterations` times
		{
			return forEach([iterations, &action](InnerSafePointer& safePointer) {
				for (std::size_t i = 0; i < iterations; i++)
					action(safePointer);
			});
		}
		template <typename F>
			requires std::is_invocable_r_v<bool, F, const InnerSafePointer&>
		Session& filter(const F& predicate) // Filters out non-conforming pointers
		{
			return forEach([&predicate](InnerSafePointer& safePointer) {
				if (!predicate(safePointer))
					safePointer.invalidate();
			});
		}
		template <typename F>
			requires std::is_invocable_r_v<std::vector<InnerSafePointer>, F, const InnerSafePointer&>
		Session& flatMap(const F& transformer) // Maps pointer to other pointers
		{
			std::vector<InnerSafePointer> newSafePointers;
			for (InnerSafePointer& safePointer : pointers) {
				auto transformed = transformer(safePointer);
				for (InnerSafePointer& newSafePointer : transformed) {
					if (!newSafePointer.isValid())
						continue;

					newSafePointers.emplace_back(newSafePointer);
				}
			}
			pointers = std::move(newSafePointers);
			return *this;
		}

		[[nodiscard]] constexpr Session clone() const
		{
			return *this;
		}

		[[nodiscard]] constexpr const MemMgr& getMemoryManager() const
		{
			return *memoryManager;
		}

		// Finalizing
		[[nodiscard]] const std::vector<InnerSafePointer>& peek() const // Allows to peek at all remaining pointers
		{
			return pointers;
		}

		[[nodiscard]] std::expected<std::uintptr_t, FinalizationError> finalize() const // Returns a std::expected based on if there is a clear result
		{
			if (pointers.size() == 1)
				return pointers.begin()->getPointer();

			if (pointers.empty())
				return std::unexpected(FinalizationError::NoPointersLeft);

			return std::unexpected(FinalizationError::TooManyPointersLeft);
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
		[[nodiscard]] T expect(const std::string& none, const std::string& tooMany) const
		{
			auto result = finalize<T>();

			if (!result.has_value())
				throw std::runtime_error{ [&none, &tooMany, error = result.error()]() {
					switch (error) {
					case FinalizationError::NoPointersLeft:
						return none;
					case FinalizationError::TooManyPointersLeft:
						return tooMany;
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
	[[nodiscard]] inline Session<MemMgr> pointerList(const MemMgr& memoryManager, const std::ranges::range auto& pointers)
	{
		return { memoryManager, pointers };
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointer(const MemMgr& memoryManager, std::uintptr_t pointer)
	{
		return pointerList(memoryManager, std::initializer_list<std::uintptr_t>{ pointer });
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointerArray(const MemMgr& memoryManager, std::uintptr_t array, std::size_t index) // e.g. Virtual function tables
	{
		return { memoryManager, std::vector<SafePointer<MemMgr>>{ SafePointer(memoryManager, array).dereference().add(index * sizeof(std::uintptr_t)).dereference() } };
	}

	template <typename MemMgr>
		requires MemoryManager::LayoutAware<MemMgr> && MemoryManager::AddressAware<typename MemMgr::RegionT> && MemoryManager::NameAware<typename MemMgr::RegionT> && MemoryManager::FlagAware<typename MemMgr::RegionT>
	[[nodiscard]] inline Session<MemMgr> regions(
		const MemMgr& memoryManager,
		const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
	{
		std::vector<std::uintptr_t> bases;
		for (const auto& region : memoryManager.getLayout())
			if (searchConstraints.allowsRegion(region))
				bases.push_back(region.getAddress());
		return pointerList(memoryManager, bases);
	}

	template <typename MemMgr>
		requires MemoryManager::Viewable<typename MemMgr::RegionT>
	[[nodiscard]] inline Session<MemMgr> signature(
		const MemMgr& memoryManager,
		const SignatureScanner::PatternSignature& signature,
		const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
	{
		std::vector<std::uintptr_t> pointers{};

		for (const auto& region : memoryManager.getLayout()) {
			if (!searchConstraints.allowsRegion(region))
				continue;

			auto view = region.view();

			auto begin = view.cbegin();
			auto end = view.cend();

			searchConstraints.clampToAddressRange(region, view.cbegin(), begin, end);

			signature.all(begin, end, detail::LambdaInserter([&pointers](decltype(begin) p) {
				pointers.push_back(reinterpret_cast<std::uintptr_t>(p.base()));
			}));
		}

		return { memoryManager, pointers };
	}
}

#endif
