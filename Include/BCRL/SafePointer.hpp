#ifndef BCRL_SAFEPOINTER_HPP
#define BCRL_SAFEPOINTER_HPP

#include "detail/LambdaInserter.hpp"

#include "SearchConstraints.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include "ldisasm.h"

#include <alloca.h>
#include <array>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <vector>

namespace BCRL {
	template <typename MemMgr>
		requires MemoryManager::LayoutAware<MemMgr> && MemoryManager::Reader<MemMgr> && MemoryManager::AddressAware<typename MemMgr::RegionT> && MemoryManager::LengthAware<typename MemMgr::RegionT>
	class SafePointer { // A pointer which can't cause read access violations
		const MemMgr* memoryManager;
		std::uintptr_t pointer;
		bool invalid; // Set to true, when an operation failed

	public:
		SafePointer() = delete;
		explicit SafePointer(const MemMgr& memoryManager, std::uintptr_t pointer, bool invalid = false)
			: memoryManager(&memoryManager)
			, pointer(pointer)
			, invalid(invalid)
		{
		}

		[[nodiscard]] bool isValid(std::size_t length = 1) const
		{
			if (isMarkedInvalid())
				return false; // It was already eliminated

			std::uintptr_t p = pointer;
			std::uintptr_t end = pointer + length;

			while (end > p) {
				auto* region = memoryManager->getLayout().findRegion(p);
				if (!region)
					return false;
				if constexpr (MemMgr::RequiresPermissionsForReading)
					if (!region->getFlags().isReadable())
						return false;
				p = region->getAddress() + region->getLength();
			}

			return true;
		}

		[[nodiscard]] bool read(void* to, size_t len) const
		{
			if (isValid(len)) {
				memoryManager->read(pointer, to, len);
				return true;
			}
			return false;
		}

		template <typename T>
			requires std::is_trivially_copyable_v<T>
		[[nodiscard]] std::optional<T> read() const
		{
			T obj;
			if (read(&obj, sizeof(T)))
				return obj;
			return std::nullopt;
		}

		SafePointer& invalidate() // Marks safe pointer as invalid
		{
			invalid = true;
			return *this;
		}
		SafePointer& revalidate() // Marks safe pointer as valid
		{
			invalid = false;
			return *this;
		}

		// Manipulation
		SafePointer& add(std::integral auto operand) // Advances pointer forward
		{
			pointer += operand;
			return *this;
		}

		SafePointer& sub(std::integral auto operand) // Inverse of above
		{
			pointer -= operand;
			return *this;
		}

		SafePointer& dereference() // Follows a pointer
		{
			std::optional<std::uintptr_t> deref = read<std::uintptr_t>();
			if (deref.has_value()) {
				pointer = deref.value();
				return revalidate();
			}
			return invalidate();
		}

		// Patterns
		// Prev occurrence of pattern signature
		SafePointer& prevSignatureOccurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
			requires MemoryManager::Viewable<typename MemMgr::RegionT>
		{
			auto* region = memoryManager->getLayout().findRegion(pointer);
			if (!region || !searchConstraints.allowsRegion(*region))
				return invalidate();

			auto view = region->view();

			auto begin = view.cbegin();
			auto end = view.cend();

			std::uintptr_t pEnd = region->getAddress() + region->getLength();

			if (pointer < pEnd)
				std::advance(end, pointer - pEnd);

			searchConstraints.clampToAddressRange(*region, view.cbegin(), begin, end);

			auto rbegin = std::make_reverse_iterator(end);
			auto rend = std::make_reverse_iterator(begin);

			auto hit = signature.prev(rbegin, rend);

			if (hit == rend)
				return invalidate();

			pointer = reinterpret_cast<std::uintptr_t>(std::to_address(hit));
			return revalidate();
		}

		// Next occurrence of pattern signature
		SafePointer& nextSignatureOccurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
			requires MemoryManager::Viewable<typename MemMgr::RegionT>
		{
			auto* region = memoryManager->getLayout().findRegion(pointer);
			if (!region || !searchConstraints.allowsRegion(*region))
				return invalidate();

			auto view = region->view();

			auto begin = view.cbegin();
			auto end = view.cend();

			if (pointer > region->getAddress())
				std::advance(begin, pointer - region->getAddress());

			searchConstraints.clampToAddressRange(*region, view.cbegin(), begin, end);

			auto hit = signature.next(begin, end);

			if (hit == end)
				return invalidate();

			pointer = reinterpret_cast<std::uintptr_t>(std::to_address(hit));
			return revalidate();
		}

		// Tests if the given pattern signature matches the current address
		[[nodiscard]] bool doesMatch(const SignatureScanner::PatternSignature& signature) const
		{
			auto* bytes = static_cast<std::byte*>(alloca(signature.getLength()));
			if (!read(bytes, signature.getLength()))
				return false;
			return signature.doesMatch(&bytes[0], &bytes[signature.getLength()]);
		}

		// X86
		// Since there can be multiple xrefs, this returns multiple addresses
		[[nodiscard]] std::vector<SafePointer> findXREFs(SignatureScanner::XRefTypes types, const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable()) const
			requires MemoryManager::Viewable<typename MemMgr::RegionT>
		{
			std::vector<SafePointer> newPointers;

			SignatureScanner::XRefSignature signature(types, pointer);
			for (const auto& region : memoryManager->getLayout()) {
				if (!searchConstraints.allowsRegion(region))
					continue;

				auto view = region.view();

				auto begin = view.cbegin();
				auto end = view.cend();

				searchConstraints.clampToAddressRange(region, view.cbegin(), begin, end);

				signature.all(begin, end, detail::LambdaInserter([&newPointers, this](decltype(begin) match) {
					newPointers.emplace_back(*memoryManager, reinterpret_cast<std::uintptr_t>(match.base()));
				}));
			}

			return newPointers;
		}

	private:
		static constexpr bool is64Bit = sizeof(void*) == 8;

	public:
		SafePointer& relativeToAbsolute()
		{
			using RelAddrType = std::conditional_t<is64Bit, int32_t, int16_t>;

			std::optional<RelAddrType> offset = read<RelAddrType>();
			if (!offset.has_value()) {
				return invalidate();
			}

			return add(sizeof(RelAddrType) + offset.value());
		}
		SafePointer& nextInstruction()
		{
			static constexpr std::size_t longestX86Insn = 15;

			if (!isValid(longestX86Insn)) {
				return invalidate();
			}

			std::array<std::byte, longestX86Insn> bytes{};
			if (!read(&bytes, longestX86Insn)) {
				return invalidate();
			}

			return add(ldisasm(bytes.data(), is64Bit));
		}

		// Filters
		[[nodiscard]] bool filter(const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable()) const
		{
			auto* region = memoryManager->getLayout().findRegion(pointer);
			if (!region || !searchConstraints.allowsRegion(*region))
				return false;

			return searchConstraints.allowsAddress(pointer);
		}

		constexpr std::strong_ordering operator<=>(const SafePointer& other) const
		{
			return pointer <=> other.pointer;
		}

		constexpr bool operator==(const SafePointer& other) const
		{
			return pointer == other.pointer;
		}

		[[nodiscard]] constexpr const MemMgr& getMemoryManager() const
		{
			return *memoryManager;
		}

		/**
		 * @returns if a previous operation failed
		 */
		[[nodiscard]] constexpr bool isMarkedInvalid() const
		{
			return invalid;
		}

		[[nodiscard]] constexpr std::uintptr_t getPointer() const
		{
			return pointer;
		};

		[[nodiscard]] constexpr SafePointer clone() const
		{
			return *this;
		}
	};
}

#endif
