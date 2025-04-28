#ifndef BCRL_SAFEPOINTER_HPP
#define BCRL_SAFEPOINTER_HPP

#include "detail/LambdaInserter.hpp"

#include "SearchConstraints.hpp"

#include "MemoryManager/MemoryManager.hpp"

#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include "LengthDisassembler/LengthDisassembler.hpp"

#include <algorithm>
#include <alloca.h>
#include <array>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <type_traits>
#include <vector>

namespace BCRL {
	template <typename MemMgr>
		requires MemoryManager::LayoutAware<MemMgr> && MemoryManager::Reader<MemMgr> && MemoryManager::AddressAware<typename MemMgr::RegionT> && MemoryManager::LengthAware<typename MemMgr::RegionT>
	class SafePointer { // A pointer which can't cause read access violations
		const MemMgr* memory_manager;
		std::uintptr_t pointer;
		bool invalid; // Set to true, when an operation failed

	public:
		SafePointer() = delete;
		explicit SafePointer(const MemMgr& memory_manager, std::uintptr_t pointer, bool invalid = false)
			: memory_manager(&memory_manager)
			, pointer(pointer)
			, invalid(invalid)
		{
		}

		[[nodiscard]] bool is_valid(std::size_t length = 1) const
		{
			if (is_marked_invalid())
				return false; // It was already eliminated

			std::uintptr_t p = pointer;
			std::uintptr_t end = pointer + length;

			while (end > p) {
				auto* region = memory_manager->get_layout().find_region(p);
				if (!region)
					return false;
				if constexpr (MemMgr::REQUIRES_PERMISSIONS_FOR_READING)
					if (!region->get_flags().is_readable())
						return false;
				p = region->get_address() + region->get_length();
			}

			return true;
		}

		[[nodiscard]] bool read(void* to, size_t len) const
		{
			if (is_valid(len)) {
				memory_manager->read(pointer, to, len);
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
		// Previous occurrence of pattern signature
		SafePointer& prev_signature_occurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
			requires MemoryManager::Viewable<typename MemMgr::RegionT>
		{
			auto* region = memory_manager->get_layout().find_region(pointer);
			if (!region || !search_constraints.allows_region(*region))
				return invalidate();

			auto view = region->view();

			auto begin = view.cbegin();
			auto end = view.cend();

			std::uintptr_t pointer_end = region->get_address() + region->get_length();

			if (pointer < pointer_end)
				std::advance(end, pointer - pointer_end);

			search_constraints.clamp_to_address_range(*region, view.cbegin(), begin, end);

			auto rbegin = std::make_reverse_iterator(end);
			auto rend = std::make_reverse_iterator(begin);

			auto hit = signature.prev(rbegin, rend);

			if (hit == rend)
				return invalidate();

			pointer = region->get_address()
				+ region->get_length()
				- 1
				- std::distance(std::make_reverse_iterator(view.cend()), hit);
			return revalidate();
		}

		// Next occurrence of pattern signature
		SafePointer& next_signature_occurrence(
			const SignatureScanner::PatternSignature& signature,
			const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable())
			requires MemoryManager::Viewable<typename MemMgr::RegionT>
		{
			auto* region = memory_manager->get_layout().find_region(pointer);
			if (!region || !search_constraints.allows_region(*region))
				return invalidate();

			auto view = region->view();

			auto begin = view.cbegin();
			auto end = view.cend();

			if (pointer > region->get_address())
				std::advance(begin, pointer - region->get_address());

			search_constraints.clamp_to_address_range(*region, view.cbegin(), begin, end);

			auto hit = signature.next(begin, end);

			if (hit == end)
				return invalidate();

			pointer = region->get_address() + std::distance(view.cbegin(), hit);
			return revalidate();
		}

		// Tests if the given pattern signature matches the current address
		[[nodiscard]] bool does_match(const SignatureScanner::PatternSignature& signature) const
		{
			std::size_t length = signature.get_elements().size();
			auto* bytes = static_cast<std::byte*>(alloca(length));
			if (!read(bytes, length))
				return false;
			return signature.does_match(&bytes[0], &bytes[length]);
		}

		// X86
		// Since there can be multiple xrefs, this returns multiple addresses
		[[nodiscard]] std::vector<SafePointer> find_xrefs(SignatureScanner::XRefTypes types, const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable()) const
			requires MemoryManager::Viewable<typename MemMgr::RegionT>
		{
			std::vector<SafePointer> new_pointers;

			SignatureScanner::XRefSignature signature(types, pointer);
			for (const auto& region : memory_manager->get_layout()) {
				if (!search_constraints.allows_region(region))
					continue;

				auto view = region.view();

				auto begin = view.cbegin();
				auto end = view.cend();

				search_constraints.clamp_to_address_range(region, view.cbegin(), begin, end);

				signature.all(begin, end, detail::LambdaInserter([&](decltype(begin) match) {
					new_pointers.emplace_back(*memory_manager, region.get_address() + std::distance(view.cbegin(), match));
				}), region.get_address() + std::distance(view.cbegin(), begin));
			}

			return new_pointers;
		}

	private:
		static constexpr bool IS_64_BIT = sizeof(void*) == 8;
		static constexpr LengthDisassembler::MachineMode DEFAULT_MACHINE_MODE = IS_64_BIT
			? LengthDisassembler::MachineMode::LONG_MODE
			: LengthDisassembler::MachineMode::LONG_COMPATIBILITY_MODE;

	public:
		SafePointer& relative_to_absolute()
		{
			using RelAddrType = std::conditional_t<IS_64_BIT, int32_t, int16_t>;

			std::optional<RelAddrType> offset = read<RelAddrType>();
			if (!offset.has_value()) {
				return invalidate();
			}

			return add(sizeof(RelAddrType) + offset.value());
		}

		SafePointer& next_instruction(LengthDisassembler::MachineMode mode = DEFAULT_MACHINE_MODE)
		{
			auto* region = memory_manager->get_layout().find_region(pointer);
			if (!region)
				return invalidate();

			std::uintptr_t end = region->get_address() + region->get_length();

			static constexpr std::size_t LONGEST_X86_INSN = LengthDisassembler::MAX_INSTRUCTION_LENGTH;

			std::size_t max_length = std::min(end - pointer, LONGEST_X86_INSN);

			std::array<std::byte, LONGEST_X86_INSN> bytes{};
			if (!read(&bytes, max_length)) {
				return invalidate();
			}

			using enum LengthDisassembler::MachineMode;

			std::expected<LengthDisassembler::Instruction, LengthDisassembler::Error>
				instruction = LengthDisassembler::disassemble(bytes.data(),
					mode,
					max_length);

			if (!instruction.has_value()) {
				return invalidate();
			}

			return add(instruction.value().length);
		}

		// Filters
		[[nodiscard]] bool filter(const SearchConstraints<typename MemMgr::RegionT>& search_constraints = everything<MemMgr>().thats_readable()) const
		{
			auto* region = memory_manager->get_layout().find_region(pointer);
			if (!region || !search_constraints.allows_region(*region))
				return false;

			return search_constraints.allows_address(pointer);
		}

		constexpr std::strong_ordering operator<=>(const SafePointer& other) const
		{
			return pointer <=> other.pointer;
		}

		constexpr bool operator==(const SafePointer& other) const
		{
			return pointer == other.pointer;
		}

		[[nodiscard]] constexpr const MemMgr& get_memory_manager() const
		{
			return *memory_manager;
		}

		/**
		 * @returns if a previous operation failed
		 */
		[[nodiscard]] constexpr bool is_marked_invalid() const
		{
			return invalid;
		}

		[[nodiscard]] constexpr std::uintptr_t get_pointer() const
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
