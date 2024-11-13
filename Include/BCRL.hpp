#ifndef BCRL_HPP
#define BCRL_HPP

#include <alloca.h>
#include <array>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "ldisasm.h"
#include "MemoryManager/MemoryManager.hpp"
#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

namespace BCRL {
	namespace detail {
		template <typename T>
		struct LambdaInserter {
			using difference_type = std::ptrdiff_t;

			std::function<void(T)> callback;

			constexpr explicit LambdaInserter(std::function<void(T)> callback)
				: callback(std::move(callback))
			{
			}

			constexpr LambdaInserter& operator=(const T& obj)
			{
				callback(obj);
				return *this;
			}

			constexpr LambdaInserter& operator*()
			{
				return *this;
			}

			constexpr LambdaInserter& operator++()
			{
				return *this;
			}

			constexpr LambdaInserter& operator++(int)
			{
				return *this;
			}
		};

		template <bool Cond, typename T>
		using ConditionalField = std::conditional_t<Cond, T, std::monostate>;

		template <typename T>
		auto conditionalInit(auto... pack)
		{
			if constexpr (std::is_same_v<T, std::monostate>)
				return std::monostate{};
			else
				return T(pack...);
		}
	}

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

			pointer = reinterpret_cast<std::uintptr_t>(hit.base().base()); // Once for reverse iterator and once for the actual iterator
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
				std::advance(begin, region->getAddress() - pointer);

			searchConstraints.clampToAddressRange(*region, view.cbegin(), begin, end);

			auto hit = signature.next(begin, end);

			if (hit == end)
				return invalidate();

			pointer = reinterpret_cast<std::uintptr_t>(hit.base());
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

				signature.all(begin, end, detail::LambdaInserter<decltype(begin)>([&newPointers, this](auto match) {
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
		Session& forEach(const std::function<void(InnerSafePointer&)>& body) // Calls action on each pointer
		{
			// This looks a bit weird, but it basically acts as a for loop which can also delete invalid entries
			std::erase_if(pointers, [&body](InnerSafePointer& safePointer) {
				body(safePointer);
				return !safePointer.isValid();
			});
			return *this;
		}
		Session& repeater(const std::function<bool(InnerSafePointer&)>& action) // Repeats action until false is returned
		{
			return forEach([&action](InnerSafePointer& safePointer) {
				while (action(safePointer))
					;
			});
		}
		Session& repeater(std::size_t iterations, const std::function<void(InnerSafePointer&)>& action) // Repeats action `iterations` times
		{
			return forEach([iterations, &action](InnerSafePointer& safePointer) {
				for (std::size_t i = 0; i < iterations; i++)
					action(safePointer);
			});
		}
		Session& filter(const std::function<bool(const InnerSafePointer&)>& predicate) // Filters out non-conforming pointers
		{
			return forEach([&predicate](InnerSafePointer& safePointer) {
				if (!predicate(safePointer))
					safePointer.invalidate();
			});
		}
		Session& flatMap(const std::function<std::vector<InnerSafePointer>(const InnerSafePointer&)>& transformer) // Maps pointer to other pointers
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

			signature.all(begin, end, detail::LambdaInserter<decltype(begin)>([&pointers](auto p) {
				pointers.push_back(reinterpret_cast<std::uintptr_t>(p.base()));
			}));
		}

		return { memoryManager, pointers };
	}
}

#endif
