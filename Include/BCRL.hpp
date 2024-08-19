#ifndef BCRL_HPP
#define BCRL_HPP

#include <functional>
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

		template <typename ImplicitSignature>
		concept ConvertableToPatternSignature = !std::derived_from<ImplicitSignature, SignatureScanner::Signature> && requires(ImplicitSignature&& s) {
			{ SignatureScanner::PatternSignature{ std::forward<ImplicitSignature>(s) } };
		};
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
			if (op && op != state)
				return false;
			return true;
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

		SearchConstraints& withName(std::string name)
			requires MemoryManager::NameAware<Region>
		{
			predicates.push_back([name](const Region& r) {
				return r.getName() == name;
			});

			return *this;
		}

		SearchConstraints& withPath(std::string path)
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
			predicates.push_back(predicate);

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

		void clampToAddressRange(auto& begin, auto& end) const
			requires MemoryManager::AddressAware<Region> && MemoryManager::LengthAware<Region>
		{
			while (begin < addressRange.first)
				begin++;

			while (end >= addressRange.second)
				end--;
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
		mutable MemMgr* memoryManager;
		std::uintptr_t pointer;
		bool invalid; // Set to true, when an operation failed

	public:
		SafePointer() = delete;
		inline explicit SafePointer(MemMgr* memoryManager, std::uintptr_t pointer, bool invalid = false)
			: memoryManager(memoryManager)
			, pointer(pointer)
			, invalid(invalid)
		{
		}

		[[nodiscard]] bool isValid(std::size_t length = 1) const
		{
			if (isMarkedInvalid())
				return false; // It was already eliminated

			auto* region = memoryManager->getLayout().findRegion(pointer);
			if (!region)
				return false;
			for (std::size_t i = 0; i < length; i++) {
				std::uintptr_t p = pointer + i;
				if (p >= region->getAddress() && p < region->getAddress() + region->getLength())
					continue;

				region = memoryManager->getLayout().findRegion(p);
				if (!region)
					return false;
			}
			return true;
		}

		[[nodiscard]] inline bool read(void* to, size_t len) const
		{
			if (isValid(len)) {
				memoryManager->read(pointer, to, len);
				return true;
			}
			return false;
		}

		template <typename T>
			requires std::is_trivially_copyable_v<T>
		[[nodiscard]] inline std::optional<T> read() const
		{
			T obj;
			if (read(&obj, sizeof(T)))
				return obj;
			return std::nullopt;
		}

		template <typename T>
		[[nodiscard]] inline bool equals(T operand) const
		{
			std::optional<T> object = read<T>();
			if (object.has_value())
				return object.value() == operand;
			return false;
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
		SafePointer& add(std::integral auto operand) // Advances all pointers forward
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

		// Signatures
		// Prev occurrence of signature
		SafePointer& prevSignatureOccurrence(
			const std::derived_from<SignatureScanner::Signature> auto& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
			requires MemoryManager::Iterable<typename MemMgr::RegionT>
		{
			auto* region = memoryManager->getLayout().findRegion(pointer);
			if (!region || !searchConstraints.allowsRegion(*region))
				return invalidate();

			auto begin = region->cbegin();
			auto end = region->cend();

			while (end > pointer)
				end--;

			searchConstraints.clampToAddressRange(begin, end);

			auto rbegin = std::make_reverse_iterator(end);
			auto rend = std::make_reverse_iterator(begin);

			auto hit = signature.prev(rbegin, rend);

			if (hit == rend)
				return invalidate();

			pointer = reinterpret_cast<std::uintptr_t>(&*hit);
			return revalidate();
		}

		[[nodiscard]] SafePointer& prevSignatureOccurrence(
			detail::ConvertableToPatternSignature auto&& s,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return prevSignatureOccurrence(SignatureScanner::PatternSignature{ std::forward<std::remove_reference_t<decltype(s)>>(s) }, searchConstraints);
		}

		// Next occurrence of signature
		SafePointer& nextSignatureOccurrence(
			const std::derived_from<SignatureScanner::Signature> auto& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
			requires MemoryManager::Iterable<typename MemMgr::RegionT>
		{
			auto* region = memoryManager->getLayout().findRegion(pointer);
			if (!region || !searchConstraints.allowsRegion(*region))
				return invalidate();

			auto begin = region->cbegin();
			auto end = region->cend();

			while (begin < pointer)
				begin++;

			searchConstraints.clampToAddressRange(begin, end);

			auto hit = signature.next(begin, end);

			if (hit == end)
				return invalidate();

			pointer = reinterpret_cast<std::uintptr_t>(&*hit);
			return revalidate();
		}

		[[nodiscard]] SafePointer& nextSignatureOccurrence(
			detail::ConvertableToPatternSignature auto&& s,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return nextSignatureOccurrence(SignatureScanner::PatternSignature{ std::forward<std::remove_reference_t<decltype(s)>>(s) }, searchConstraints);
		}

		// Tests if the given pattern signature matches the current address
		[[nodiscard]] bool doesMatch(const SignatureScanner::PatternSignature& signature) const
		{
			std::byte bytes[signature.getLength()];
			if (!read(bytes, signature.getLength()))
				return false;
			return signature.doesMatch(&bytes[0], &bytes[signature.getLength()]);
		}

		[[nodiscard]] bool doesMatch(detail::ConvertableToPatternSignature auto&& signature) const
		{
			return doesMatch(SignatureScanner::PatternSignature{ std::forward<std::remove_reference_t<decltype(signature)>>(signature) });
		}

		// X86
		// Since there can be multiple xrefs, this returns multiple addresses
		template <bool Relative, bool Absolute, std::endian Endianness = std::endian::native>
			requires MemoryManager::Iterable<typename MemMgr::RegionT>
		[[nodiscard]] std::vector<SafePointer> findXREFs(const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable()) const
		{
			std::vector<SafePointer> newPointers;

			SignatureScanner::XRefSignature<Relative, Absolute, Endianness> signature(pointer);
			for (const auto& region : memoryManager->getLayout()) {
				if (!searchConstraints.allowsRegion(region))
					continue;

				auto begin = region.cbegin();
				auto end = region.cend();

				searchConstraints.clampToAddressRange(begin, end);

				signature.all(begin, end, detail::LambdaInserter<decltype(begin)>([&newPointers, this](auto match) -> void {
					newPointers.emplace_back(memoryManager, match);
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

		[[nodiscard]] constexpr const MemMgr* getMemoryManager() const
		{
			return memoryManager;
		}

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

	template <typename MemMgr>
	class Session {
		using SafePointer = SafePointer<MemMgr>;

		MemMgr& memoryManager;
		std::vector<SafePointer> pointers;

	public:
		constexpr Session(MemMgr& memoryManager, std::vector<SafePointer>&& pointers)
			: memoryManager(memoryManager)
			, pointers(std::move(pointers))
		{
		}

		constexpr Session(MemMgr& memoryManager, const std::ranges::range auto& pointers)
			: memoryManager(memoryManager)
			, pointers()
		{
			this->pointers.reserve(pointers.size());
			for (auto pointer : pointers) {
				this->pointers.emplace_back(&memoryManager, pointer);
			}
		}

		Session() = delete;

		// Manipulation
		Session& add(std::integral auto operand) // Advances all pointers forward
		{
			return forEach([operand](SafePointer& safePointer) {
				safePointer.add(operand);
			});
		}

		Session& sub(std::integral auto operand) // Inverse of above
		{
			return forEach([operand](SafePointer& safePointer) {
				safePointer.sub(operand);
			});
		}

		Session& dereference() // Follows a pointer
		{
			return forEach([](SafePointer& safePointer) {
				safePointer.dereference();
			});
		}

		// Signatures
		// Prev occurrence of signature
		Session& prevSignatureOccurrence(
			const std::derived_from<SignatureScanner::Signature> auto& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return forEach([&signature, searchConstraints](SafePointer& safePointer) {
				safePointer.prevSignatureOccurrence(signature, searchConstraints);
			});
		}

		[[nodiscard]] Session& prevSignatureOccurrence(
			detail::ConvertableToPatternSignature auto&& s,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return prevSignatureOccurrence(SignatureScanner::PatternSignature{ std::forward<std::remove_reference_t<decltype(s)>>(s) }, searchConstraints);
		}

		// Next occurrence of signature
		Session& nextSignatureOccurrence(
			const std::derived_from<SignatureScanner::Signature> auto& signature,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return forEach([&signature, searchConstraints](SafePointer& safePointer) {
				safePointer.nextSignatureOccurrence(signature, searchConstraints);
			});
		}

		[[nodiscard]] Session& nextSignatureOccurrence(
			detail::ConvertableToPatternSignature auto&& s,
			const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return nextSignatureOccurrence(SignatureScanner::PatternSignature{ std::forward<std::remove_reference_t<decltype(s)>>(s) }, searchConstraints);
		}

		// Filters
		Session& filter(const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return filter([&searchConstraints](const SafePointer& safePointer) {
				return safePointer.filter(searchConstraints);
			});
		}

		// X86
		template <bool Relative, bool Absolute, std::endian Endianness = std::endian::native>
		Session& findXREFs(const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
		{
			return flatMap([&searchConstraints](const SafePointer& safePointer) {
				return safePointer.template findXREFs<Relative, Absolute, Endianness>(searchConstraints);
			});
		}

		Session& relativeToAbsolute()
		{
			return forEach([](SafePointer& safePointer) {
				safePointer.relativeToAbsolute();
			});
		}

		Session& nextInstruction()
		{
			return forEach([](SafePointer& safePointer) {
				safePointer.nextInstruction();
			});
		}

		// Advanced Flow
		Session& forEach(const std::function<void(SafePointer&)>& body) // Calls action on each pointer
		{
			// This looks a bit scuffed, but it basically acts as a for loop which can also delete invalid entries
			std::erase_if(pointers, [body](SafePointer& safePointer) {
				body(safePointer);
				return !safePointer.isValid();
			});
			return *this;
		}
		Session& repeater(const std::function<bool(SafePointer&)>& action) // Repeats action until false is returned
		{
			return forEach([action](SafePointer& safePointer) {
				while (action(safePointer))
					;
			});
		}
		Session& repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action) // Repeats action `iterations` times
		{
			return forEach([iterations, action](SafePointer& safePointer) {
				for (std::size_t i = 0; i < iterations; i++)
					action(safePointer);
			});
		}
		Session& filter(const std::function<bool(const SafePointer&)>& predicate) // Filters out non-conforming pointers
		{
			return forEach([predicate](SafePointer& safePointer) {
				if (!predicate(safePointer))
					safePointer.invalidate();
			});
		}
		Session& flatMap(const std::function<std::vector<SafePointer>(const SafePointer&)>& transformer) // Maps pointer to other pointers
		{
			std::vector<SafePointer> newSafePointers;
			for (SafePointer& safePointer : pointers) {
				auto transformed = transformer(safePointer);
				for (SafePointer& newSafePointer : transformed) {
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

		// Finalizing
		struct Result {
			union {
				std::uintptr_t pointer;
				std::uintptr_t count;
			};
			bool found; // true if there was only one remaining pointer
		};

		[[nodiscard]] const std::vector<SafePointer>& peek() const // Allows to peek at all remaining pointers
		{
			return pointers;
		}

		[[nodiscard]] Result finalize() const // Will return a Result struct if there are no/multiple pointers available
		{
			if (pointers.size() == 1)
				return { pointers.begin()->getPointer(), true };

			return { pointers.size(), false };
		}

		// Gets the last remaining pointer, but throws a std::exception if the pool doesn't contain exactly one pointer
		template <typename T = std::uintptr_t>
		[[nodiscard]] T get() const
		{
			Result opt = finalize();

			if (!opt.found)
				throw std::exception{};

			if constexpr (std::is_pointer_v<T>)
				return reinterpret_cast<T>(reinterpret_cast<void*>(opt.pointer));
			else
				return T(opt.pointer);
		}

		// Gets the last remaining pointer, but throws a std::runtime_error with a user-defined message if the pool doesn't contain exactly one pointer
		template <typename T = std::uintptr_t>
		[[nodiscard]] T expect(const std::string& tooFew, const std::string& tooMany) const
		{
			Result optional = finalize();

			if (!optional.found)
				throw std::runtime_error{ optional.count == 0 ? tooFew : tooMany };

			if constexpr (std::is_pointer_v<T>)
				return reinterpret_cast<T>(reinterpret_cast<void*>(optional.pointer));
			else
				return T(optional.pointer);
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
	[[nodiscard]] inline Session<MemMgr> pointerList(MemMgr& memoryManager, const std::ranges::range auto& pointers)
	{
		return Session{ memoryManager, pointers };
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointer(MemMgr& memoryManager, std::uintptr_t pointer)
	{
		return pointerList(memoryManager, std::initializer_list<std::uintptr_t>{ pointer });
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> pointerArray(MemMgr& memoryManager, std::uintptr_t array, std::size_t index) // e.g. Virtual function tables
	{
		return { memoryManager, SafePointer(&memoryManager, array).dereference().add(index * sizeof(std::uintptr_t)).dereference() };
	}

	template <typename MemMgr>
		requires MemoryManager::LayoutAware<MemMgr> && MemoryManager::AddressAware<typename MemMgr::RegionT> && MemoryManager::NameAware<typename MemMgr::RegionT> && MemoryManager::FlagAware<typename MemMgr::RegionT>
	[[nodiscard]] inline Session<MemMgr> regions(
		MemMgr& memoryManager,
		const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
	{
		std::vector<std::uintptr_t> bases;
		for (const auto& region : memoryManager.getLayout())
			if (searchConstraints.allowsRegion(region))
				bases.push_back(region.getAddress());
		return pointerList(memoryManager, bases);
	}

	template <typename MemMgr>
		requires MemoryManager::Iterable<typename MemMgr::RegionT>
	[[nodiscard]] inline Session<MemMgr> signature(
		MemMgr& memoryManager,
		const std::derived_from<SignatureScanner::Signature> auto& signature,
		const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
	{
		std::vector<std::uintptr_t> pointers{};

		for (const auto& region : memoryManager.getLayout()) {
			if (!searchConstraints.allowsRegion(region))
				continue;

			auto begin = region.cbegin();
			auto end = region.cend();

			searchConstraints.clampToAddressRange(begin, end);

			signature.all(begin, end, std::back_inserter(pointers));
		}

		return { memoryManager, pointers };
	}

	template <typename MemMgr>
	[[nodiscard]] inline Session<MemMgr> signature(
		MemMgr& memoryManager,
		detail::ConvertableToPatternSignature auto&& s,
		const SearchConstraints<typename MemMgr::RegionT>& searchConstraints = everything<MemMgr>().thatsReadable())
	{
		return signature(memoryManager, SignatureScanner::PatternSignature{ std::forward<std::remove_reference_t<decltype(s)>>(s) }, searchConstraints);
	}
}

#endif
