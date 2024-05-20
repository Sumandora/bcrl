#ifndef BCRL_HPP
#define BCRL_HPP

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>
#include <ranges>
#include <iterator>

#include "MemoryManager/MemoryManager.hpp"
#include "SignatureScanner/PatternSignature.hpp"

namespace BCRL {
	namespace detail {
		template<typename T>
		struct LambdaInserter {
			std::function<void(T)> callback;

			constexpr explicit LambdaInserter(std::function<void(T)> callback)
				: callback(std::move(callback))
			{
			}

			constexpr LambdaInserter& operator=(const T& obj) {
				callback(obj);
				return *this;
			}

			constexpr LambdaInserter& operator*() {
				return *this;
			}

			constexpr LambdaInserter& operator+() {
				return *this;
			}

			constexpr LambdaInserter& operator+(int) {
				return *this;
			}
		};
	}

	class SafePointer { // A pointer which can't cause read access violations
		const MemoryManager::MemoryManager* memoryManager;
		std::uintptr_t pointer;
		bool invalid; // Set to true, when an operation failed

	public:
		SafePointer() = delete;
		inline explicit SafePointer(const MemoryManager::MemoryManager* memoryManager, void* pointer, bool invalid = false)
			: memoryManager(memoryManager)
			, pointer(reinterpret_cast<std::uintptr_t>(pointer))
			, invalid(invalid)
		{
		}
		inline explicit SafePointer(const MemoryManager::MemoryManager* memoryManager, std::uintptr_t pointer, bool invalid = false)
			: memoryManager(memoryManager)
			, pointer(pointer)
			, invalid(invalid)
		{
		}

		[[nodiscard]] bool isValid(std::size_t length = 1) const
		{
			if (invalid)
				return false; // It was already eliminated

			auto region = memoryManager->getLayout().findRegion(pointer);
			if (!region || !region->getFlags().isReadable())
				return false;
			for (std::size_t i = 0; i < length; i++) {
				std::uintptr_t p = pointer + i;
				if (region->isInside(p))
					continue;
				region = memoryManager->getLayout().findRegion(p);
				if (!region || !region->getFlags().isReadable())
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

		SafePointer& invalidate()  // Marks safe pointer as invalid
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
		SafePointer& add(std::size_t operand) // Advances all pointers forward
		{
			pointer += operand;
			return *this;
		}
		SafePointer& sub(std::size_t operand) // Inverse of above
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
			} else
				return invalidate();
		}

		// Signatures
		// Prev occurrence of signature
		template <typename DerivedSignature> requires std::is_base_of_v<SignatureScanner::Signature, DerivedSignature>
		SafePointer& prevSignatureOccurrence(const DerivedSignature& signature, std::optional<bool> executable = std::nullopt)
		{
			for (const auto& region : memoryManager->getLayout() | std::ranges::views::reverse) {
				if (region.getBeginAddress() >= pointer)
					continue;

				if (!region.getFlags().isReadable() || region.isSpecial())
					continue;

				if (!executable.has_value() || region.getFlags().isExecutable() == executable)
					continue;

				auto search = [&](auto begin, auto end) {
					while(begin != reinterpret_cast<std::byte*>(pointer))
						begin++;

					auto hit = signature.prev(begin, end());
					return hit;
				};

				if(memoryManager->isRemoteAddressSpace()) {
					auto& cache = region.cache();
					auto hit = search(cache->crbegin(), cache->crend());

					if (!hit.has_value())
						continue;

					pointer = hit.value();
					return revalidate();
				} else {
					std::span<std::byte> b{ reinterpret_cast<std::byte*>(region.getBeginAddress()), reinterpret_cast<std::byte*>(region.getEndAddress())};
					auto hit = search(b.crbegin(), b.crend());

					if (!hit.has_value())
						continue;

					pointer = hit.value();
					return revalidate();
				}
			}

			return invalidate();
		}

		// Next occurrence of signature
		template <typename DerivedSignature> requires std::is_base_of_v<SignatureScanner::Signature, DerivedSignature>
		SafePointer& nextSignatureOccurrence(const DerivedSignature& signature, std::optional<bool> executable = std::nullopt)
		{
			for (const auto& region : memoryManager->getLayout()) {
				if (region.getEndAddress() <= pointer)
					continue;

				if (!region.getFlags().isReadable() || region.isSpecial())
					continue;

				if (!executable.has_value() || region.getFlags().isExecutable() == executable)
					continue;

				auto search = [&](auto begin, auto end) {
					while(begin != reinterpret_cast<std::byte*>(pointer))
						begin++;

					auto hit = signature.next(begin, end());
					return hit;
				};

				if(memoryManager->isRemoteAddressSpace()) {
					auto& cache = region.cache();
					auto hit = search(cache->crbegin(), cache->crend());

					if (!hit.has_value())
						continue;

					pointer = hit.value();
					return revalidate();
				} else {
					std::span<std::byte> b{ reinterpret_cast<std::byte*>(region.getBeginAddress()), reinterpret_cast<std::byte*>(region.getEndAddress())};
					auto hit = search(b.crbegin(), b.crend());

					if (!hit.has_value())
						continue;

					pointer = hit.value();
					return revalidate();
				}
			}

			return invalidate();
		}

		// Tests if the given pattern signature matches the current address
		template <std::size_t N>
		bool doesMatch(const SignatureScanner::PatternSignature<N>& signature) const
		{
			if (isValid(signature.getElements().size()))
				return signature.doesMatch(pointer);
			return false;
		}

		// Tests if the given signature matches the current address (WARNING: Unsafe as generic signatures don't expose any length)
		template <typename DerivedSignature> requires std::is_base_of_v<SignatureScanner::Signature, DerivedSignature>
		bool doesMatch(const DerivedSignature& signature) const
		{
			auto region = memoryManager->getLayout().findRegion(pointer);
			if(!region)
				return false;

			if(memoryManager->isRemoteAddressSpace()) {
				auto& cache = region->cache();
				auto begin = cache->cbegin();
				while(begin < reinterpret_cast<std::byte*>(pointer))
					begin++;

				return signature.doesMatch(begin, cache->cend());
			} else {
				return signature.doesMatch(reinterpret_cast<std::byte*>(getPointer()), reinterpret_cast<std::byte*>(region->getEndAddress()));
			}
		}

		// For addons:
		template<typename F>
		SafePointer& invoke(F&& func) requires std::is_invocable_v<F, decltype(*this)> {
			if constexpr(std::is_same_v<std::invoke_result_t<F>, SafePointer&>)
				return func(*this);
			else {
				func(*this);
				return *this;
			}
		}

		// Filters
		[[nodiscard]] bool isInModule(const std::string& moduleName) const
		{
			auto module = memoryManager->getLayout().findRegion(pointer);
			return module && module->getName()->ends_with(moduleName);
		}

		constexpr std::strong_ordering operator<=>(const SafePointer& other) const
		{
			return pointer <=> other.pointer;
		}

		constexpr bool operator==(const SafePointer& other) const
		{
			return pointer == other.pointer;
		}

		[[nodiscard]] constexpr const MemoryManager::MemoryManager* getMemoryManager() const {
			return memoryManager;
		}

		[[nodiscard]] constexpr std::uintptr_t getPointer() const
		{
			return pointer;
		};
	};

	class Session {
		const MemoryManager::MemoryManager& memoryManager;
		std::vector<SafePointer> pointers;

		bool safe; // Are we using safety measures?

		constexpr Session(const MemoryManager::MemoryManager& memoryManager, std::vector<SafePointer>&& pointers, bool safe)
			: memoryManager(memoryManager)
			, pointers(std::move(pointers))
			, safe(safe)
		{
		}
		template <typename Container>
		constexpr Session(const MemoryManager::MemoryManager& memoryManager, const Container& pointers, bool safe)
			: memoryManager(memoryManager)
			, pointers()
			, safe(safe)
		{
			this->pointers.reserve(pointers.size());
			for (auto pointer : pointers) {
				this->pointers.emplace_back(&memoryManager, pointer);
			}
		}

	public:
		[[nodiscard]] static Session module(const MemoryManager::MemoryManager& memoryManager, const std::string& moduleName)
		{
			std::uintptr_t lowest = 0;
			for (const auto& region : memoryManager.getLayout())
				if(region.getName().has_value() && region.getName()->ends_with(moduleName))
					if(lowest == 0 || lowest > region.getBeginAddress())
						lowest = region.getBeginAddress();
			if (lowest == 0)
				return Session{ memoryManager, {}, true };
			return pointer(memoryManager, reinterpret_cast<void*>(lowest));
		}

		template<typename DerivedSignature> requires std::is_base_of_v<SignatureScanner::Signature, DerivedSignature>
		[[nodiscard]] static Session signature(const MemoryManager::MemoryManager& memoryManager, const DerivedSignature& signature, std::optional<bool> executable = std::nullopt) {
			std::vector<std::byte*> pointers{};

			for (const auto& region : memoryManager.getLayout()) {
				if (!region.getFlags().isReadable() || region.isSpecial())
					continue;

				if (executable.has_value() && region.getFlags().isExecutable() != executable)
					continue;

				if(memoryManager.isRemoteAddressSpace()) {
					auto& cache = region.cache();
					signature.all(cache->cbegin(), cache->cend(), detail::LambdaInserter<MemoryManager::CachedRegion::CacheIterator>([&](MemoryManager::CachedRegion::CacheIterator match) {
						pointers.push_back(&*match);
					}));
				} else {
					signature.all(reinterpret_cast<std::byte*>(region.getBeginAddress()), reinterpret_cast<std::byte*>(region.getEndAddress()), detail::LambdaInserter<std::byte*>([&](std::byte* match) {
						pointers.push_back(match);
					}));
				}
			}

			return { memoryManager, pointers, true };
		}

		template<typename Container>
		[[nodiscard]] static Session pointerList(const MemoryManager::MemoryManager& memoryManager, const Container& pointers) {
			return Session{ memoryManager, pointers, true };
		}

		[[nodiscard]] static Session pointer(const MemoryManager::MemoryManager& memoryManager, void* pointer)
		{
			return Session{ memoryManager, std::initializer_list<std::uintptr_t>{ reinterpret_cast<std::uintptr_t>(pointer) }, true };
		}

		[[nodiscard]] static Session pointerArray(const MemoryManager::MemoryManager& memoryManager, void* array, std::size_t index) // e.g. Virtual function tables
		{
			return { memoryManager, { SafePointer(&memoryManager, array).dereference().add(index * sizeof(void*)).dereference() }, true };
		}

		Session() = delete;

		// Manipulation
		Session& add(std::size_t operand) // Advances all pointers forward
		{
			return forEach([operand](SafePointer& safePointer) {
				safePointer.add(operand);
			});
		}
		Session& sub(std::size_t operand) // Inverse of above
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

		// Safety
		Session& setSafety(bool newSafeness)
		{
			safe = newSafeness;
			return *this;
		}
		[[nodiscard]] bool isSafe() const { return safe; }
		Session& toggleSafety()
		{
			safe = !safe;
			return *this;
		}

		// Signatures
		// Prev occurrence of signature
		template <typename DerivedSignature> requires std::is_base_of_v<SignatureScanner::Signature, DerivedSignature>
		Session& prevSignatureOccurrence(const DerivedSignature& signature, std::optional<bool> executable = std::nullopt)
		{
			return forEach([&signature, executable](SafePointer& safePointer) {
				safePointer.prevSignatureOccurrence(signature, executable);
			});
		}

		// Next occurrence of signature
		template <typename DerivedSignature> requires std::is_base_of_v<SignatureScanner::Signature, DerivedSignature>
		Session& nextSignatureOccurrence(const DerivedSignature& signature, std::optional<bool> executable = std::nullopt)
		{
			return forEach([&signature, executable](SafePointer& safePointer) {
				safePointer.nextSignatureOccurrence(signature, executable);
			});
		}

		// Filters
		Session& filterModule(const std::string& moduleName)
		{
			return filter([&moduleName](const SafePointer& safePointer) {
				return safePointer.isInModule(moduleName);
			});
		}

		// Advanced Flow
		Session& purgeInvalid(std::size_t length = 1) // Will purge all pointers, which can't be dereferenced (Useful when using unsafe mode)
		{
			return forEach([length](SafePointer& safePointer) {
				if (!safePointer.isValid(length))
					safePointer.invalidate();
			});
		}
		Session& forEach(const std::function<void(SafePointer&)>& body) // Calls action on each pointer
		{
			// This looks a bit scuffed, but I'm pretty sure it is the most memory-efficient way of doing it
			std::erase_if(pointers, [this, body](SafePointer& safePointer) {
				body(safePointer);
				return isSafe() && !safePointer.isValid();
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
				for(SafePointer& newSafePointer : transformed) {
					if(isSafe() && !newSafePointer.isValid())
						continue;

					newSafePointers.emplace_back(newSafePointer);
				}
			}
			pointers = std::move(newSafePointers);
			return *this;
		}

		// Finalizing
		struct Finalization {
			std::uintptr_t value; // If `found == true` contains the remaining pointer, if `found == false` contains amount of remaining elements
			bool found; // If there was only one remaining pointer
		};

		[[nodiscard]] const std::vector<SafePointer>& peek() const // Allows to peek at all remaining pointers
		{
			return pointers;
		}
		[[nodiscard]] Finalization finalize() const // Will return a Finalization struct if there are no/multiple pointers available
		{
			if (pointers.size() == 1)
				return { pointers.begin()->getPointer(), true };

			return Finalization{ pointers.size(), false };
		}
		[[nodiscard]] std::uintptr_t expect(const std::string& tooFew, const std::string& tooMany) const // Calls finalize, but throws a std::runtime_error if it wasn't found
		{
			Session::Finalization optional = finalize();

			if (optional.found)
				return optional.value;

			throw std::runtime_error(optional.value == 0 ? tooFew : tooMany);
		}
		[[nodiscard]] std::uintptr_t expect(const std::string& message) const // Calls expect with tooFew and tooMany both set to message
		{
			return expect(message, message);
		}

		// Automatic casts
		template <typename T>
		[[nodiscard]] T expect(const std::string& tooFew, const std::string& tooMany) const {
			return T(expect(tooFew, tooMany));
		}
		template <typename T>
		[[nodiscard]] T expect(const std::string& message) const {
			return T(expect(message));
		}
	};
}

#endif
