#ifndef BCRL_HPP
#define BCRL_HPP

#include <optional>
#include <map>
#include <cstdint>
#include <string>
#include <cstring>
#include <vector>
#include <unordered_set>
#include <functional>

namespace BCRL {
	inline class MemoryRegionStorage {
	public:
		struct MemoryRegion {
			std::uintptr_t begin;
			size_t length;
			bool executable;
			std::optional<std::string> name;
		};

	private:
		std::map<std::uintptr_t /*begin address*/, MemoryRegion> memoryRegions{};

	public:
		MemoryRegionStorage();
		bool update(); // To update memory regions call this (for example on dlopen/dlclose calls)

		[[nodiscard]] const std::map<std::uintptr_t /*begin address*/, MemoryRegion>& getMemoryRegions() const;
		[[nodiscard]] std::optional<std::reference_wrapper<const MemoryRegion>> addressRegion(std::uintptr_t address) const;

	} memoryRegionStorage;

	class SafePointer { // A pointer which can't cause read access violations
		std::uintptr_t pointer;
		bool invalid; // Set to true, when an operation failed

	public:
		SafePointer() = delete;
		inline explicit SafePointer(void* pointer, bool invalid = false)
			: pointer(reinterpret_cast<std::uintptr_t>(pointer))
			, invalid(invalid)
		{
		}
		inline explicit SafePointer(std::uintptr_t pointer, bool invalid = false)
			: pointer(pointer)
			, invalid(invalid)
		{
		}

		[[nodiscard]] bool isValid(std::size_t length = 1) const;

		[[nodiscard]] inline bool read(void* to, size_t len) const
		{
			if (isValid(len)) {
				std::memcpy(to, reinterpret_cast<const void*>(pointer), len);
				return true;
			}
			return false;
		}

		template <typename T> requires std::is_trivially_copyable_v<T>
		[[nodiscard]] inline std::optional<T> read() const
		{
			T obj;
			if(read(&obj, sizeof(T)))
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

		SafePointer& invalidate(); // Marks safe pointer as invalid
		SafePointer& revalidate(); // Marks safe pointer as valid

		// Manipulation
		SafePointer& add(std::size_t operand); // Advances all pointers forward
		SafePointer& sub(std::size_t operand); // Inverse of above
		SafePointer& dereference(); // Follows a pointer

		// X86
#if defined(__x86_64) || defined(i386)
		SafePointer& relativeToAbsolute(); // Follows down a relative offset

		SafePointer& prevInstruction(); // WARNING: X86 can't be disassembled backwards properly, use with caution
		SafePointer& nextInstruction(); // Skips the current X86 instruction

		[[nodiscard]] std::vector<SafePointer> findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] std::vector<SafePointer> findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const; // Same as above but limited to a single module
#endif
		// Signatures
		SafePointer& prevByteOccurrence(const std::string& signature, char wildcard = '?', std::optional<bool> code = std::nullopt); // Last occurrence of signature
		SafePointer& nextByteOccurrence(const std::string& signature, char wildcard = '?', std::optional<bool> code = std::nullopt); // Next occurrence of signature
		[[nodiscard]] bool doesMatch(const std::string& signature, char wildcard = '?') const; // Tests if the given signature matches the current address

		// Strings
		SafePointer& prevStringOccurrence(const std::string& string, std::optional<char> wildcard = std::nullopt); // Prev occurrence of string
		SafePointer& nextStringOccurrence(const std::string& string, std::optional<char> wildcard = std::nullopt); // Next occurrence of string

		// Filters
		[[nodiscard]] bool isInModule(const std::string& moduleName) const;

		inline std::strong_ordering operator<=>(const SafePointer& other) const
		{

			return pointer <=> other.pointer;
		}

		inline bool operator==(const SafePointer& other) const
		{
			return pointer == other.pointer;
		}

		[[nodiscard]] inline std::uintptr_t getPointer() const
		{
			return pointer;
		};
	};

	class Session {
		std::vector<SafePointer> pointers;

		bool safe; // Are we using safety measures?

		inline Session(std::vector<SafePointer>&& pointers, bool safe)
			: pointers(std::move(pointers))
			, safe(safe)
		{
		}
		template <typename Container>
		inline Session(const Container& pointers, bool safe)
			: pointers()
			, safe(safe)
		{
			this->pointers.reserve(pointers.size());
			for (auto pointer : pointers) {
				this->pointers.emplace_back(pointer);
			}
		}
		inline Session(std::uintptr_t pointer, bool safe)
			: pointers({ SafePointer(pointer) })
			, safe(safe)
		{
		}
		inline explicit Session(bool safe = true)
			: pointers()
			, safe(safe)
		{
		}

	public:
		Session() = delete;

		// Openers
		[[nodiscard]] static Session signature(const std::string& signature, char wildcard = '?', std::optional<bool> code = std::nullopt);
		[[nodiscard]] static Session module(const std::string& moduleName);
		[[nodiscard]] static Session string(const std::string& string, std::optional<char> wildcard = std::nullopt);
		[[nodiscard]] static Session pointerList(const std::vector<void*>& pointers);
		[[nodiscard]] static Session pointer(void* pointer);
		[[nodiscard]] static Session pointerArray(void* array, std::size_t index); // e.g. Virtual function tables

		// Manipulation
		Session& add(std::size_t operand); // Advances all pointers forward
		Session& sub(std::size_t operand); // Inverse of above
		Session& dereference(); // Follows a pointer

		// Safety
		Session& setSafety(bool newSafeness);
		[[nodiscard]] bool isSafe() const;
		Session& toggleSafety();

		// X86
#if defined(__x86_64) || defined(i386)
		Session& relativeToAbsolute(); // Follows down a relative offset

		Session& prevInstruction(); // WARNING: X86 can't be disassembled backwards properly, use with caution
		Session& nextInstruction(); // Skips the current X86 instruction

		Session& findXREFs(bool relative = true, bool absolute = true); // Since there can be multiple xrefs, this can increase the amount of addresses
		Session& findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true); // Same as above but limited to a single module
#endif
		// Signatures
		Session& prevByteOccurrence(const std::string& signature, char wildcard = '?', std::optional<bool> code = std::nullopt); // Prev occurrence of signature
		Session& nextByteOccurrence(const std::string& signature, char wildcard = '?', std::optional<bool> code = std::nullopt); // Next occurrence of signature

		// Strings
		Session& prevStringOccurrence(const std::string& string, std::optional<char> wildcard = std::nullopt); // Prev occurrence of string
		Session& nextStringOccurrence(const std::string& string, std::optional<char> wildcard = std::nullopt); // Next occurrence of string

		// Filters
		Session& filterModule(const std::string& moduleName);

		// Advanced Flow
		Session& purgeInvalid(std::size_t length = 1); // Will purge all pointers, which can't be dereferenced (Useful when using unsafe mode)
		Session& forEach(const std::function<void(SafePointer&)>& body); // Calls action on each pointer
		Session& repeater(const std::function<bool(SafePointer&)>& action); // Repeats action until false is returned
		Session& repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action); // Repeats action `iterations` times
		Session& filter(const std::function<bool(const SafePointer&)>& predicate); // Filters out non-conforming pointers
		Session& flatMap(const std::function<std::vector<SafePointer>(const SafePointer&)>& transformer); // Maps pointer to other pointers

		// Finalizing
		[[nodiscard]] std::size_t size() const; // Returns size of remaining pointers
		[[nodiscard]] std::vector<void*> getPointers() const; // Returns all remaining pointers
		[[nodiscard]] std::optional<void*> getPointer() const; // Will return std::nullopt if there are no/multiple pointers available
		[[nodiscard]] void* expect(const std::string& message) const; // Same as getPointer, but throws a std::runtime_error if not present

		// Automatic casts
		template <typename T>
		[[nodiscard]] std::optional<T> getPointer() const {
			if(auto opt = getPointer(); opt.has_value())
				return std::optional<T>{ T(opt.value()) };
			return std::nullopt;
		}
		template <typename T>
		[[nodiscard]] T expect(const std::string& message) const {
			return T(expect(message));
		}
	};
}

#endif
