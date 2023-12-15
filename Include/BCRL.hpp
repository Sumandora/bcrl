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

		template <typename T> requires std::is_trivially_copyable_v<T>
		[[nodiscard]] inline std::optional<T> read() const
		{
			if (isValid(sizeof(T*))) {
				T obj;
				std::memcpy(&obj, reinterpret_cast<const void*>(pointer), sizeof(T));
				return obj;
			}
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

		[[nodiscard]] SafePointer invalidate() const; // Marks safe pointer as invalid
		[[nodiscard]] SafePointer revalidate() const; // Marks safe pointer as valid

		// Manipulation
		[[nodiscard]] SafePointer add(std::size_t operand) const; // Advances all pointers forward
		[[nodiscard]] SafePointer sub(std::size_t operand) const; // Inverse of above
		[[nodiscard]] SafePointer dereference() const; // Follows a pointer

		// X86
#if defined(__x86_64) || defined(i386)
		[[nodiscard]] SafePointer relativeToAbsolute() const; // Follows down a relative offset

		[[nodiscard]] SafePointer prevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		[[nodiscard]] SafePointer nextInstruction() const; // Skips the current X86 instruction

		[[nodiscard]] std::vector<SafePointer> findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] std::vector<SafePointer> findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const; // Same as above but limited to a single module
#endif
		// Signatures
		[[nodiscard]] SafePointer prevByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Last occurrence of signature
		[[nodiscard]] SafePointer nextByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Next occurrence of signature
		[[nodiscard]] bool doesMatch(const std::string& signature) const; // Tests if the given signature matches the current address

		// Strings
		[[nodiscard]] SafePointer prevStringOccurrence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Prev occurrence of string
		[[nodiscard]] SafePointer nextStringOccurrence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Next occurrence of string

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

		struct Hash {
			inline std::size_t operator()(const SafePointer& s) const noexcept
			{
				return std::hash<decltype(s.pointer)>{}(s.pointer);
			}
		};
	};

	class Session {
		std::unordered_set<SafePointer, SafePointer::Hash> pointers{};

		bool safe; // Are we using safety measures?

		inline Session(std::unordered_set<SafePointer, SafePointer::Hash>&& pointers, bool safe)
			: pointers(std::move(pointers))
			, safe(safe)
		{
		}
		template <typename Container>
		inline Session(const Container& pointers, bool safe)
			: pointers()
			, safe(safe)
		{
			for (auto pointer : pointers) {
				this->pointers.emplace(pointer);
			}
		}
		inline Session(std::uintptr_t pointer, bool safe)
			: pointers()
			, safe(safe)
		{
			pointers.emplace(pointer);
		}
		inline explicit Session(bool safe)
			: pointers()
			, safe(safe)
		{
		}

	public:
		Session() = delete;

		// Openers
		[[nodiscard]] static Session signature(const char* signature, std::optional<bool> code = std::nullopt);
		[[nodiscard]] static Session module(const char* moduleName);
		[[nodiscard]] static Session string(const char* string);
		[[nodiscard]] static Session pointerList(const std::vector<void*>& pointers);
		[[nodiscard]] static Session pointer(void* pointer);
		[[nodiscard]] static Session pointerArray(void* array, std::size_t index); // e.g. Virtual function tables

		// Manipulation
		[[nodiscard]] Session add(std::size_t operand) const; // Advances all pointers forward
		[[nodiscard]] Session sub(std::size_t operand) const; // Inverse of above
		[[nodiscard]] Session dereference() const; // Follows a pointer

		// Safety
		[[nodiscard]] Session setSafety(bool newSafeness) const;
		[[nodiscard]] bool isSafe() const;
		[[nodiscard]] Session toggleSafety() const;

		// X86
#if defined(__x86_64) || defined(i386)
		[[nodiscard]] Session relativeToAbsolute() const; // Follows down a relative offset

		[[nodiscard]] Session prevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		[[nodiscard]] Session nextInstruction() const; // Skips the current X86 instruction

		[[nodiscard]] Session findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] Session findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const; // Same as above but limited to a single module
#endif
		// Signatures
		[[nodiscard]] Session prevByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Prev occurrence of signature
		[[nodiscard]] Session nextByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Next occurrence of signature

		// Strings
		[[nodiscard]] Session prevStringOccurrence(const std::string& string) const; // Prev occurrence of string
		[[nodiscard]] Session nextStringOccurrence(const std::string& string) const; // Next occurrence of string

		// Advanced Flow
		[[nodiscard]] Session purgeInvalid(std::size_t length = 1) const; // Will purge all pointers, which can't be dereferenced (Useful when using unsafe mode)
		[[nodiscard]] Session forEach(const std::function<void(SafePointer&)>& action) const; // Calls action on each pointer
		[[nodiscard]] Session repeater(const std::function<bool(SafePointer&)>& action) const; // Repeats action until false is returned
		[[nodiscard]] Session repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action) const; // Repeats action `iterations` times
		[[nodiscard]] Session filter(const std::function<bool(const SafePointer&)>& predicate) const; // Filters out non-conforming pointers
		[[nodiscard]] Session map(const std::function<SafePointer(const SafePointer&)>& transformer) const; // Maps pointer to other pointer
		[[nodiscard]] Session flatMap(const std::function<std::vector<SafePointer>(const SafePointer&)>& transformer) const; // Maps pointer to other pointers

		// Finalizing
		[[nodiscard]] inline std::size_t size() const; // Returns size of remaining pointers
		[[nodiscard]] std::vector<void*> getPointers() const; // Returns all remaining pointers
		[[nodiscard]] std::optional<void*> getPointer() const; // Will return std::nullopt if there are no/multiple pointers available
		[[nodiscard]] void* expect(const std::string& message) const; // Same as getPointer, but throws a std::runtime_error if not present
	};
}

#endif
