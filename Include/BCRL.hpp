#ifndef BCRL_HPP
#define BCRL_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace BCRL {
	inline class MemoryRegionStorage {
	public:
		struct MemoryRegion {
			std::span<std::byte> addressSpace;
			bool writable, executable;
			std::optional<std::string> name;
		};

	private:
		std::vector<MemoryRegion> memoryRegions{};

	public:
		MemoryRegionStorage();
		bool update(); // To update memory regions call this (for example on dlopen/dlclose calls)

		[[nodiscard]] std::vector<MemoryRegion> getMemoryRegions(
			std::optional<bool> writable = std::nullopt,
			std::optional<bool> executable = std::nullopt,
			std::optional<std::string> name = std::nullopt) const;
		const MemoryRegion* addressRegion(void* address) const;

	} memoryRegionStorage;

	class SafePointer { // A pointer which can't cause read access violations
		void* pointer;
		bool invalid = false; // Set to true, when a operation failed
		bool safe;

	public:
		SafePointer() = delete;
		inline SafePointer(void* pointer, bool safe)
			: pointer(pointer)
			, safe(safe)
		{
		}
		inline SafePointer(std::uintptr_t pointer, bool safe)
			: pointer(reinterpret_cast<void*>(pointer))
			, safe(safe)
		{
		}
		inline SafePointer(const SafePointer& other, bool safe)
			: pointer(other.pointer)
			, safe(safe)
		{
		}

		[[nodiscard]] bool isValid(std::size_t length = 1) const;

		template <typename T>
		[[nodiscard]] inline std::optional<T> read() const
		{
			if (isValid(sizeof(T*)))
				return *(T*)pointer;
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

		[[nodiscard]] SafePointer invalidate() const;

		// Manipulation
		[[nodiscard]] SafePointer add(std::size_t operand) const;
		[[nodiscard]] SafePointer sub(std::size_t operand) const;
		[[nodiscard]] SafePointer dereference() const;

		// Safety
		[[nodiscard]] inline SafePointer setSafe(bool safe) const { return { this->pointer, safe }; }
		[[nodiscard]] inline bool isSafe() const { return safe; }
		[[nodiscard]] inline SafePointer toggleSafety() const { return { this->pointer, !isSafe() }; }

		// X86
#if defined(__x86_64) || defined(i386)
		[[nodiscard]] SafePointer relativeToAbsolute() const;

		[[nodiscard]] SafePointer prevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		[[nodiscard]] SafePointer nextInstruction() const;

		[[nodiscard]] std::vector<SafePointer> findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] std::vector<SafePointer> findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const;
#endif
		// Signatures
		[[nodiscard]] SafePointer prevByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Last occurence of signature
		[[nodiscard]] SafePointer nextByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Next occurence of signature
		[[nodiscard]] bool doesMatch(const std::string& signature) const; // Tests if the given signature matches the current address

		// Strings
		[[nodiscard]] SafePointer prevStringOccurrence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Prev occurence of string
		[[nodiscard]] SafePointer nextStringOccurrence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Next occurence of string

		inline std::strong_ordering operator<=>(const SafePointer& other) const
		{

			return reinterpret_cast<std::uintptr_t>(pointer) <=> reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		inline bool operator==(const SafePointer& other) const
		{
			return reinterpret_cast<std::uintptr_t>(pointer) == reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		[[nodiscard]] inline void* getPointer() const
		{
			return pointer;
		};
	};

	class Session {
		std::vector<SafePointer> pointers{};

		bool safe; // Are we using safety measures?

		inline Session(std::vector<SafePointer> pointers, bool safe)
			: pointers(std::move(pointers))
			, safe(safe)
		{
			for (SafePointer& pointer : this->pointers) {
				pointer = pointer.setSafe(safe);
			}
		}
		inline Session(const std::vector<void*>& pointers, bool safe)
			: pointers({})
			, safe(safe)
		{
			for (void* pointer : pointers) {
				this->pointers.emplace_back(pointer, safe);
			}
		}
		inline Session(void* pointer, bool safe)
			: pointers({})
			, safe(safe)
		{
			pointers.emplace_back(pointer, safe);
		}

	public:
		Session() = delete;

		// Openers
		[[nodiscard]] static Session signature(const char* signature, std::optional<bool> code = std::nullopt);
		[[nodiscard]] static Session module(const char* moduleName);
		[[nodiscard]] static Session string(const char* string);
		[[nodiscard]] static Session pointerList(const std::vector<void*>& pointers);
		[[nodiscard]] static Session pointer(void* pointer);
		[[nodiscard]] static Session arrayPointer(void* pointerArray, std::size_t index); // e.g. Virtual function tables

		// Manipulation
		[[nodiscard]] Session add(std::size_t operand);
		[[nodiscard]] Session sub(std::size_t operand);
		[[nodiscard]] Session dereference();

		// Safety
		[[nodiscard]] Session setSafe(bool safe);
		[[nodiscard]] inline bool isSafe() const { return safe; }
		[[nodiscard]] Session toggleSafety();

		// X86
#if defined(__x86_64) || defined(i386)
		[[nodiscard]] Session relativeToAbsolute();

		[[nodiscard]] Session prevInstruction(); // WARNING: X86 can't be disassembled backwards properly, use with caution
		[[nodiscard]] Session nextInstruction();

		[[nodiscard]] Session findXREFs(bool relative = true, bool absolute = true); // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] Session findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true);
#endif
		// Signatures
		[[nodiscard]] Session prevByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt); // Prev occurence of signature
		[[nodiscard]] Session nextByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt); // Next occurence of signature

		// Strings
		[[nodiscard]] Session prevStringOccurrence(const std::string& string); // Prev occurence of string
		[[nodiscard]] Session nextStringOccurrence(const std::string& string); // Next occurence of string

		// Advanced Flow
		[[nodiscard]] Session purgeDuplicates();
		[[nodiscard]] Session purgeInvalid(std::size_t length = 1); // Will purge all pointers, which can't be dereferenced
		[[nodiscard]] Session forEach(const std::function<void(SafePointer&)>& action);
		[[nodiscard]] Session repeater(const std::function<bool(SafePointer&)>& action); // Repeats action until false is returned
		[[nodiscard]] Session repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action); // Repeats action `iterations` times
		[[nodiscard]] Session filter(const std::function<bool(SafePointer)>& predicate); // Filters out non-conforming pointers
		[[nodiscard]] Session map(const std::function<std::optional<SafePointer>(SafePointer)>& transformer, bool purgeInvalid = true, bool purgeDuplicates = true); // Maps pointer to other pointer (nullopts will be removed)
		[[nodiscard]] Session map(const std::function<std::vector<SafePointer>(SafePointer)>& transformer, bool purgeInvalid = true, bool purgeDuplicates = true); // Maps pointer to other pointers (nullopts will be removed)

		// Finalizing
		[[nodiscard]] inline std::size_t size() { return pointers.size(); }
		[[nodiscard]] std::vector<void*> getPointers();
		[[nodiscard]] std::optional<void*> first(const std::function<bool(SafePointer)>& predicate); // Returns the first chosen pointer
		[[nodiscard]] std::optional<void*> getPointer(); // Will return std::nullopt if there are no/multiple pointers available
	};
}

#endif
