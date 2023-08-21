#ifndef BCRL_HPP
#define BCRL_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
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

		std::vector<MemoryRegion> getMemoryRegions(
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

		bool isValid(std::size_t length = 1) const;

		template <typename T>
		inline std::optional<T> read() const
		{
			if (isValid(sizeof(T*)))
				return *(T*)pointer;
			return std::nullopt;
		}

		template <typename T>
		inline bool equals(T operand) const
		{
			std::optional<T> object = read<T>();
			if (object.has_value())
				return object.value() == operand;
			return false;
		}

		SafePointer invalidate() const;

		// Manipulation
		SafePointer add(std::size_t operand) const;
		SafePointer sub(std::size_t operand) const;
		SafePointer dereference() const;

		// Safety
		inline SafePointer setSafe(bool safe) const { return { this->pointer, isSafe() }; }
		inline bool isSafe() const { return safe; }
		inline SafePointer toggleSafety() const { return { this->pointer, !isSafe() }; }

		// X86
#if defined(__x86_64) || defined(i386)
		SafePointer relativeToAbsolute() const;

		SafePointer prevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		SafePointer nextInstruction() const;

		std::vector<SafePointer> findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		std::vector<SafePointer> findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const;
#endif
		// Signatures
		SafePointer prevByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Last occurence of signature
		SafePointer nextByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Next occurence of signature
		bool doesMatch(const std::string& signature) const; // Tests if the given signature matches the current address

		// Strings
		SafePointer prevStringOccurence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Prev occurence of string
		SafePointer nextStringOccurence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Next occurence of string

		inline std::strong_ordering operator<=>(const SafePointer& other) const
		{

			return reinterpret_cast<std::uintptr_t>(pointer) <=> reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		inline bool operator==(const SafePointer& other) const
		{
			return reinterpret_cast<std::uintptr_t>(pointer) == reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		inline void* getPointer() const
		{
			return pointer;
		};
	};

	class Session {
		std::vector<SafePointer> pointers{};

		bool safe; // Are we using safety measures?

		inline Session(std::vector<SafePointer> pointers, bool safe)
			: pointers(pointers)
			, safe(safe)
		{
			for (SafePointer& pointer : this->pointers) {
				pointer = pointer.setSafe(safe);
			}
		}
		inline Session(std::vector<void*> pointers, bool safe)
			: pointers({})
			, safe(safe)
		{
			for (void* pointer : pointers) {
				this->pointers.push_back({ pointer, safe });
			}
		}
		inline Session(void* pointer, bool safe)
			: pointers({})
			, safe(safe)
		{
			pointers.push_back({ pointer, safe });
		}

	public:
		Session() = delete;

		// Openers
		static Session signature(const char* signature, std::optional<bool> code = std::nullopt);
		static Session module(const char* moduleName);
		static Session string(const char* string);
		static Session pointerList(std::vector<void*> pointers);
		static Session pointer(void* pointer);
		static Session arrayPointer(void* pointerArray, std::size_t index); // e.g. Virtual function tables

		// Manipulation
		Session add(std::size_t operand);
		Session sub(std::size_t operand);
		Session dereference();

		// Safety
		Session setSafe(bool safe);
		inline bool isSafe() { return safe; }
		Session toggleSafety();

		// X86
#if defined(__x86_64) || defined(i386)
		Session relativeToAbsolute();

		Session prevInstruction(); // WARNING: X86 can't be disassembled backwards properly, use with caution
		Session nextInstruction();

		Session findXREFs(bool relative = true, bool absolute = true); // Since there can be multiple xrefs, this can increase the amount of addresses
		Session findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true);
#endif
		// Signatures
		Session prevByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt); // Prev occurence of signature
		Session nextByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt); // Next occurence of signature

		// Strings
		Session prevStringOccurence(const std::string& string); // Prev occurence of string
		Session nextStringOccurence(const std::string& string); // Next occurence of string

		// Advanced Flow
		Session purgeInvalid(std::size_t length = 1); // Will purge all pointers, which can't be dereferenced
		Session forEach(std::function<void(SafePointer&)> action);
		Session repeater(std::function<bool(SafePointer&)> action); // Repeats action until false is returned
		Session repeater(std::size_t iterations, std::function<void(SafePointer&)> action); // Repeats action `iterations` times
		Session filter(std::function<bool(SafePointer)> predicate); // Filters out non-conforming pointers
		Session map(std::function<std::optional<SafePointer>(SafePointer)> transformer, bool purgeInvalid = true); // Maps pointer to other pointer (nullopts will be removed)
		Session map(std::function<std::vector<SafePointer>(SafePointer)> transformer, bool purgeInvalid = true); // Maps pointer to other pointers (nullopts will be removed)

		// Finalizing
		inline std::size_t size() { return pointers.size(); }
		std::vector<void*> getPointers();
		std::optional<void*> choose(std::function<bool(SafePointer)> predicate); // Returns the first chosen pointer
		std::optional<void*> getPointer(); // Will return std::nullopt if there are no/multiple pointers available
	};
}

#endif
