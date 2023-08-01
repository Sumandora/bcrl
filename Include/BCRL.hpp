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
		bool Update(); // To update memory regions call this (for example on dlopen/dlclose calls)

		std::vector<MemoryRegion> GetMemoryRegions(
			std::optional<bool> writable = std::nullopt,
			std::optional<bool> executable = std::nullopt,
			std::optional<std::string> name = std::nullopt) const;
		bool IsAddressReadable(void* address) const;
		const MemoryRegion* AddressRegion(void* address) const;

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

		template <typename T>
		inline std::optional<T> Read() const
		{
			if (IsValid(sizeof(T*)))
				return *(T*)pointer;
			return std::nullopt;
		}

		template <typename T>
		inline bool Equals(T operand) const
		{
			std::optional<T> read = Read<T>();
			if (read.has_value())
				return read.value() == operand;
			return false;
		}

		SafePointer Invalidate() const;

		// Manipulation
		SafePointer Add(std::size_t operand) const;
		SafePointer Sub(std::size_t operand) const;
		SafePointer Dereference() const;

		// Safety
		inline SafePointer SetSafe(bool safe) const { return { this->pointer, IsSafe() }; }
		inline bool IsSafe() const { return safe; }
		inline SafePointer ToggleSafety() const { return { this->pointer, !IsSafe() }; }

		// X86
#if defined(__x86_64) || defined(i386)
		SafePointer RelativeToAbsolute() const;

#ifndef BCLR_DISABLE_LDE
		SafePointer PrevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		SafePointer NextInstruction() const;
#endif
		std::vector<SafePointer> FindXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		std::vector<SafePointer> FindXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const;
#endif
		// Signatures
		SafePointer PrevByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Last occurence of signature
		SafePointer NextByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Next occurence of signature
		bool DoesMatch(const std::string& signature) const; // Tests if the given signature matches the current address

		// Strings
		SafePointer PrevStringOccurence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Prev occurence of string
		SafePointer NextStringOccurence(const std::string& string, std::optional<bool> code = std::nullopt) const; // Next occurence of string

		inline std::strong_ordering operator<=>(const SafePointer& other) const
		{

			return reinterpret_cast<std::uintptr_t>(pointer) <=> reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		inline bool operator==(const SafePointer& other) const
		{
			return reinterpret_cast<std::uintptr_t>(pointer) == reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		bool IsValid(std::size_t length = 1) const;

		inline void* GetPointer() const
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
				pointer = pointer.SetSafe(safe);
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
		static Session Signature(const char* signature, std::optional<bool> code = std::nullopt);
		static Session Module(const char* moduleName);
		static Session String(const char* string);
		static Session PointerList(std::vector<void*> pointers);
		static Session Pointer(void* pointer);
		static Session ArrayPointer(void* pointerArray, std::size_t index); // e.g. Virtual function tables

		// Manipulation
		Session Add(std::size_t operand);
		Session Sub(std::size_t operand);
		Session Dereference();

		// Safety
		Session SetSafe(bool safe);
		inline bool IsSafe() { return safe; }
		Session ToggleSafety();

		// X86
#if defined(__x86_64) || defined(i386)
		Session RelativeToAbsolute();

#ifndef BCLR_DISABLE_LDE
		Session PrevInstruction(); // WARNING: X86 can't be disassembled backwards properly, use with caution
		Session NextInstruction();
#endif
		Session FindXREFs(bool relative = true, bool absolute = true); // Since there can be multiple xrefs, this can increase the amount of addresses
		Session FindXREFs(const std::string& moduleName, bool relative = true, bool absolute = true);
#endif
		// Signatures
		Session PrevByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt); // Prev occurence of signature
		Session NextByteOccurence(const std::string& signature, std::optional<bool> code = std::nullopt); // Next occurence of signature

		// Strings
		Session PrevStringOccurence(const std::string& string); // Prev occurence of string
		Session NextStringOccurence(const std::string& string); // Next occurence of string

		// Advanced Flow
		Session PurgeInvalid(std::size_t length = 1); // Will purge all pointers, which can't be dereferenced
		Session ForEach(std::function<void(SafePointer&)> action);
		Session Repeater(std::function<bool(SafePointer&)> action); // Repeats action until false is returned
		Session Repeater(std::size_t iterations, std::function<void(SafePointer&)> action); // Repeats action `iterations` times
		Session Filter(std::function<bool(SafePointer)> predicate); // Filters out non-conforming pointers
		Session Map(std::function<std::optional<SafePointer>(SafePointer)> transformer, bool purgeInvalid = true); // Maps pointer to other pointer (nullopts will be removed)
		Session Map(std::function<std::vector<SafePointer>(SafePointer)> transformer, bool purgeInvalid = true); // Maps pointer to other pointers (nullopts will be removed)

		// Finalizing
		inline std::size_t Size() { return pointers.size(); }
		std::vector<void*> Pointers();
		std::optional<void*> Choose(std::function<bool(SafePointer)> predicate); // Returns the first chosen pointer
		std::optional<void*> Pointer(); // Will return std::nullopt if there are no/multiple pointers available
	};
}

#endif
