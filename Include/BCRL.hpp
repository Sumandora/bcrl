#ifndef BCRL_HPP
#define BCRL_HPP

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
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
		};

	private:
		std::vector<MemoryRegion> memoryRegions{};

	public:
		MemoryRegionStorage();
		bool Update(); // To update memory regions call this (for example on dlopen/dlclose calls)

		std::vector<MemoryRegion> GetMemoryRegions(std::optional<bool> writable = std::nullopt, std::optional<bool> executable = std::nullopt) const;
		bool IsAddressReadable(void* address) const;
		const MemoryRegion* AddressRegion(void* address) const;

	} memoryRegionStorage;

#if defined(__x86_64) || defined(i386)
	struct XREFTypes {
#ifdef __x86_64
		bool search32bit, search64bit;
#else
		bool search16bit, search32bit;
#endif
	};

#endif
	class SafePointer { // A pointer which can't cause read access violations
		void* pointer;
		bool invalid = false; // Set to true, when a operation failed
		bool safe;

	public:
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
			if (IsValid(sizeof(T)))
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
		SafePointer NextInstruction() const; // `unsafe` forces the disassembly, even if it might lead to read access violations
#endif
		std::vector<SafePointer> FindXREFs(const XREFTypes& types = { true, true }) const; // Since there can be multiple xrefs, this can increase the amount of addresses

#endif
		// Signatures
		SafePointer PrevOccurence(const std::string& signature) const; // Last occurence of signature
		SafePointer NextOccurence(const std::string& signature) const; // Next occurence of signature

		// Misc
		bool DoesMatch(const std::string& signature) const; // Tests if the given signature matches the current address

		inline std::strong_ordering operator<=>(const SafePointer& other) const
		{

			return reinterpret_cast<std::uintptr_t>(pointer) <=> reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		inline bool operator==(const SafePointer& other) const
		{
			return reinterpret_cast<std::uintptr_t>(pointer) == reinterpret_cast<std::uintptr_t>(other.pointer);
		}

		inline bool IsValid(std::size_t length = 1) const
		{
			if (invalid)
				return false; // It was already eliminated
			if (!safe)
				return true; // The user wants it this way
			bool valid = true;
			for (std::size_t i = 0; i < length; i++) {
				if (!memoryRegionStorage.IsAddressReadable(Add(i).pointer))
					valid = false;
			}
			return valid;
		}

		inline void* GetPointer() const
		{
			return pointer;
		};
	};

	class Session {
		std::vector<SafePointer> pointers{};

		bool safe; // Are we using safety measures?

		inline Session(std::vector<SafePointer> pointers)
			: pointers(pointers)
		{
		}
		inline Session(std::vector<void*> pointers)
		{
			for (void* pointer : pointers) {
				this->pointers.push_back({ pointer, safe });
			}
		}
		inline Session(void* pointer)
			: pointers({})
		{
			pointers.push_back({ pointer, safe });
		}

	public:
		Session() = delete;

		// Openers
		static Session Signature(const char* signature);
		static Session Module(const char* moduleName);
		static Session String(const char* string);
		static Session PointerList(std::vector<void*> pointers);
		static Session Pointer(void* pointer);
		static Session PointerArray(void* pointerArray, std::size_t index); // e.g. Virtual function tables

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
		Session NextInstruction(); // `unsafe` forces the disassembly, even if it might lead to read access violations
#endif

		Session FindXREFs(XREFTypes types = { true, true }); // Since there can be multiple xrefs, this can increase the amount of addresses

#endif
		// Signatures
		Session PrevOccurence(const std::string& signature); // Last occurence of signature
		Session NextOccurence(const std::string& signature); // Next occurence of signature

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
