#ifndef BCRL_HPP
#define BCRL_HPP

#include <cstdint>
#include <cstring>
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

		[[nodiscard]] std::vector<MemoryRegion> getMemoryRegions(
			std::optional<bool> writable = std::nullopt,
			std::optional<bool> executable = std::nullopt,
			std::optional<std::string> name = std::nullopt) const;
		const MemoryRegion* addressRegion(void* address) const;

	} memoryRegionStorage;

	class SafePointer { // A pointer which can't cause read access violations
		void* pointer;
		bool invalid; // Set to true, when an operation failed

	public:
		SafePointer() = delete;
		inline explicit SafePointer(void* pointer, bool invalid = false)
			: pointer(pointer)
			, invalid(invalid)
		{
		}
		inline explicit SafePointer(std::uintptr_t pointer, bool invalid = false)
			: pointer(reinterpret_cast<void*>(pointer))
			, invalid(invalid)
		{
		}

		[[nodiscard]] bool isValid(std::size_t length = 1) const;

		template <typename T> requires std::is_trivially_copyable_v<T>
		[[nodiscard]] inline std::optional<T> read() const
		{
			if (isValid(sizeof(T*))) {
				T obj;
				std::memcpy(&obj, pointer, sizeof(T));
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

		[[nodiscard]] SafePointer invalidate() const;
		[[nodiscard]] SafePointer revalidate() const;

		// Manipulation
		[[nodiscard]] SafePointer add(std::size_t operand) const;
		[[nodiscard]] SafePointer sub(std::size_t operand) const;
		[[nodiscard]] SafePointer dereference() const;

		// X86
#if defined(__x86_64) || defined(i386)
		[[nodiscard]] SafePointer relativeToAbsolute() const;

		[[nodiscard]] SafePointer prevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		[[nodiscard]] SafePointer nextInstruction() const;

		[[nodiscard]] std::vector<SafePointer> findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] std::vector<SafePointer> findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const;
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

		struct Hash {
			inline std::size_t operator()(const SafePointer& s) const noexcept
			{
				return std::hash<void*>{}(s.pointer);
			}
		};
	};

	class Session {
		std::vector<SafePointer> pointers{};

		bool safe; // Are we using safety measures?

		inline Session(std::vector<SafePointer> pointers, bool safe)
			: pointers(std::move(pointers))
			, safe(safe)
		{
		}
		inline Session(const std::vector<void*>& pointers, bool safe)
			: pointers()
			, safe(safe)
		{
			for (void* pointer : pointers) {
				this->pointers.emplace_back(pointer);
			}
		}
		inline Session(void* pointer, bool safe)
			: pointers()
			, safe(safe)
		{
			pointers.emplace_back(pointer);
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
		[[nodiscard]] Session add(std::size_t operand) const;
		[[nodiscard]] Session sub(std::size_t operand) const;
		[[nodiscard]] Session dereference() const;

		// Safety
		[[nodiscard]] Session setSafety(bool newSafeness) const;
		[[nodiscard]] inline bool isSafe() const { return safe; }
		[[nodiscard]] Session toggleSafety() const;

		// X86
#if defined(__x86_64) || defined(i386)
		[[nodiscard]] Session relativeToAbsolute() const;

		[[nodiscard]] Session prevInstruction() const; // WARNING: X86 can't be disassembled backwards properly, use with caution
		[[nodiscard]] Session nextInstruction() const;

		[[nodiscard]] Session findXREFs(bool relative = true, bool absolute = true) const; // Since there can be multiple xrefs, this can increase the amount of addresses
		[[nodiscard]] Session findXREFs(const std::string& moduleName, bool relative = true, bool absolute = true) const;
#endif
		// Signatures
		[[nodiscard]] Session prevByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Prev occurrence of signature
		[[nodiscard]] Session nextByteOccurrence(const std::string& signature, std::optional<bool> code = std::nullopt) const; // Next occurrence of signature

		// Strings
		[[nodiscard]] Session prevStringOccurrence(const std::string& string) const; // Prev occurrence of string
		[[nodiscard]] Session nextStringOccurrence(const std::string& string) const; // Next occurrence of string

		// Advanced Flow
		[[nodiscard]] Session purgeInvalid(std::size_t length = 1) const; // Will purge all pointers, which can't be dereferenced
		[[nodiscard]] Session forEach(const std::function<void(SafePointer&)>& action) const;
		[[nodiscard]] Session repeater(const std::function<bool(SafePointer&)>& action) const; // Repeats action until false is returned
		[[nodiscard]] Session repeater(std::size_t iterations, const std::function<void(SafePointer&)>& action) const; // Repeats action `iterations` times
		[[nodiscard]] Session filter(const std::function<bool(SafePointer)>& predicate) const; // Filters out non-conforming pointers
		[[nodiscard]] Session map(const std::function<std::optional<SafePointer>(SafePointer)>& transformer) const; // Maps pointer to other pointer (nullopts will be removed)
		[[nodiscard]] Session flatMap(const std::function<std::vector<SafePointer>(SafePointer)>& transformer) const; // Maps pointer to other pointers (nullopts will be removed)

		// Finalizing
		[[nodiscard]] inline std::size_t size() const { return pointers.size(); }
		[[nodiscard]] std::vector<void*> getPointers() const;
		[[nodiscard]] std::optional<void*> first(const std::function<bool(SafePointer)>& predicate) const; // Returns the first chosen pointer
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
