#include "BCRL/SearchConstraints.hpp"
#include "BCRL/Session.hpp"

#include "MemoryManager/LinuxMemoryManager.hpp"
#include "SignatureScanner/PatternSignature.hpp"
#include "SignatureScanner/XRefSignature.hpp"

#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <print>

int main()
{
	void* handle = dlopen("libExampleTarget.so", RTLD_NOW); // Force load
	link_map* lmap = nullptr;
	// NOLINTNEXTLINE(bugprone-multi-level-implicit-pointer-conversion)
	dlinfo(handle, RTLD_DI_LINKMAP, &lmap);
	std::println("Loaded at 0x{:x}", lmap->l_addr);

	using namespace BCRL;
	MemoryManager::LinuxMemoryManager<true, true, true> local_memory_manager;
	local_memory_manager.sync_layout();

	/**
	 *	super_secret_method:
	 *	f3 0f 1e fa             endbr64
	 *	55                      push   %rbp
	 *	48 89 e5                mov    %rsp,%rbp
	 *	48 8d 05 88 0e 00 00    lea    0xe88(%rip),%rax        # "You will never find me!"
	 *	48 89 c7                mov    %rax,%rdi
	 *	e8 f0 fe ff ff          call   1070 <puts@plt>
	 *	e8 db fe ff ff          call   1060 <another_secret_method@plt>
	 *	90                      nop
	 *	5d                      pop    %rbp
	 *	c3                      ret
	 */

	auto another_secret_method = BCRL::signature(local_memory_manager, SignatureScanner::PatternSignature::for_literal_string<"You will never find me!">())
									 .find_xrefs(SignatureScanner::XRefTypes::relative_and_absolute(), BCRL::everything(local_memory_manager).thats_readable().with_name("libExampleTarget.so")) // This lands us in super_secret_method at the offset of the lea instruction ("48 8d 05 HERE-> 88 0e 00 00")
									 .add(4) // Skip the offset
									 .repeater([](auto& s) {
										 const bool has_call = s.does_match(SignatureScanner::PatternSignature::for_array_of_bytes<"e8">());
										 if (!has_call)
											 s.next_instruction();
										 return !has_call;
									 }) // Find the two call instructions by stepping through the function
									 .next_instruction() // This is puts, not another_secret_method
									 .filter([](const auto& ptr) { return ptr.does_match(SignatureScanner::PatternSignature::for_array_of_bytes<"e8">()); }) // Verify that there's another call instruction here
									 .add(1) // Skip the opcode
									 .relative_to_absolute() // Jump to the target of the relative offset
									 .filter(BCRL::everything(local_memory_manager).with_flags("r-x").with_name("libExampleTarget.so"))
									 .for_each([](const auto& ptr) { std::println("another_secret_method: 0x{:x}", ptr.get_pointer()); })
									 .expect<void (*)()>("Couldn't find another_secret_method", "Found too many solutions.");

	auto strings = BCRL::signature(local_memory_manager, SignatureScanner::PatternSignature::for_literal_string<"I really really really really really love Linux!">())
					   .filter(BCRL::everything(local_memory_manager).thats_readable().with_name("libExampleTarget.so"))
					   .peek();

	assert(!strings.empty());
	for (auto string : strings) {
		const char* interjection = "I'd just like to interject for moment.";
		local_memory_manager.write(string.get_pointer(), interjection, strlen(interjection) + 1 /*null terminator*/); // Get Stallman'd
	}

	another_secret_method(); // Invoke 'another_secret_method' without linking against it, but its string has been overwritten, so the GNU Linux interjection appears
}
