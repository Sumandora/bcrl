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
	MemoryManager::LinuxMemoryManager<true, true, true> localMemoryManager;
	localMemoryManager.update();

	/**
	 *	superSecretMethod:
	 *	f3 0f 1e fa             endbr64
	 *	55                      push   %rbp
	 *	48 89 e5                mov    %rsp,%rbp
	 *	48 8d 05 88 0e 00 00    lea    0xe88(%rip),%rax        # "You will never find me!"
	 *	48 89 c7                mov    %rax,%rdi
	 *	e8 f0 fe ff ff          call   1070 <puts@plt>
	 *	e8 db fe ff ff          call   1060 <anotherSecretMethod@plt>
	 *	90                      nop
	 *	5d                      pop    %rbp
	 *	c3                      ret
	 */

	auto anotherSecretMethod = BCRL::signature(localMemoryManager, SignatureScanner::PatternSignature::fromString<"You will never find me!">())
								   .findXREFs(SignatureScanner::XRefTypes::relativeAndAbsolute(), BCRL::everything(localMemoryManager).thatsReadable().withName("libExampleTarget.so")) // This lands us in superSecretMethod at the offset of the lea instruction ("48 8d 05 HERE-> 88 0e 00 00")
								   .add(4) // Skip the offset
								   .repeater([](auto& s) {
									   const bool hasCall = s.doesMatch(SignatureScanner::PatternSignature::fromBytes<"e8">());
									   if (!hasCall)
										   s.nextInstruction();
									   return !hasCall;
								   }) // Find the two call instructions by stepping through the function
								   .nextInstruction() // This is puts, not anotherSecretMethod
								   .filter([](const auto& ptr) { return ptr.doesMatch(SignatureScanner::PatternSignature::fromBytes<"e8">()); }) // Verify that there's another call instruction here
								   .add(1) // Skip the opcode
								   .relativeToAbsolute() // Jump to the target of the relative offset
								   .filter(BCRL::everything(localMemoryManager).withFlags("r-x").withName("libExampleTarget.so"))
								   .forEach([](const auto& ptr) { std::println("anotherSecretMethod: 0x{:x}", ptr.getPointer()); })
								   .expect<void (*)()>("Couldn't find anotherSecretMethod", "Found too many solutions.");

	auto strings = BCRL::signature(localMemoryManager, SignatureScanner::PatternSignature::fromString<"I really really really really really love Linux!">())
					   .filter(BCRL::everything(localMemoryManager).thatsReadable().withName("libExampleTarget.so"))
					   .peek();

	assert(!strings.empty());
	for (auto string : strings) {
		const char* interjection = "I'd just like to interject for moment.";
		localMemoryManager.write(string.getPointer(), interjection, strlen(interjection) + 1 /*null terminator*/); // Get Stallman'd
	}

	anotherSecretMethod(); // Invoke 'anotherSecretMethod' without linking against it, but its string has been overwritten, so the GNU Linux interjection appears
}
