#include "BCRL.hpp"

#include "MemoryManager/LinuxMemoryManager.hpp"
#include "SignatureScanner/PatternSignature.hpp"

#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <link.h>

int main()
{
	void* handle = dlopen("libExampleTarget.so", RTLD_NOW); // Force load
	link_map* lmap;
	dlinfo(handle, RTLD_DI_LINKMAP, &lmap);
	printf("Loaded at 0x%lx\n", lmap->l_addr);

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

	auto anotherSecretMethod = BCRL::signature(localMemoryManager, SignatureScanner::buildStringPattern<"You will never find me!">())
					.findXREFs<true, false>(BCRL::everything(localMemoryManager).thatsReadable().withName("libExampleTarget.so")) // This lands us in superSecretMethod at the offset of the lea instruction ("48 8d 05 HERE-> 88 0e 00 00")
					.add(4) // Skip the offset
					.repeater([](auto& ptr) { ptr.nextInstruction(); return !ptr.template equals<unsigned char>('\xe8'); }) // Find next call instruction
					.add(5) // This is puts, not anotherSecretMethod
					.filter([](const auto& ptr) { return ptr.template equals<unsigned char>('\xe8'); }) // Verify that we have another call instruction here
					.add(1) // Skip the opcode
					.relativeToAbsolute() // Jump to the target of the relative offset
					.forEach([](const auto& ptr) { printf("anotherSecretMethod: 0x%lx\n", ptr.getPointer()); })
					.expect<void (*)()>("Couldn't find anotherSecretMethod", "Found too many solutions.");

	auto strings = BCRL::signature(localMemoryManager, SignatureScanner::buildStringPattern<"I really really really really really love Linux!">())
					   .filter(BCRL::everything(localMemoryManager).thatsReadable().withName("libExampleTarget.so"))
					   .peek();

	assert(!strings.empty());
	for (auto string : strings) {
		char* str = reinterpret_cast<char*>(string.getPointer());

		const char* interjection = "I'd just like to interject for moment.";
		localMemoryManager.write(reinterpret_cast<std::uintptr_t>(str), interjection, strlen(interjection) + 1); // Get Stallman'd
	}

	anotherSecretMethod(); // Invoke 'anotherSecretMethod', but its string has been overwritten, so we get the GNU Linux interjection
}
