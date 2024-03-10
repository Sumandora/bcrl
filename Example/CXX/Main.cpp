#include "BCRL.hpp"

#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
	dlopen("libExampleTarget.so", RTLD_NOW); // Force load

	using namespace BCRL;
	auto func = Session::string("You will never find me!")
					.findXREFs("libExampleTarget.so", true, false) // main and superSecretMethod
					.add(4)
					.repeater([](SafePointer& ptr) { ptr = ptr.nextInstruction(); return !ptr.equals<unsigned char>('\xe8'); }) // Find next call instruction
					.add(5)
					.filter([](const SafePointer& ptr) { return ptr.equals<unsigned char>('\xe8'); }) // Verify that we have another call instruction here (This will implicitly remove the main method from the pool)
					.add(1)
					.relativeToAbsolute()
					.forEach([](const SafePointer& ptr) { printf("anotherSecretMethod: 0x%lx\n", ptr.getPointer()); })
					.expect<void (*)()>("Couldn't find anotherSecretMethod");

	auto strings = Session::string("I really really really really really love Linux!")
					   .filterModule("libExampleTarget.so")
					   .getPointers();
	assert(!strings.empty());
	for (auto string : strings) {
		char* str = static_cast<char*>(string);

		std::size_t pagesize = getpagesize();
		auto page = reinterpret_cast<std::uintptr_t>(str);
		page -= page % pagesize;

		mprotect((void*)page, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);

		const char* interjection = "I'd just like to interject for moment.";
		strcpy(str, interjection); // Get Stallman'd
	}

	func(); // Invoke 'anotherSecretMethod', but its string has been overwritten, so we get the GNU Linux interjection
}
