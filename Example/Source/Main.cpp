#define MEMORYMANAGER_DEFINE_PTR_WRAPPER
#include "BCRL.hpp"
#include "BCRL/BCRLx86.hpp"
#include "MemoryManager/LocalMemoryManager.hpp"
#include "SignatureScanner/PatternSignature.hpp"

#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
	dlopen("libExampleTarget.so", RTLD_NOW); // Force load

	using namespace BCRL;
	MemoryManager::LocalMemoryManager<MemoryManager::RWMode::WRITE> localMemoryManager;
	localMemoryManager.update();
	auto func = Session::signature(localMemoryManager, SignatureScanner::PatternSignature{ SignatureScanner::String::build<"You will never find me!">() })
					.flatMap(findXREFs<true, false>("libExampleTarget.so")) // main and superSecretMethod
					.add(4)
					.repeater([](auto& ptr) { nextInstruction(ptr); return !ptr.template equals<unsigned char>('\xe8'); }) // Find next call instruction
					.add(5)
					.filter([](const auto& ptr) { return ptr.template equals<unsigned char>('\xe8'); }) // Verify that we have another call instruction here (This will implicitly remove the main method from the pool)
					.add(1)
					.forEach(relativeToAbsolute)
					.forEach([](const auto& ptr) { printf("anotherSecretMethod: 0x%lx\n", ptr.getPointer()); })
					.expect<void (*)()>("Couldn't find anotherSecretMethod", "Found too many solutions.");

	auto strings = Session::signature(localMemoryManager, SignatureScanner::PatternSignature{ SignatureScanner::String::build<"I really really really really really love Linux!">() })
					   .filterModule("libExampleTarget.so")
					   .peek();
	assert(!strings.empty());
	for (auto string : strings) {
		char* str = reinterpret_cast<char*>(string.getPointer());

		const char* interjection = "I'd just like to interject for moment.";
		localMemoryManager.write(str, interjection, strlen(interjection) + 1); // Get Stallman'd
	}

	func(); // Invoke 'anotherSecretMethod', but its string has been overwritten, so we get the GNU Linux interjection
}
