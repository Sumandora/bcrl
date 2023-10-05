#include "BCRL.hpp"

#include <cassert>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

// Notice how I am calling functions which haven't been declared yet
int main()
{
	using namespace BCRL;
	const char* newString = strdup("You will never find me!"); // The compiler reuses strings when possible, so we duplicate it to force our library not to cheat

	auto functionPtr = Session::string(newString)
						   .findXREFs("bcrlExample" /*We know the executable name, no point in searching somewhere else*/, true, false) // main and superSecretMethod
						   .add(4)
						   .repeater([](SafePointer& ptr) { ptr = ptr.nextInstruction(); return !ptr.equals<unsigned char>('\xe8'); }) // Find next call instruction
						   .add(5)
						   .filter([](SafePointer ptr) { return ptr.equals<unsigned char>('\xe8'); }) // Verify that we have another call instruction here (This will remove the main method from the pool)
						   .add(1)
						   .relativeToAbsolute()
						   .nextByteOccurrence("c3") // Go to return
						   .prevByteOccurrence("55 48 89 e5") // Go back to the method prolog
						   .forEach([](SafePointer ptr) { printf("anotherSecretMethod: %p\n", ptr.getPointer()); })
						   .expect("Couldn't find anotherSecretMethod");

	auto func = reinterpret_cast<void (*)()>(functionPtr);

	auto stringSearch = Session::string(strdup("I really really really really really love Linux!")).getPointer();
	assert(stringSearch.has_value());
	char* str = static_cast<char*>(stringSearch.value());

	mprotect((void*)(((std::size_t)str) & ~(getpagesize() - 1)), getpagesize() + strlen(str), PROT_READ | PROT_WRITE | PROT_EXEC);

	const char* interjection = "I'd just like to interject for moment.";
	strcpy(str, interjection); // Get Stallman'd

	func(); // Invoke 'anotherSecretMethod', but its string has been overwritten, so we get the GNU Linux interjection
}

void anotherSecretMethod();

[[gnu::used]] void superSecretMethod()
{
	puts("You will never find me!");
	anotherSecretMethod();
}

void anotherSecretMethod()
{
	puts("I really really really really really love Linux!");
}
