#include "BCRL.hpp"

#include <cstring>

#include <sys/mman.h>
#include <unistd.h>

#include <iostream>

#include <cassert>

// Notice how I am calling functions which haven't been declared yet
int main()
{
	const char* newString = strdup("You will never find me!"); // The compiler reuses strings when possible

	auto session = BCRL::Session::String(newString)
					   .FindXREFs("bcrlExample", true, false) // main and SuperSecretMethod
					   .Add(4)
					   .Repeater([](BCRL::SafePointer& ptr) { ptr = ptr.NextInstruction(); return !ptr.Equals<unsigned char>('\xe8'); }) // Find next call instruction
					   .Add(5)
					   .Filter([](BCRL::SafePointer ptr) { return ptr.Equals<unsigned char>('\xe8'); }) // Verify that we have another call instruction here (This will remove main from the options)
					   .Add(1)
					   .RelativeToAbsolute()
					   .NextByteOccurence("c3") // Go to return
					   .PrevByteOccurence("55 48 89 e5") // Go back to the method prolog
					   .ForEach([](BCRL::SafePointer ptr) { printf("AnotherSecretMethod: %p\n", ptr.GetPointer()); })
					   .Pointer();

	assert(session.has_value());

	void (*func)() = (void (*)())session.value();

	auto stringSearch = BCRL::Session::String(strdup("I really really really really really love Linux!")).Pointer();
	assert(stringSearch.has_value());
	char* str = static_cast<char*>(stringSearch.value());

	mprotect((void*)(((std::size_t)str) & ~(getpagesize() - 1)), getpagesize() + strlen(str), PROT_READ | PROT_WRITE | PROT_EXEC);

	const char* interjection = "I'd just like to interject for moment.";
	strcpy(str, interjection); // Get Stallman'd

	func();
}

void AnotherSecretMethod();

void SuperSecretMethod()
{
	puts("You will never find me!");
	AnotherSecretMethod();
}

void AnotherSecretMethod()
{
	puts("I really really really really really love Linux!");
}
