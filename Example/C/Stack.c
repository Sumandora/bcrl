#include "BCRL.h"

#include <alloca.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

bool nextCallInstruction(void* safePointer, void* _data) {
	safePointer = bcrl_safepointer_next_instruction(safePointer);
	char opcode;
	bcrl_safepointer_read(safePointer, &opcode, 1);
	return opcode != '\xe8';
}

bool verifyCall(const void* safePointer, void* _data) {
	char opcode;
	bcrl_safepointer_read(safePointer, &opcode, 1);
	return opcode == '\xe8';
}

void printMethod(void* safePointer, void* data) {
	printf((char*)data, bcrl_safepointer_get_pointer(safePointer));
}

// Notice how I am calling functions which haven't been declared yet
int main()
{
	dlopen("libExampleTarget.so", RTLD_NOW); // Force load

	const char* newString = strdup("You will never find me!"); // The compiler reuses strings when possible, so we duplicate it to force our library not to cheat

	void* session = alloca(bcrl_sizeof_session);
	bcrl_session_string(session, newString);

	session = bcrl_session_find_xrefs_with_module(session, "libExampleTarget.so", true, false);
	session = bcrl_session_add(session, 4);
	session = bcrl_session_repeater(session, nextCallInstruction, NULL);
	session = bcrl_session_add(session, 5);
	session = bcrl_session_filter(session, verifyCall, NULL);
	session = bcrl_session_add(session, 1);
	session = bcrl_session_relative_to_absolute(session);
	session = bcrl_session_for_each(session, printMethod, "anotherSecretMethod: 0x%lx\n");

	void(*func)() = bcrl_session_expect(session, "Couldn't find anotherSecretMethod");

	func(); // Invoke 'anotherSecretMethod', but its string has been overwritten, so we get the GNU Linux interjection

	bcrl_session_cleanup(session);
	bcrl_session_string(session, strdup("I really really really really really love Linux!"));

	session = bcrl_session_filter_module(session, "libExampleTarget.so");

	size_t count;
	void** pointers = bcrl_session_get_pointers(session, &count);
	assert(count > 0);

	for (size_t i = 0; i < count; i++) {
		char* str = (char*)pointers[i];

		size_t pagesize = getpagesize();
		uintptr_t page = (uintptr_t)str;
		page -= page % pagesize;

		mprotect((void*)page, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);

		const char* interjection = "I'd just like to interject for moment.";
		strcpy(str, interjection); // Get Stallman'd
	}

	bcrl_session_cleanup(session);

	func(); // Invoke 'anotherSecretMethod', but its string has been overwritten, so we get the GNU Linux interjection
}
