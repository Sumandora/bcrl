#include "BCRL.hpp"
#include "BCRL.h"

#include <new>

extern "C" {

using namespace BCRL;

const size_t bcrl_sizeof_safepointer = sizeof(SafePointer);
const size_t bcrl_sizeof_session = sizeof(Session);

void bcrl_construct_safepointer(void* safepointer, void* pointer, bool invalid)
{
	new (safepointer) SafePointer(pointer, invalid);
}

bool bcrl_safepointer_is_valid(const void* safepointer, size_t length)
{
	return static_cast<const SafePointer*>(safepointer)->isValid(length);
}
bool bcrl_safepointer_read(const void* safepointer, void* to, size_t length)
{
	return static_cast<const SafePointer*>(safepointer)->read(to, length);
}

void* bcrl_safepointer_invalidate(void* safepointer)
{
	return &static_cast<SafePointer*>(safepointer)->invalidate();
}
void* bcrl_safepointer_revalidate(void* safepointer)
{
	return &static_cast<SafePointer*>(safepointer)->revalidate();
}

void* bcrl_safepointer_add(void* safepointer, size_t operand)
{
	return &static_cast<SafePointer*>(safepointer)->add(operand);
}
void* bcrl_safepointer_sub(void* safepointer, size_t operand)
{
	return &static_cast<SafePointer*>(safepointer)->sub(operand);
}
void* bcrl_safepointer_dereference(void* safepointer)
{
	return &static_cast<SafePointer*>(safepointer)->dereference();
}

// X86
#if defined(__x86_64) || defined(i386)
void* bcrl_safepointer_relative_to_absolute(void* safepointer)
{
	return &static_cast<SafePointer*>(safepointer)->relativeToAbsolute();
}

void* bcrl_safepointer_prev_instruction(void* safepointer)
{
	return &static_cast<SafePointer*>(safepointer)->prevInstruction();
}
void* bcrl_safepointer_next_instruction(void* safepointer)
{
	return &static_cast<SafePointer*>(safepointer)->nextInstruction();
}

void* bcrl_safepointer_find_xrefs(const void* safepointer, bool relative, bool absolute, size_t* count)
{
	auto vec = static_cast<const SafePointer*>(safepointer)->findXREFs(relative, absolute);
	auto* array = static_cast<SafePointer*>(malloc((*count = vec.size()) * sizeof(SafePointer)));
	std::size_t i = 0;
	for (const SafePointer& s : vec) {
		array[i] = s;
		i++;
	}
	return array;
}
void* bcrl_safepointer_find_xrefs_with_module(const void* safepointer, const char* moduleName, bool relative, bool absolute, size_t* count)
{
	auto vec = static_cast<const SafePointer*>(safepointer)->findXREFs(moduleName, relative, absolute);
	auto* array = static_cast<SafePointer*>(malloc((*count = vec.size()) * sizeof(SafePointer)));
	std::size_t i = 0;
	for (const SafePointer& s : vec) {
		array[i] = s;
		i++;
	}
	return array;
}
#endif

void* bcrl_safepointer_prev_byte_occurrence(void* safepointer, const char* signature, char wildcard)
{
	return &static_cast<SafePointer*>(safepointer)->prevByteOccurrence(signature, wildcard);
}
void* bcrl_safepointer_prev_byte_occurrence_code(void* safepointer, const char* signature, char wildcard, bool code)
{
	return &static_cast<SafePointer*>(safepointer)->prevByteOccurrence(signature, wildcard, code);
}
void* bcrl_safepointer_next_byte_occurrence(void* safepointer, const char* signature, char wildcard)
{
	return &static_cast<SafePointer*>(safepointer)->nextByteOccurrence(signature, wildcard);
}
void* bcrl_safepointer_next_byte_occurrence_code(void* safepointer, const char* signature, char wildcard, bool code)
{
	return &static_cast<SafePointer*>(safepointer)->nextByteOccurrence(signature, wildcard, code);
}
bool bcrl_safepointer_does_match(const void* safepointer, const char* signature)
{
	return static_cast<const SafePointer*>(safepointer)->doesMatch(signature);
}

void* bcrl_safepointer_prev_string_occurrence(void* safepointer, const char* string)
{
	return &static_cast<SafePointer*>(safepointer)->prevStringOccurrence(string);
}
void* bcrl_safepointer_prev_wildcard_string_occurrence(void* safepointer, const char* string, char wildcard)
{
	return &static_cast<SafePointer*>(safepointer)->prevStringOccurrence(string, wildcard);
}
void* bcrl_safepointer_next_string_occurrence(void* safepointer, const char* string)
{
	return &static_cast<SafePointer*>(safepointer)->nextStringOccurrence(string);
}
void* bcrl_safepointer_next_wildcard_string_occurrence(void* safepointer, const char* string, char wildcard)
{
	return &static_cast<SafePointer*>(safepointer)->nextStringOccurrence(string, wildcard);
}

bool bcrl_safepointer_is_in_module(const void* safepointer, const char* moduleName)
{
	return static_cast<const SafePointer*>(safepointer)->isInModule(moduleName);
}

uintptr_t bcrl_safepointer_get_pointer(const void* safepointer)
{
	return static_cast<const SafePointer*>(safepointer)->getPointer();
}

void bcrl_session_signature(void* session, const char* signature, char wildcard)
{
	new (session) Session{ Session::signature(signature, wildcard) };
}
void bcrl_session_signature_code(void* session, const char* signature, char wildcard, bool code)
{
	new (session) Session{ Session::signature(signature, wildcard, code) };
}
void bcrl_session_module(void* session, const char* moduleName)
{
	new (session) Session{ Session::module(moduleName) };
}
void bcrl_session_string(void* session, const char* string)
{
	new (session) Session{ Session::string(string) };
}
void bcrl_session_wildcard_string(void* session, const char* string, char wildcard)
{
	new (session) Session{ Session::string(string, wildcard) };
}
void bcrl_session_pointerList(void* session, void** pointers, size_t list_length)
{
	std::vector<void*> vec;
	vec.reserve(list_length);
	for (std::size_t i = 0; i < list_length; i++) {
		vec.emplace_back(pointers[i]);
	}

	new (session) Session{ Session::pointerList(vec) };
}
void bcrl_session_pointer(void* session, void* pointer)
{
	new (session) Session{ Session::pointer(pointer) };
}
void bcrl_session_pointerArray(void* session, void* array, size_t index)
{
	new (session) Session{ Session::pointerArray(array, index) };
}

void bcrl_session_copy(const void* from, void* to) {
	new (to) Session{ *static_cast<const Session*>(from) };
}

void* bcrl_session_add(void* session, size_t operand)
{
	return &static_cast<Session*>(session)->add(operand);
}
void* bcrl_session_sub(void* session, size_t operand)
{
	return &static_cast<Session*>(session)->sub(operand);
}
void* bcrl_session_dereference(void* session)
{
	return &static_cast<Session*>(session)->dereference();
}

void* bcrl_session_set_safety(void* session, bool new_safeness)
{
	return &static_cast<Session*>(session)->setSafety(new_safeness);
}
bool bcrl_session_is_safe(const void* session)
{
	return static_cast<const Session*>(session)->isSafe();
}
void* bcrl_session_toggle_safety(void* session)
{
	return &static_cast<Session*>(session)->toggleSafety();
}

#if defined(__x86_64) || defined(i386)
void* bcrl_session_relative_to_absolute(void* session)
{
	return &static_cast<Session*>(session)->relativeToAbsolute();
}

void* bcrl_session_prev_instruction(void* session)
{
	return &static_cast<Session*>(session)->prevInstruction();
}
void* bcrl_session_next_instruction(void* session)
{
	return &static_cast<Session*>(session)->nextInstruction();
}

void* bcrl_session_find_xrefs(void* session, bool relative, bool absolute)
{
	return &static_cast<Session*>(session)->findXREFs(relative, absolute);
}
void* bcrl_session_find_xrefs_with_module(void* session, const char* moduleName, bool relative, bool absolute)
{
	return &static_cast<Session*>(session)->findXREFs(moduleName, relative, absolute);
}
#endif

void* bcrl_session_prev_byte_occurrence(void* session, const char* signature, char wildcard)
{
	return &static_cast<Session*>(session)->prevByteOccurrence(signature, wildcard);
}
void* bcrl_session_prev_byte_occurrence_code(void* session, const char* signature, char wildcard, bool code)
{
	return &static_cast<Session*>(session)->prevByteOccurrence(signature, wildcard, code);
}
void* bcrl_session_next_byte_occurrence(void* session, const char* signature, char wildcard)
{
	return &static_cast<Session*>(session)->nextByteOccurrence(signature, wildcard);
}
void* bcrl_session_next_byte_occurrence_code(void* session, const char* signature, char wildcard, bool code)
{
	return &static_cast<Session*>(session)->nextByteOccurrence(signature, wildcard, code);
}

void* bcrl_session_prev_string_occurrence(void* session, const char* string)
{
	return &static_cast<Session*>(session)->prevStringOccurrence(string);
}
void* bcrl_session_prev_wildcard_string_occurrence(void* session, const char* string, char wildcard)
{
	return &static_cast<Session*>(session)->prevStringOccurrence(string, wildcard);
}
void* bcrl_session_next_string_occurrence(void* session, const char* string)
{
	return &static_cast<Session*>(session)->nextStringOccurrence(string);
}
void* bcrl_session_next_wildcard_string_occurrence(void* session, const char* string, char wildcard)
{
	return &static_cast<Session*>(session)->nextStringOccurrence(string, wildcard);
}

void* bcrl_session_filter_module(void* session, const char* moduleName)
{
	return &static_cast<Session*>(session)->filterModule(moduleName);
}

void* bcrl_sesion_purge_invalid(void* session, size_t length)
{
	return &static_cast<Session*>(session)->purgeInvalid(length);
}
void* bcrl_session_for_each(void* session, void (*body)(void* safePointer, void* data), void* data)
{
	return &static_cast<Session*>(session)->forEach([body, data](SafePointer& safePointer) {
		body(&safePointer, data);
	});
}
void* bcrl_session_repeater(void* session, bool (*action)(void* safePointer, void* data), void* data)
{
	return &static_cast<Session*>(session)->repeater([action, data](SafePointer& safePointer) {
		return action(&safePointer, data);
	});
}
void* bcrl_session_repeater_with_count(void* session, size_t iterations, bool (*loop)(void* safePointer, void* data), void* data)
{
	return &static_cast<Session*>(session)->repeater(iterations, [loop, data](SafePointer& safePointer) {
		loop(&safePointer, data);
	});
}
void* bcrl_session_filter(void* session, bool (*predicate)(const void* safePointer, void* data), void* data)
{
	return &static_cast<Session*>(session)->filter([predicate, data](const SafePointer& safePointer) {
		return predicate(&safePointer, data);
	});
}
void* bcrl_session_flat_map(void* session, void** (*transformer)(const void* safePointer, size_t* count, void* data), void* data)
{
	return &static_cast<Session*>(session)->flatMap([transformer, data](const SafePointer& safePointer) {
		size_t count;
		void** transformed = transformer(&safePointer, &count, data);
		std::vector<SafePointer> safePointers;
		safePointers.reserve(count);
		for (std::size_t i = 0; i < count; i++) {
			safePointers.emplace_back(*static_cast<SafePointer*>(transformed[i]));
		}
		return safePointers;
	});
}

size_t bcrl_session_size(const void* session)
{
	return static_cast<const Session*>(session)->size();
}
void** bcrl_session_get_pointers(const void* session, size_t* count)
{
	auto vec = static_cast<const Session*>(session)->getPointers();
	void** array = static_cast<void**>(malloc((*count = vec.size()) * sizeof(void*)));
	std::size_t i = 0;
	for (void* s : vec) {
		array[i] = s;
		i++;
	}
	return array;
}
#pragma clang diagnostic push
#pragma ide diagnostic ignored "modernize-use-nullptr" // This belongs to C, use NULL over nullptr because that's what C wants
void* bcrl_session_get_pointer(const void* session)
{
	return static_cast<const Session*>(session)->getPointer().value_or((void*)NULL);
}
#pragma clang diagnostic pop
void* bcrl_session_expect(const void* session, const char* message)
{
	return static_cast<const Session*>(session)->expect(message);
}

void bcrl_safepointer_cleanup(void* safePointer)
{
	static_cast<SafePointer*>(safePointer)->~SafePointer();
}
void bcrl_session_cleanup(void* session)
{
	static_cast<Session*>(session)->~Session();
}

}