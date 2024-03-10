#ifndef BCRL_H
#define BCRL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const size_t bcrl_sizeof_safepointer;
extern const size_t bcrl_sizeof_session;

void bcrl_construct_safepointer(void* safepointer, void* pointer, bool invalid /*= false*/);

bool bcrl_safepointer_is_valid(const void* safepointer, size_t length);
bool bcrl_safepointer_read(const void* safepointer, void* to, size_t length); // Returns true when successful

void* bcrl_safepointer_invalidate(void* safepointer);
void* bcrl_safepointer_revalidate(void* safepointer);

void* bcrl_safepointer_add(void* safepointer, size_t operand);
void* bcrl_safepointer_sub(void* safepointer, size_t operand);
void* bcrl_safepointer_dereference(void* safepointer);

		// X86
#if defined(__x86_64) || defined(i386)
void* bcrl_safepointer_relative_to_absolute(void* safepointer);

void* bcrl_safepointer_prev_instruction(void* safepointer);
void* bcrl_safepointer_next_instruction(void* safepointer);

void* bcrl_safepointer_find_xrefs(const void* safepointer, bool relative, bool absolute, size_t* count); // Returns list of SafePointers
void* bcrl_safepointer_find_xrefs_with_module(const void* safepointer, const char* moduleName, bool relative, bool absolute, size_t* count); // Returns list of SafePointers
#endif

void* bcrl_safepointer_prev_byte_occurrence(void* safepointer, const char* signature, char wildcard /*= '?'*/);
void* bcrl_safepointer_prev_byte_occurrence_code(void* safepointer, const char* signature, char wildcard /*= '?'*/, bool code);
void* bcrl_safepointer_next_byte_occurrence(void* safepointer, const char* signature, char wildcard /*= '?'*/);
void* bcrl_safepointer_next_byte_occurrence_code(void* safepointer, const char* signature, char wildcard /*= '?'*/, bool code);
bool bcrl_safepointer_does_match(const void* safepointer, const char* signature);

void* bcrl_safepointer_prev_string_occurrence(void* safepointer, const char* string);
void* bcrl_safepointer_prev_wildcard_string_occurrence(void* safepointer, const char* string, char wildcard);
void* bcrl_safepointer_next_string_occurrence(void* safepointer, const char* string);
void* bcrl_safepointer_next_wildcard_string_occurrence(void* safepointer, const char* string, char wildcard);

[[nodiscard]] bool bcrl_safepointer_is_in_module(const void* safepointer, const char* moduleName);

uintptr_t bcrl_safepointer_get_pointer(const void* safepointer);

void bcrl_session_signature(void* session, const char* signature, char wildcard /*= '?'*/);
void bcrl_session_signature_code(void* session, const char* signature, char wildcard /*= '?'*/, bool code);
void bcrl_session_module(void* session, const char* moduleName);
void bcrl_session_string(void* session, const char* string);
void bcrl_session_wildcard_string(void* session, const char* string, char wildcard);
void bcrl_session_pointerList(void* session, void** pointers, size_t list_length);
void bcrl_session_pointer(void* session, void* pointer);
void bcrl_session_pointerArray(void* session, void* array, size_t index);

void* bcrl_session_add(void* session, size_t operand);
void* bcrl_session_sub(void* session, size_t operand);

void* bcrl_session_dereference(void* session);

void* bcrl_session_set_safety(void* session, bool new_safeness);
bool bcrl_session_is_safe(const void* session);
void* bcrl_session_toggle_safety(void* session);

#if defined(__x86_64) || defined(i386)
void* bcrl_session_relative_to_absolute(void* session);

void* bcrl_session_prev_instruction(void* session);
void* bcrl_session_next_instruction(void* session);

void* bcrl_session_find_xrefs(void* session, bool relative, bool absolute);
void* bcrl_session_find_xrefs_with_module(void* session, const char* moduleName, bool relative, bool absolute);
#endif

void* bcrl_session_prev_byte_occurrence(void* session, const char* signature, char wildcard /*= '?'*/);
void* bcrl_session_prev_byte_occurrence_code(void* session, const char* signature, char wildcard /*= '?'*/, bool code);
void* bcrl_session_next_byte_occurrence(void* session, const char* signature, char wildcard /*= '?'*/);
void* bcrl_session_next_byte_occurrence_code(void* session, const char* signature, char wildcard /*= '?'*/, bool code);

void* bcrl_session_prev_string_occurrence(void* session, const char* string);
void* bcrl_session_prev_wildcard_string_occurrence(void* session, const char* string, char wildcard);
void* bcrl_session_next_string_occurrence(void* session, const char* string);
void* bcrl_session_next_wildcard_string_occurrence(void* session, const char* string, char wildcard);

void* bcrl_session_filter_module(void* session, const char* moduleName);

void* bcrl_sesion_purge_invalid(void* session, size_t length /*= 1*/);
void* bcrl_session_for_each(void* session, void(*body)(void* safePointer, void* data), void* data);
void* bcrl_session_repeater(void* session, bool(*action)(void* safePointer, void* data), void* data);
void* bcrl_session_repeater_with_count(void* session, size_t iterations, bool(*loop)(void* safePointer, void* data), void* data);
void* bcrl_session_filter(void* session, bool(*predicate)(const void* safePointer, void* data), void* data);
void* bcrl_session_flat_map(void* session, void**(*transformer)(const void* safePointer, size_t* count, void* data), void* data);

size_t bcrl_session_size(const void* session);
void** bcrl_session_get_pointers(const void* session, size_t* count);
void* bcrl_session_get_pointer(const void* session); // NULL when empty
void* bcrl_session_expect(const void* session, const char* message);

void bcrl_safepointer_cleanup(void* safepointer);
void bcrl_session_cleanup(void* session);

#ifdef __cplusplus
}
#endif

#endif
