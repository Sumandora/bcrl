#include "BCRL.hpp"

using namespace BCRL;

Session& Session::add(std::size_t operand)
{
	return forEach([operand](SafePointer& safePointer) {
		safePointer.add(operand);
	});
}
Session& Session::sub(std::size_t operand)
{
	return forEach([operand](SafePointer& safePointer) {
		safePointer.sub(operand);
	});
}
Session& Session::dereference()
{
	return forEach([](SafePointer& safePointer) {
		safePointer.dereference();
	});
}

#if defined(__x86_64) || defined(i386)
Session& Session::relativeToAbsolute()
{
	return forEach([](SafePointer& safePointer) {
		safePointer.relativeToAbsolute();
	});
}

Session& Session::prevInstruction()
{
	return forEach([](SafePointer& safePointer) {
		safePointer.prevInstruction();
	});
}
Session& Session::nextInstruction()
{
	return forEach([](SafePointer& safePointer) {
		safePointer.nextInstruction();
	});
}

Session& Session::findXREFs(bool relative, bool absolute)
{
	return flatMap([relative, absolute](const SafePointer& safePointer) {
		return safePointer.findXREFs(relative, absolute);
	});
}

Session& Session::findXREFs(const std::string& moduleName, bool relative, bool absolute)
{
	return flatMap([&moduleName, relative, absolute](const SafePointer& safePointer) {
		return safePointer.findXREFs(moduleName, relative, absolute);
	});
}
#endif

Session& Session::prevByteOccurrence(const std::string& signature, char wildcard, std::optional<bool> code)
{
	return forEach([&signature, wildcard, &code](SafePointer& safePointer) {
		safePointer.prevByteOccurrence(signature, wildcard, code);
	});
}
Session& Session::nextByteOccurrence(const std::string& signature, char wildcard, std::optional<bool> code)
{
	return forEach([&signature, wildcard, &code](SafePointer& safePointer) {
		safePointer.nextByteOccurrence(signature, wildcard, code);
	});
}

Session& Session::prevStringOccurrence(const std::string& string, std::optional<char> wildcard)
{
	return forEach([&string, wildcard](SafePointer& safePointer) {
		safePointer.prevStringOccurrence(string, wildcard);
	});
}
Session& Session::nextStringOccurrence(const std::string& string, std::optional<char> wildcard)
{
	return forEach([&string, wildcard](SafePointer& safePointer) {
		return safePointer.nextStringOccurrence(string, wildcard);
	});
}

Session& Session::filterModule(const std::string& moduleName)
{
	return filter([&moduleName](const SafePointer& safePointer) {
		return safePointer.isInModule(moduleName);
	});
}
