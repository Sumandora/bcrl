#include "BCRL.hpp"

BCRL::Session BCRL::Session::add(std::size_t operand)
{
	return map([operand](SafePointer safePointer) {
		return safePointer.add(operand);
	});
}
BCRL::Session BCRL::Session::sub(std::size_t operand)
{
	return map([operand](SafePointer safePointer) {
		return safePointer.sub(operand);
	});
}
BCRL::Session BCRL::Session::dereference()
{
	return map([](SafePointer safePointer) {
		return safePointer.dereference();
	});
}

BCRL::Session BCRL::Session::setSafe(bool safe)
{
	BCRL::Session session = map([safe](SafePointer safePointer) {
		return safePointer.setSafe(safe);
	});
	session.safe = safe;
	return session;
}

BCRL::Session BCRL::Session::toggleSafety()
{
	return map([](SafePointer safePointer) {
		return safePointer.toggleSafety();
	});
}

#if defined(__x86_64) || defined(i386)
BCRL::Session BCRL::Session::relativeToAbsolute()
{
	return map([](SafePointer safePointer) {
		return safePointer.relativeToAbsolute();
	});
}

BCRL::Session BCRL::Session::prevInstruction()
{
	return map([](SafePointer safePointer) {
		return safePointer.prevInstruction();
	});
}
BCRL::Session BCRL::Session::nextInstruction()
{
	return map([](SafePointer safePointer) {
		return safePointer.nextInstruction();
	});
}

BCRL::Session BCRL::Session::findXREFs(bool relative, bool absolute)
{
	return map([relative, absolute](SafePointer safePointer) {
		return safePointer.findXREFs(relative, absolute);
	});
}

BCRL::Session BCRL::Session::findXREFs(const std::string& moduleName, bool relative, bool absolute)
{
	return map([&moduleName, relative, absolute](SafePointer safePointer) {
		return safePointer.findXREFs(moduleName, relative, absolute);
	});
}
#endif

BCRL::Session BCRL::Session::prevByteOccurence(const std::string& signature, std::optional<bool> code)
{
	return map([&signature, &code](SafePointer safePointer) {
		return safePointer.prevByteOccurence(signature);
	});
}
BCRL::Session BCRL::Session::nextByteOccurence(const std::string& signature, std::optional<bool> code)
{
	return map([&signature, &code](SafePointer safePointer) {
		return safePointer.nextByteOccurence(signature, code);
	});
}

BCRL::Session BCRL::Session::prevStringOccurence(const std::string& string)
{
	return map([&string](SafePointer safePointer) {
		return safePointer.prevStringOccurence(string);
	});
}
BCRL::Session BCRL::Session::nextStringOccurence(const std::string& string)
{
	return map([&string](SafePointer safePointer) {
		return safePointer.nextStringOccurence(string);
	});
}
