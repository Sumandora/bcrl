#include "BCRL.hpp"

using namespace BCRL;

Session Session::add(std::size_t operand)
{
	return map([operand](SafePointer safePointer) {
		return safePointer.add(operand);
	});
}
Session Session::sub(std::size_t operand)
{
	return map([operand](SafePointer safePointer) {
		return safePointer.sub(operand);
	});
}
Session Session::dereference()
{
	return map([](SafePointer safePointer) {
		return safePointer.dereference();
	});
}

Session Session::setSafe(bool safe)
{
	Session session = map([safe](SafePointer safePointer) {
		return safePointer.setSafe(safe);
	});
	session.safe = safe;
	return session;
}

Session Session::toggleSafety()
{
	return map([](SafePointer safePointer) {
		return safePointer.toggleSafety();
	});
}

#if defined(__x86_64) || defined(i386)
Session Session::relativeToAbsolute()
{
	return map([](SafePointer safePointer) {
		return safePointer.relativeToAbsolute();
	});
}

Session Session::prevInstruction()
{
	return map([](SafePointer safePointer) {
		return safePointer.prevInstruction();
	});
}
Session Session::nextInstruction()
{
	return map([](SafePointer safePointer) {
		return safePointer.nextInstruction();
	});
}

Session Session::findXREFs(bool relative, bool absolute)
{
	return map([relative, absolute](SafePointer safePointer) {
		return safePointer.findXREFs(relative, absolute);
	});
}

Session Session::findXREFs(const std::string& moduleName, bool relative, bool absolute)
{
	return map([&moduleName, relative, absolute](SafePointer safePointer) {
		return safePointer.findXREFs(moduleName, relative, absolute);
	});
}
#endif

Session Session::prevByteOccurence(const std::string& signature, std::optional<bool> code)
{
	return map([&signature, &code](SafePointer safePointer) {
		return safePointer.prevByteOccurence(signature);
	});
}
Session Session::nextByteOccurence(const std::string& signature, std::optional<bool> code)
{
	return map([&signature, &code](SafePointer safePointer) {
		return safePointer.nextByteOccurence(signature, code);
	});
}

Session Session::prevStringOccurence(const std::string& string)
{
	return map([&string](SafePointer safePointer) {
		return safePointer.prevStringOccurence(string);
	});
}
Session Session::nextStringOccurence(const std::string& string)
{
	return map([&string](SafePointer safePointer) {
		return safePointer.nextStringOccurence(string);
	});
}
