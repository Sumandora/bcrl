#include "BCRL.hpp"

BCRL::Session BCRL::Session::Add(std::size_t operand)
{
	return Map([operand](SafePointer safePointer) {
		return safePointer.Add(operand);
	});
}
BCRL::Session BCRL::Session::Sub(std::size_t operand)
{
	return Map([operand](SafePointer safePointer) {
		return safePointer.Sub(operand);
	});
}
BCRL::Session BCRL::Session::Dereference()
{
	return Map([](SafePointer safePointer) {
		return safePointer.Dereference();
	});
}

BCRL::Session BCRL::Session::SetSafe(bool safe)
{
	BCRL::Session session = Map([safe](SafePointer safePointer) {
		return safePointer.SetSafe(safe);
	});
	session.safe = safe;
	return session;
}

BCRL::Session BCRL::Session::ToggleSafety()
{
	return Map([](SafePointer safePointer) {
		return safePointer.ToggleSafety();
	});
}

#if defined(__x86_64) || defined(i386)
BCRL::Session BCRL::Session::RelativeToAbsolute()
{
	return Map([](SafePointer safePointer) {
		return safePointer.RelativeToAbsolute();
	});
}

#ifndef BCLR_DISABLE_LDE
BCRL::Session BCRL::Session::PrevInstruction()
{
	return Map([](SafePointer safePointer) {
		return safePointer.PrevInstruction();
	});
}
BCRL::Session BCRL::Session::NextInstruction()
{
	return Map([](SafePointer safePointer) {
		return safePointer.NextInstruction();
	});
}
#endif

BCRL::Session BCRL::Session::FindXREFs(bool relative, bool absolute)
{
	return Map([relative, absolute](SafePointer safePointer) {
		return safePointer.FindXREFs(relative, absolute);
	});
}

BCRL::Session BCRL::Session::FindXREFs(const std::string& moduleName, bool relative, bool absolute)
{
	return Map([&moduleName, relative, absolute](SafePointer safePointer) {
		return safePointer.FindXREFs(moduleName, relative, absolute);
	});
}
#endif

BCRL::Session BCRL::Session::PrevByteOccurence(const std::string& signature)
{
	return Map([signature](SafePointer safePointer) {
		return safePointer.PrevByteOccurence(signature);
	});
}
BCRL::Session BCRL::Session::NextByteOccurence(const std::string& signature)
{
	return Map([signature](SafePointer safePointer) {
		return safePointer.NextByteOccurence(signature);
	});
}

BCRL::Session BCRL::Session::PrevStringOccurence(const std::string& string)
{
	return Map([string](SafePointer safePointer) {
		return safePointer.PrevStringOccurence(string);
	});
}
BCRL::Session BCRL::Session::NextStringOccurence(const std::string& string)
{
	return Map([string](SafePointer safePointer) {
		return safePointer.NextStringOccurence(string);
	});
}
