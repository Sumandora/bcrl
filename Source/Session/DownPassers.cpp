#include "BCRL.hpp"

#include <functional>
#include <vector>

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

BCRL::Session BCRL::Session::FindXREFs(XREFTypes types)
{
	return Map([types](SafePointer safePointer) {
		return safePointer.FindXREFs(types);
	});
}
#endif

BCRL::Session BCRL::Session::PrevOccurence(const std::string& signature)
{
	return Map([signature](SafePointer safePointer) {
		return safePointer.PrevOccurence(signature);
	});
}
BCRL::Session BCRL::Session::NextOccurence(const std::string& signature)
{
	return Map([signature](SafePointer safePointer) {
		return safePointer.NextOccurence(signature);
	});
}
