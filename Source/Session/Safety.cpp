#include "BCRL.hpp"

using namespace BCRL;

Session Session::setSafety(bool newSafeness) const
{
	return { pointers, newSafeness };
}

bool Session::isSafe() const
{
	return safe;
}

Session Session::toggleSafety() const
{
	return { pointers, !isSafe() };
}
