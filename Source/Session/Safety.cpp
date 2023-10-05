#include "BCRL.hpp"

using namespace BCRL;

Session Session::setSafety(bool newSafeness) const
{
	return { pointers, newSafeness };
}

Session Session::toggleSafety() const
{
	return { pointers, !isSafe() };
}
