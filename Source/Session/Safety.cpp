#include "BCRL.hpp"

using namespace BCRL;

Session& Session::setSafety(bool newSafeness)
{
	safe = newSafeness;
	return *this;
}

bool Session::isSafe() const
{
	return safe;
}

Session& Session::toggleSafety()
{
	safe = !safe;
	return *this;
}
