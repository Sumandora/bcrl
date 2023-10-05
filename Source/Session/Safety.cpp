#include "BCRL.hpp"

using namespace BCRL;

Session Session::setSafety(bool newSafeness)
{
	return { pointers, newSafeness };
}

Session Session::toggleSafety()
{
	return { pointers, !isSafe() };
}
