#include "BCRL.hpp"

#include "SignatureScanner.hpp"

using namespace BCRL;

bool SafePointer::isInModule(const std::string& moduleName) const
{
	auto module = memoryRegionStorage.addressRegion(pointer);
	return module.has_value() && module->get().name->ends_with(moduleName);
}
