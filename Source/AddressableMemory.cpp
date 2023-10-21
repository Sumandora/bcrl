#include "BCRL.hpp"

#include <fstream>
#include <sstream>

using namespace BCRL;

MemoryRegionStorage::MemoryRegionStorage()
{
	if (!update())
		this->memoryRegions = {};
}

bool MemoryRegionStorage::update()
{
	std::vector<MemoryRegion> newMemoryRegions{};
	std::fstream fileStream{ "/proc/self/maps", std::fstream::in };
	if (!fileStream) {
		this->memoryRegions = newMemoryRegions;
		return false;
	}

	for (std::string line; std::getline(fileStream, line);) {
		if (line.empty())
			continue; // ?

		std::vector<std::string> columns{};
		std::stringstream ss{ line };
		std::string part{};
		while (std::getline(ss, part, ' '))
			columns.push_back(part);

		if (columns[1][0] != 'r')
			continue; // If the region isn't readable, why would we bother keeping it?

		std::string& addressRange = columns[0];

		size_t dash = addressRange.find('-');
		std::uintptr_t begin = std::stol(addressRange.substr(0, dash), nullptr, 16);
		std::uintptr_t end = std::stol(addressRange.substr(dash + 1, addressRange.length()), nullptr, 16);

		std::optional<std::string> fileName = std::nullopt;
		if (columns.size() > 5) {
			std::string name;
			for (size_t i = 5; i < columns.size(); i++) {
				if (!columns[i].empty() && columns[i] != "(deleted)")
					name += columns[i] + " ";
			}
			name = name.substr(0, name.length() - 1);
			if (name.starts_with("["))
				continue;
			else if (!name.empty())
				fileName = name;
		}

		newMemoryRegions.push_back({ { reinterpret_cast<std::byte*>(begin), end - begin }, columns[1][1] == 'w', columns[1][2] == 'x', fileName });
	}

	fileStream.close();

	this->memoryRegions = newMemoryRegions;
	return true;
}

std::vector<MemoryRegionStorage::MemoryRegion> MemoryRegionStorage::getMemoryRegions(std::optional<bool> writable, std::optional<bool> executable, std::optional<std::string> name) const
{
	std::vector<MemoryRegionStorage::MemoryRegion> selectedMemoryRegions{};

	for (const MemoryRegion& memoryRegion : memoryRegions) {
		if (writable.has_value() && memoryRegion.writable != writable.value())
			continue;

		if (executable.has_value() && memoryRegion.executable != executable.value())
			continue;

		if (name.has_value() && (!memoryRegion.name.has_value() || !memoryRegion.name.value().ends_with('/' + name.value())))
			continue;

		selectedMemoryRegions.push_back({ memoryRegion });
	}

	return selectedMemoryRegions;
}

const MemoryRegionStorage::MemoryRegion* MemoryRegionStorage::addressRegion(void* address) const
{
	long left = 0;
	long right = (long)memoryRegions.size() - 1;
	while (left <= right) {
		long middle = left + (right - left) / 2;
		const MemoryRegion& memoryRegion = memoryRegions[middle];
		if (&memoryRegion.addressSpace.front() <= address && address < &memoryRegion.addressSpace.back())
			return &memoryRegion;

		if (address < &memoryRegion.addressSpace.front())
			right = middle - 1;
		else
			left = middle + 1;
	}
	return nullptr;
}
