#include "BCRL.hpp"

#include <fstream>
#include <ranges>
#include <sstream>

using namespace BCRL;

MemoryRegionStorage::MemoryRegionStorage()
{
	if (!update())
		this->memoryRegions = {};
}

bool MemoryRegionStorage::update()
{
	decltype(memoryRegions) newMemoryRegions{};
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

		std::size_t dash = addressRange.find('-');
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

		newMemoryRegions[begin] = MemoryRegion{ begin, end - begin, columns[1][1] == 'w', columns[1][2] == 'x', fileName };
	}

	fileStream.close();

	this->memoryRegions = newMemoryRegions;
	return true;
}

const std::map<std::uintptr_t /*begin address*/, MemoryRegionStorage::MemoryRegion>& MemoryRegionStorage::getMemoryRegions() const
{
	return memoryRegions;
}

std::optional<std::reference_wrapper<const MemoryRegionStorage::MemoryRegion>> MemoryRegionStorage::addressRegion(std::uintptr_t address) const
{
	auto it = memoryRegions.lower_bound(address);
	if(it != memoryRegions.end() && it->first + it->second.length > address)
		return it->second;
	return std::nullopt;
}
