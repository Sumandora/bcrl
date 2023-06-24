#include "BCRL.hpp"

#include <cstddef>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <vector>

BCRL::MemoryRegionStorage::MemoryRegionStorage()
{
	if (!Update())
		this->memoryRegions = {};
}

bool BCRL::MemoryRegionStorage::Update()
{
	std::vector<MemoryRegion> memoryRegions{};
	std::fstream fileStream{ "/proc/self/maps", std::fstream::in };
	if (!fileStream) {
		this->memoryRegions = memoryRegions;
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

		if (columns.size() <= 6)
			continue;

		if (columns[1][0] != 'r')
			continue; // If the region isn't readable, why would we bother keeping it?

		if (std::stoi(columns[4]) == 0)
			continue; // Not a file mapping

		std::string& addressRange = columns[0];

		size_t dash = addressRange.find('-');
		std::uintptr_t begin = std::stol(addressRange.substr(0, dash), 0, 16);
		std::uintptr_t end = std::stol(addressRange.substr(dash + 1, addressRange.length()), 0, 16);

		memoryRegions.push_back({ { reinterpret_cast<std::byte*>(begin), end - begin }, columns[1][1] == 'w', columns[1][2] == 'x' });
	}

	fileStream.close();

	this->memoryRegions = memoryRegions;
	return true;
}

bool BCRL::MemoryRegionStorage::IsAddressReadable(void* address) const
{
    const MemoryRegion* memoryRegion = AddressRegion(address);
    return memoryRegion;
}

std::vector<BCRL::MemoryRegionStorage::MemoryRegion> BCRL::MemoryRegionStorage::GetMemoryRegions(std::optional<bool> writable, std::optional<bool> executable) const
{
	if (!writable.has_value() && !executable.has_value())
		return this->memoryRegions;

	std::vector<BCRL::MemoryRegionStorage::MemoryRegion> memoryRegions{};

	for (const MemoryRegion& memoryRegion : this->memoryRegions) {
		if (writable.has_value() && memoryRegion.writable != writable.value())
			continue;

		if (executable.has_value() && memoryRegion.executable != executable.value())
			continue;

		memoryRegions.push_back({ memoryRegion });
	}

	return memoryRegions;
}

const BCRL::MemoryRegionStorage::MemoryRegion* BCRL::MemoryRegionStorage::AddressRegion(void* address) const
{
    long left = 0;
    long right = memoryRegions.size() - 1;
    while (left <= right) {
        std::size_t middle = left + (right - left) / 2;
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
