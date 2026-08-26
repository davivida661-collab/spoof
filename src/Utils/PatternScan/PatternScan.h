#pragma once

#include <ntifs.h>
#include <windef.h>


namespace SPOOFER_V3::Utils
{
	void* PatternScan(void* address, size_t size, const char* pattern, const char* mask);

	void* PatternScanSection(void* moduleBase, const char* pattern, const char* mask, const char* sectionName = ".text");

	bool CheckPattern(const char* data, const char* pattern, const char* mask);
}
