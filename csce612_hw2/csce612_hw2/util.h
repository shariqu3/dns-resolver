// Mohammed Sharique CSCE-612 Fall 2026
#pragma once
#include "stdarg.h"

struct Timer
{
    std::chrono::time_point<std::chrono::steady_clock> start;
	Timer();
	long Elapsed();
	void Stop();
};

static inline int SafeSNPrintf(char *buf, size_t size, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	int res = vsnprintf(buf, size, format, args);

	if (res >= size)
		throw std::runtime_error("snprintf overflow");
	va_end(args);
	return res;
}
