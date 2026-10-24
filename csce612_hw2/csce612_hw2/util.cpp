// Mohammed Sharique CSCE-612 Fall 2026
#include "pch.h"

Timer::Timer()
{
	start = std::chrono::steady_clock::now();
}

long Timer::Elapsed()
{
	auto end = std::chrono::steady_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	return duration.count();
}
