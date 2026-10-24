#include "pch.h"

void test_make_reverse_host()
{
	std::string s = "192.168.1.2";
	std::string s2 = "192.168.1.434331";
	MakeReverseHost(s);
	MakeReverseHost(s2);
	printf("%s\n%s", s.c_str(), s2.c_str());
}

void test() {
	test_make_reverse_host();
}
