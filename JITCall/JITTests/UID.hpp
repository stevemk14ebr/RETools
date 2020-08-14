#pragma once
#include <atomic>

class UID {
public:
	UID(long val) {
		this->val = val;
	}

	static std::atomic_long& singleton() {
		static std::atomic_long base = { -1 };
		base++;
		return base;
	}

	long	val;
};