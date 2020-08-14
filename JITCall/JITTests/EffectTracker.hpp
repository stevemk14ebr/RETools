#pragma once
#include <vector>
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

class Effect {
public:
	Effect();

	Effect& operator=(const Effect& rhs);

	void trigger();

	bool didExecute();
private:
	bool m_executed;
	UID m_uid;
};

/**Track if some side effect happened.**/
class EffectTracker {
public:
	void PushEffect();
	Effect PopEffect();
	Effect& PeakEffect();
private:
	std::vector<Effect> m_effectQ;
};