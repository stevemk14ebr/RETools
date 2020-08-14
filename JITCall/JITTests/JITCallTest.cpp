#include "../JITLoadDll/JITCall.hpp"
#include "EffectTracker.hpp"
#include "catch.hpp"

#include <limits>

EffectTracker effects;

// do some random logic in the attempt to trigger an exception if jit is wrong
#define uselessOps() volatile int i = 10; i++; i--; i *= i; printf("Ignore me: %i\n", i) 

// only trigger function as successful if condition is true
#define triggerIf(cond) if (cond) { effects.PeakEffect().trigger(); }

NOINLINE void __cdecl noArgsCdecl() {
	uselessOps();
	effects.PeakEffect().trigger();
}

NOINLINE void __stdcall noArgsStd() {
	uselessOps();
	effects.PeakEffect().trigger();
}

NOINLINE void __fastcall noArgsFast() {
	uselessOps();
	effects.PeakEffect().trigger();
}

NOINLINE void __cdecl intArgsCdecl(int one, uint8_t two, int8_t negthree, uint64_t max64Four, int64_t maxneg64Four, bool lastBool) {
	uselessOps();
	triggerIf(one == 1 && two == 2 && negthree == -3 &&
		max64Four == std::numeric_limits<uint64_t>::max() &&
		maxneg64Four == std::numeric_limits<int64_t>::min() &&
		lastBool == true
	);
}

NOINLINE void __cdecl intArgsStd(int one, uint8_t two, int8_t negthree, uint64_t max64Four, int64_t maxneg64Four, bool lastBool) {
	uselessOps();
	triggerIf(one == 1 && two == 2 && negthree == -3 &&
		max64Four == std::numeric_limits<uint64_t>::max() &&
		maxneg64Four == std::numeric_limits<int64_t>::min() &&
		lastBool == true
	);
}

NOINLINE void __cdecl intArgsFast(int one, uint8_t two, int8_t negthree, uint64_t max64Four, int64_t maxneg64Four, bool lastBool) {
	uselessOps();
	triggerIf(one == 1 && two == 2 && negthree == -3 &&
		max64Four == std::numeric_limits<uint64_t>::max() &&
		maxneg64Four == std::numeric_limits<int64_t>::min() &&
		lastBool == true
	);
}

TEST_CASE("Test function JIT", "[JITCall]") {
	SECTION("No parameters") {
		// cdecl
		{
			JITCall jit((uint64_t)&noArgsCdecl);

			JITCall::tJitCall jitFunc = jit.getJitFunc("void", {}, "cdecl");
			JITCall::Parameters params(0);

			effects.PushEffect();
			jitFunc(params.getDataPtr());
			REQUIRE(effects.PopEffect().didExecute());
		}

		// stdcall
		{
			JITCall jit((uint64_t)&noArgsStd);

			JITCall::tJitCall jitFunc = jit.getJitFunc("void", {}, "stdcall");
			JITCall::Parameters params(0);

			effects.PushEffect();
			jitFunc(params.getDataPtr());
			REQUIRE(effects.PopEffect().didExecute());
		}

		// fastcall
		{
			JITCall jit((uint64_t)&noArgsFast);

			JITCall::tJitCall jitFunc = jit.getJitFunc("void", {}, "fastcall");
			JITCall::Parameters params(0);

			effects.PushEffect();
			jitFunc(params.getDataPtr());
			REQUIRE(effects.PopEffect().didExecute());
		}
	}

	SECTION("Int parameters") {
		// cdecl
		{
			JITCall jit((uint64_t)&intArgsCdecl);

			JITCall::tJitCall jitFunc = jit.getJitFunc("void", {"int", "uint8_t", "int8_t", "uint64_t", "int64_t", "bool"}, "cdecl");
			JITCall::Parameters params(6);
			params.setArg<int>(0, 1);
			params.setArg<uint8_t>(1, 2);
			params.setArg<int8_t>(2, -3);
			params.setArg<uint64_t>(3, std::numeric_limits<uint64_t>::max());
			params.setArg<int64_t>(4, std::numeric_limits<int64_t>::min());
			params.setArg<bool>(5, true);

			effects.PushEffect();
			jitFunc(params.getDataPtr());
			REQUIRE(effects.PopEffect().didExecute());
		}

		// stdcall
		{
			JITCall jit((uint64_t)&intArgsStd);

			JITCall::tJitCall jitFunc = jit.getJitFunc("void", { "int", "uint8_t", "int8_t", "uint64_t", "int64_t", "bool" }, "stdcall");
			JITCall::Parameters params(6);
			params.setArg<int>(0, 1);
			params.setArg<uint8_t>(1, 2);
			params.setArg<int8_t>(2, -3);
			params.setArg<uint64_t>(3, std::numeric_limits<uint64_t>::max());
			params.setArg<int64_t>(4, std::numeric_limits<int64_t>::min());
			params.setArg<bool>(5, true);

			effects.PushEffect();
			jitFunc(params.getDataPtr());
			REQUIRE(effects.PopEffect().didExecute());
		}

		// fastcall
		{
			JITCall jit((uint64_t)&intArgsFast);

			JITCall::tJitCall jitFunc = jit.getJitFunc("void", { "int", "uint8_t", "int8_t", "uint64_t", "int64_t", "bool" }, "fastcall");
			JITCall::Parameters params(6);
			params.setArg<int>(0, 1);
			params.setArg<uint8_t>(1, 2);
			params.setArg<int8_t>(2, -3);
			params.setArg<uint64_t>(3, std::numeric_limits<uint64_t>::max());
			params.setArg<int64_t>(4, std::numeric_limits<int64_t>::min());
			params.setArg<bool>(5, true);

			effects.PushEffect();
			jitFunc(params.getDataPtr());
			REQUIRE(effects.PopEffect().didExecute());
		}
	}
}