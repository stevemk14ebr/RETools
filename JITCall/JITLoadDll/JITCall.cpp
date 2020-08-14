#include "JITCall.hpp"

asmjit::CallConv::Id JITCall::getCallConv(const std::string& conv) {
	if (conv == "cdecl") {
		return asmjit::CallConv::kIdHostCDecl;
	} else if (conv == "stdcall") {
		return asmjit::CallConv::kIdHostStdCall;
	} else if (conv == "fastcall") {
		return asmjit::CallConv::kIdHostFastCall;
	}
	return asmjit::CallConv::kIdHost;
}

#define TYPEID_MATCH_STR_IF(var, T) if (var == #T) { return asmjit::Type::IdOfT<T>::kTypeId; }
#define TYPEID_MATCH_STR_ELSEIF(var, T)  else if (var == #T) { return asmjit::Type::IdOfT<T>::kTypeId; }

uint8_t JITCall::getTypeId(const std::string& type) {
	// we only care about ptr value, size doesn't matter
	// so just use a uintptr size for any type
	if (type.find("*") != std::string::npos) {
		return asmjit::Type::kIdUIntPtr;
	}

	TYPEID_MATCH_STR_IF(type, signed char)
		TYPEID_MATCH_STR_ELSEIF(type, unsigned char)
		TYPEID_MATCH_STR_ELSEIF(type, short)
		TYPEID_MATCH_STR_ELSEIF(type, unsigned short)
		TYPEID_MATCH_STR_ELSEIF(type, int)
		TYPEID_MATCH_STR_ELSEIF(type, unsigned int)
		TYPEID_MATCH_STR_ELSEIF(type, long)
		TYPEID_MATCH_STR_ELSEIF(type, unsigned long)
		TYPEID_MATCH_STR_ELSEIF(type, __int64)
		TYPEID_MATCH_STR_ELSEIF(type, unsigned __int64)
		TYPEID_MATCH_STR_ELSEIF(type, long long)
		TYPEID_MATCH_STR_ELSEIF(type, unsigned long long)
		TYPEID_MATCH_STR_ELSEIF(type, char)
		TYPEID_MATCH_STR_ELSEIF(type, char16_t)
		TYPEID_MATCH_STR_ELSEIF(type, char32_t)
		TYPEID_MATCH_STR_ELSEIF(type, wchar_t)
		TYPEID_MATCH_STR_ELSEIF(type, uint8_t)
		TYPEID_MATCH_STR_ELSEIF(type, int8_t)
		TYPEID_MATCH_STR_ELSEIF(type, uint16_t)
		TYPEID_MATCH_STR_ELSEIF(type, int16_t)
		TYPEID_MATCH_STR_ELSEIF(type, int32_t)
		TYPEID_MATCH_STR_ELSEIF(type, uint32_t)
		TYPEID_MATCH_STR_ELSEIF(type, uint64_t)
		TYPEID_MATCH_STR_ELSEIF(type, int64_t)
		TYPEID_MATCH_STR_ELSEIF(type, float)
		TYPEID_MATCH_STR_ELSEIF(type, double)
		TYPEID_MATCH_STR_ELSEIF(type, bool)
		TYPEID_MATCH_STR_ELSEIF(type, void)
	else if (type == "intptr_t") {
		return asmjit::Type::kIdIntPtr;
	} else if (type == "uintptr_t") {
		return asmjit::Type::kIdUIntPtr;
	}

	return asmjit::Type::kIdVoid;
}

JITCall::tJitCall JITCall::getJitFunc(const asmjit::FuncSignature& sig, JITCall::WaitType waitType) {
	SimpleErrorHandler eh;
	asmjit::CodeHolder code;                        // Holds code and relocation information.
	code.init(m_jitRuntime.environment());             // Initialize to the same arch as JIT runtime.
	code.setErrorHandler(&eh);

	asmjit::StringLogger log;
	uint32_t kFormatFlags = asmjit::FormatOptions::kFlagMachineCode | asmjit::FormatOptions::kFlagExplainImms | asmjit::FormatOptions::kFlagRegCasts
		| asmjit::FormatOptions::kFlagAnnotations | asmjit::FormatOptions::kFlagDebugPasses | asmjit::FormatOptions::kFlagDebugRA
		| asmjit::FormatOptions::kFlagHexImms | asmjit::FormatOptions::kFlagHexOffsets | asmjit::FormatOptions::kFlagPositions;

	log.addFlags(kFormatFlags);

	code.setLogger(&log);

	asmjit::x86::Compiler cc(&code);
	asmjit::FuncNode* func = cc.addFunc(           // Create the wrapper function around call we JIT
		asmjit::FuncSignatureT<void, JITCall::Parameters*>());

	asmjit::x86::Gp paramImm = cc.newUIntPtr();
	asmjit::x86::Gp i = cc.newUIntPtr();
	cc.setArg(0, paramImm);

	// paramMem = ((char*)paramImm) + i (char* size walk, uint64_t size r/w)
	asmjit::x86::Mem paramMem = asmjit::x86::ptr(paramImm, i);
	paramMem.setSize(sizeof(uint64_t));

	// i = 0
	cc.mov(i, 0);

	struct ArgRegSlot {
		ArgRegSlot(uint32_t idx) {
			argIdx = idx;
			useHighReg = false;
		}

		asmjit::x86::Reg low;
		asmjit::x86::Reg high;

		uint32_t argIdx;
		bool useHighReg;
	};

	// map argument slots to registers, following abi. (We can have multiple register per arg slot such as high and low 32bits of a 64bit slot)
	std::vector<ArgRegSlot> argRegSlots;
	uint32_t offsetNextSlot = sizeof(uint64_t);
	for (uint8_t arg_idx = 0; arg_idx < sig.argCount(); arg_idx++) {
		const uint8_t argType = sig.args()[arg_idx];

		// increment arg slot if not first one
		if (arg_idx != 0) {
			cc.add(i, offsetNextSlot);
			offsetNextSlot = sizeof(uint64_t);
		}

		ArgRegSlot argSlot(arg_idx);
		if (isGeneralReg(argType)) {
			argSlot.low = cc.newUIntPtr();
			cc.mov(argSlot.low.as<asmjit::x86::Gp>(), paramMem);

			if (hasHiArgSlot(cc, argType)) {
				cc.add(i, sizeof(uint32_t));
				offsetNextSlot -= sizeof(uint32_t);

				argSlot.high = cc.newUIntPtr();
				argSlot.useHighReg = true;
				cc.mov(argSlot.high.as<asmjit::x86::Gp>(), paramMem);
			}
		} else if (isXmmReg(argType)) {
			argSlot.low = cc.newXmm();
			cc.movq(argSlot.low.as<asmjit::x86::Xmm>(), paramMem);
		} else {
			// ex: void example(__m128i xmmreg) is invalid: https://github.com/asmjit/asmjit/issues/83
			ErrorLog::singleton().push("Parameters wider than 64bits not supported", ErrorLevel::SEV);
			return 0;
		}

		argRegSlots.push_back(argSlot);
	}

	// allows debuggers to trap
	if (waitType == JITCall::WaitType::INT3) {
		cc.int3();
	} else if (waitType == JITCall::WaitType::WAIT_KEYPRESS) {
		asmjit::InvokeNode* invokeNode;
		cc.invoke(&invokeNode,
			(uint64_t)&getchar,
			asmjit::FuncSignatureT<int>()
		);
	}

	// Gen the call
	asmjit::InvokeNode* invokeNode;
	cc.invoke(&invokeNode,
		(uint64_t)m_Target,
		sig
	);
	
	// Map call params to the args
	for (auto argSlot : argRegSlots) {
		invokeNode->setArg(argSlot.argIdx, 0, argSlot.low);
		if (argSlot.useHighReg) {
			invokeNode->setArg(argSlot.argIdx, 1, argSlot.high);
		}
	}

	cc.ret();
	cc.endFunc();                           // End of the function body.

	cc.finalize();
	// ----> x86::Compiler is no longer needed from here and can be destroyed <----

	tJitCall wrapperFunc;
	asmjit::Error err = m_jitRuntime.add(&wrapperFunc, &code);
	if (err) {
		//printf("Error: %s\nGenerated so far%s\n", asmjit::DebugUtils::errorAsString(err), log.data());
		return 0;
	}

	// ----> CodeHolder is no longer needed from here and can be destroyed <----
	printf("JIT Wrapper:\n%s\n", log.data());
	return wrapperFunc;
}

JITCall::tJitCall JITCall::getJitFunc(const std::string& retType, const std::vector<std::string>& paramTypes, std::string callConv/* = ""*/, JITCall::WaitType waitType /* = WaitType::NONE*/) {
	asmjit::FuncSignature sig;
	std::vector<uint8_t> args;
	for (const std::string& s : paramTypes) {
		args.push_back(getTypeId(s));
	}
	sig.init(getCallConv(callConv), asmjit::FuncSignature::kNoVarArgs, getTypeId(retType), args.data(), (uint32_t)args.size());
	return getJitFunc(sig, waitType);
}

bool JITCall::isGeneralReg(const uint8_t typeId) const {
	switch (typeId) {
	case asmjit::Type::kIdI8:
	case asmjit::Type::kIdU8:
	case asmjit::Type::kIdI16:
	case asmjit::Type::kIdU16:
	case asmjit::Type::kIdI32:
	case asmjit::Type::kIdU32:
	case asmjit::Type::kIdI64:
	case asmjit::Type::kIdU64:
	case asmjit::Type::kIdIntPtr:
	case asmjit::Type::kIdUIntPtr:
		return true;
	default:
		return false;
	}
}

bool JITCall::isXmmReg(const uint8_t typeId) const {
	switch (typeId) {
	case  asmjit::Type::kIdF32:
	case asmjit::Type::kIdF64:
		return true;
	default:
		return false;
	}
}

bool JITCall::hasHiArgSlot(const asmjit::x86::Compiler& compiler, const uint8_t typeId) const {
	// 64bit width regs can fit wider args
	if (compiler.is64Bit()) {
		return false;
	}

	switch (typeId) {
	case asmjit::Type::kIdI64:
	case asmjit::Type::kIdU64:
		return true;
	}
	return false;
}

JITCall::JITCall(uint64_t target) {
	m_Target = target;
}

JITCall::JITCall(char* target) {
	m_Target = (uint64_t)target;
}

JITCall::~JITCall() {

}