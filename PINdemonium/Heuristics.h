#pragma once
#include "pin.H"
#include "Debug.h"
#include "Config.h"
#include "OepFinder.h"
#include "LongJumpHeuristic.h"
#include "EntropyHeuristic.h"
#include "JumpOuterSectionHeuristic.h"
#include "InitFunctionCallHeuristic.h"
#include "WxorXHandler.h"
#include "PushadPopadHeuristic.h"


//static class where you have to define all the methods that o some kind of heuristic
class Heuristics
{
public:
	static UINT32 longJmpHeuristic(INS ins, ADDRINT prev_ip);
	static UINT32 entropyHeuristic();
	static UINT32 jmpOuterSectionHeuristic(INS ins, ADDRINT prev_ip);
	static UINT32 initFunctionCallHeuristic(ADDRINT curEip, WriteInterval* wi);
	static UINT32 pushadPopadHeuristic();
};


