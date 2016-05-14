#pragma once

#include <stdio.h>
#include "pin.H"
#include "OepFinder.h"
#include <time.h>
#include  "Debug.h"
#include "Config.h"
#include "FilterHandler.h"
#include "HookFunctions.h"
#include "HookSyscalls.h"


namespace W {
	#include <windows.h>

}


OepFinder oepf;
HookFunctions hookFun;
clock_t tStart;
ProcInfo *proc_info = ProcInfo::getInstance();
//PolymorphicCodePatches pcpatcher;

//------------------------------Custom option for our FindOEPpin.dll-------------------------------------------------------------------------

KNOB <UINT32> KnobInterWriteSetAnalysis(KNOB_MODE_WRITEONCE, "pintool",
    "iwae", "0" , "specify if you want or not to track the inter_write_set analysis dumps and how many jump");

KNOB <BOOL> KnobAntiEvasion(KNOB_MODE_WRITEONCE, "pintool",
    "antiev", "false" , "specify if you want or not to activate the anti evasion engine");

KNOB <BOOL> KnobAdvancedIATFixing(KNOB_MODE_WRITEONCE, "pintool",
    "adv-iatfix", "false" , "specify if you want or not to activate the advanced IAT fix technique");

//KNOB <BOOL> KnobPolymorphicCodePatch(KNOB_MODE_WRITEONCE, "pintool",
//    "poly-patch", "false" , "specify if you want or not to activate the patch in order to avoid crash during the instrumentation of polymorphic code");

//------------------------------Custom option for our FindOEPpin.dll-------------------------------------------------------------------------



// This function is called when the application exits
VOID Fini(INT32 code, VOID *v){
	//DEBUG --- inspect the write set at the end of the execution
	WxorXHandler *wxorxHandler = WxorXHandler::getInstance();
	MYINFO("WRITE SET SIZE: %d", wxorxHandler->getWritesSet().size());
	//DEBUG --- get the execution time
	MYINFO("Total execution Time: %.2fs", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	CLOSELOG();
	Config *config = Config::getInstance();
	config->closeReportFile();
}

//cc
INT32 Usage(){
	PIN_ERROR("This Pintool unpacks common packers\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

// - Get initial entropy
// - Get PE section data 
// - Add filtered library
void imageLoadCallback(IMG img,void *){

	/*for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){
		for( RTN rtn= SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) ){
			MYINFO("Inside %s -> %s",IMG_Name(img).c_str(),RTN_Name(rtn).c_str());
		}
	}*/

	Section item;
	static int va_hooked = 0;
	ProcInfo *proc_info = ProcInfo::getInstance();
	FilterHandler *filterHandler = FilterHandler::getInstance();

	//get the initial entropy of the PE
	//we have to consder only the main executable and av�void the libraries
	if(IMG_IsMainExecutable(img)){
		
		ADDRINT startAddr = IMG_LowAddress(img);
		ADDRINT endAddr = IMG_HighAddress(img);
		proc_info->setMainIMGAddress(startAddr, endAddr);
		//get the  address of the first instruction
		proc_info->setFirstINSaddress(IMG_Entry(img));
		//get the program name
		proc_info->setProcName(IMG_Name(img));
		//get the initial entropy
		MYINFO("----------------------------------------------");
		float initial_entropy = proc_info->GetEntropy();
		proc_info->setInitialEntropy(initial_entropy);
		MYINFO("----------------------------------------------");
		//retrieve the section of the PE
		for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ){
			item.name = SEC_Name(sec);
			item.begin = SEC_Address(sec);
			item.end = item.begin + SEC_Size(sec);
			proc_info->insertSection(item);
		}
		//DEBUG
		proc_info->PrintSections();
	}
	//build the filtered libtrary list
	ADDRINT startAddr = IMG_LowAddress(img);
	ADDRINT endAddr = IMG_HighAddress(img);
	const string name = IMG_Name(img); 
	
	if(!IMG_IsMainExecutable(img)){	
		
		//*** If you need to protect other sections of other dll put them here ***

		hookFun.hookDispatcher(img);		
		
		proc_info->addLibrary(name,startAddr,endAddr);

		if(filterHandler->IsNameInFilteredArray(name)){
			filterHandler->addToFilteredLibrary(name,startAddr,endAddr);
			MYINFO("Added to the filtered array the module %s\n" , name);
		}
	}
	
}

void DetachFunc(){
	PIN_Detach();
}

// Instruction callback Pin calls this function every time a new instruction is encountered
// (Testing if better than trace iteration)
void Instruction(INS ins,void *v){

	//printf("ADDR %08x - INS %s\n" , INS_Address(ins), INS_Disassemble(ins).c_str());
	/*
	MemoryRange mem;
	
	ProcInfo::getInstance()->getMemoryRange(0x75e714a4 ,mem);

	if(mem.StartAddress <= 0x75e714a4  &&  0x75e714a4  <= mem.EndAddress){
		MYINFO("yyyyyyyyyyyyyyyyyNow the address has been mapped EIP:%08x  mapped from %08x -> %08x name %s",INS_Address(ins),mem.StartAddress,mem.EndAddress,RTN_FindNameByAddress(INS_Address(ins)).c_str());
	}
	else{ 
		MYINFO("zzzzzzCur EIP:%08x name %s ",INS_Address(ins),RTN_FindNameByAddress(INS_Address(ins)).c_str());
	}
	*/

		oepf.IsCurrentInOEP(ins);

	

}


VOID Trace(TRACE trace,void *v){
	//pcpatcher.inspectTrace(trace);
}


// - retrive the stack base address
static VOID OnThreadStart(THREADID, CONTEXT *ctxt, INT32, VOID *){

	ADDRINT stackBase = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	ProcInfo *pInfo = ProcInfo::getInstance();
	pInfo->addThreadStackAddress(stackBase);
	pInfo->addThreadTebAddress();

	MYINFO("-----------------a NEW Thread started!--------------------\n");
}

void initDebug(){
	DEBUG_MODE mode;
	mode._type = DEBUG_CONNECTION_TYPE_TCP_SERVER;
	mode._options = DEBUG_MODE_OPTION_STOP_AT_ENTRY;
	PIN_SetDebugMode(&mode);
}

void ConfigureTool(){
	
	Config *config = Config::getInstance();
	config->INTER_WRITESET_ANALYSIS_ENABLE = KnobInterWriteSetAnalysis.Value();	
	config->ADVANCED_IAT_FIX = KnobAdvancedIATFixing.Value();
//	config->POLYMORPHIC_CODE_PATCH = KnobPolymorphicCodePatch.Value();


	if(KnobInterWriteSetAnalysis.Value() > 1 && KnobInterWriteSetAnalysis.Value() <= Config::MAX_JUMP_INTER_WRITE_SET_ANALYSIS ){
		config->WRITEINTERVAL_MAX_NUMBER_JMP = KnobInterWriteSetAnalysis.Value();
	}
	else{
		MYWARN("Invalid number of jumps to track, se to default value: 2\n");
		config->WRITEINTERVAL_MAX_NUMBER_JMP = 2; // default value is 2 if we have invalid value 
	}
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v){
	
	MYINFO("ECC!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	MYINFO("%s",PIN_ExceptionToString(pExceptInfo).c_str());
	MYINFO("ECC!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

	return EHR_CONTINUE_SEARCH;

}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[]){

	//If we want to debug the program manually setup the proper options in order to attach an external debugger
	if(Config::ATTACH_DEBUGGER){
		initDebug();
	}

	MYINFO("->Configuring Pintool<-\n");

	//get the start time of the execution (benchmark)
	tStart = clock();
	
	// Initialize pin
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) return Usage();

	//Register PIN Callbacks
	INS_AddInstrumentFunction(Instruction,0);
	
	//TRACE_AddInstrumentFunction(Trace,0);

	PIN_AddThreadStartFunction(OnThreadStart, 0);

	IMG_AddInstrumentFunction(imageLoadCallback, 0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_AddInternalExceptionHandler(ExceptionHandler,NULL);

	//get theknob args
	ConfigureTool();

	if(Config::getInstance()->POLYMORPHIC_CODE_PATCH){
		TRACE_AddInstrumentFunction(Trace,0);
	}
	proc_info->addPebAddress();

	//init the hooking system
	HookSyscalls::enumSyscalls();
	HookSyscalls::initHooks();
	// Start the program, never returns

	MYINFO("->Starting instrumented program<-\n");


	PIN_StartProgram();
	
	return 0;
	
}
