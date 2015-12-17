#include "FakeMemoryHandler.h"




FakeMemoryHandler::FakeMemoryHandler(void)
{
	pInfo = ProcInfo::getInstance();
	//Populating the ntdll function patch  table
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserApcDispatcher","\x8D\x84\x24\xDC\x02\x00\x00"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserCallbackDispatcher","\x64\x8B\x0D\x00\x00\x00\x00"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("KiUserExceptionDispatcher","\xFC\x8B\x4C\x24\x04"));
	ntdllHooksNamesPatch.insert(std::pair<string,string>("LdrInitializeThunk","\x8B\xFF\x55\x8B\xEC"));
	
}



FakeMemoryHandler::~FakeMemoryHandler(void)
{
}

ADDRINT FakeMemoryHandler::ntdllFuncPatch(ADDRINT curReadAddr, ADDRINT ntdllFuncAddr){
	string patch = ntdllHooksAddrPatch.at(ntdllFuncAddr);
	int delta = curReadAddr - ntdllFuncAddr;
	curFakeMemory = patch.substr(delta,string::npos);
	ADDRINT patchAddr = (ADDRINT)&curFakeMemory;
	//MYINFO("read at %08x containig %02x  Patched address %08x with string %02x \n",curReadAddr, *(char *)curReadAddr,patchAddr,*(char *)curFakeMemory.c_str());
	return patchAddr;
}



VOID FakeMemoryHandler::initFakeMemory(){
	//Hide the ntdll hooks
	for(map<string,string>::iterator it = ntdllHooksNamesPatch.begin(); it != ntdllHooksNamesPatch.end();++it){
		const char  *funcName = it->first.c_str();
		string patch = it->second;
		ADDRINT address = (ADDRINT)W::GetProcAddress(W::GetModuleHandle("ntdll.dll"), funcName);		
		ntdllHooksAddrPatch.insert(std::pair<ADDRINT,string>(address,patch));

		FakeMemoryItem fakeMem;
		fakeMem.StartAddress = address;
		fakeMem.EndAddress = address + patch.length()-1; //-1 beacuse need to exclude the trailing 0x00
		fakeMem.func = &FakeMemoryHandler::ntdllFuncPatch;
		fakeMemory.push_back(fakeMem);
		MYINFO("Add FakeMemory ntdll %s addr  %08x -> %08x",funcName,fakeMem.StartAddress,fakeMem.EndAddress);
	}
	//add other FakeMemoryItem to the fakeMemory array for handling other cases
	
}

ADDRINT FakeMemoryHandler::getFakeMemory(ADDRINT address){

	//Check if address is inside the FakeMemory array (need to modify the result of the read)
	for(std::vector<FakeMemoryItem>::iterator it = fakeMemory.begin(); it != fakeMemory.end(); ++it){
		if(it->StartAddress <= address && address <= it->EndAddress){
			//MYINFO("Found address in FakeMemory %08x\n",address);
			//Executing the PatchFunction associated to this memory range which contains the address
			ADDRINT patchedAddr = it->func(address,it->StartAddress);
			//MYINFO("Found address in FakeMemory %08x ",address);
			MYINFO("Found FakeMemory read at %08x containig %02x  Patched at %08x with %02x\n",address, *(unsigned char *)address,patchedAddr, *(unsigned char *)(*(string *)patchedAddr).c_str());
			return patchedAddr;
		}
	}

	//Check if the address is inside the WhiteListed addresses( need to return the correct value)
	if(isAddrInWhiteList(address)){
		return address;
	}
	//Read address is outside of the Whitelist probably in the PIN address space (need to return some random garbage)
	else{
		MYINFO("Detected suspicious read at %08x containig %02x",address,*(unsigned char*)address);
		curFakeMemory = "TopoMotoTopoMotoTopoMotoTopoMotoTopoMotoTopoMotoTopoMoto";
		return NULL;
	}
	
}


/**
Check if address is inside:
	- Main executable
	- Stack
	- Dynamically allocated memory
	- Teb
	- Peb
	- generic memory region (SharedMemory pContextData..)
	**/
BOOL FakeMemoryHandler::isAddrInWhiteList(ADDRINT address){

	//Main IMG
	if(pInfo->isInsideMainIMG(address)){
		return TRUE;
	}
	//Stack
	if(pInfo->isStackAddress(address)){
		return TRUE;
	}
	//Dynamic Allocation
	if(pInfo->searchHeapMap(address)!= -1){
		return TRUE;
	}
	
	//Library Addresses
	if (pInfo->isLibraryInstruction(address)){
		return TRUE;
	}
	//Teb Addresses
	if(pInfo->isTebAddress(address)){
		return TRUE;
	}
	//Peb Addresses
	if(pInfo->isPebAddress(address)){
		return TRUE;
	}
	//Generic memory addresses (pContextData ..)
	if(pInfo->isGenericMemoryAddress(address)){
		return TRUE;
	}

	return FALSE;
	
}