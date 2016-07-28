#include "DumpingModule.h"


DumpingModule::DumpingModule(void)
{
	config = Config::getInstance();
	pinfo = ProcInfo::getInstance();
}


DumpingModule::~DumpingModule(void)
{
	
}

UINT32 DumpingModule::DumpMainModule(W::DWORD pid,ADDRINT curEip,char *tmpDumpFile){

	char  originalExe[MAX_PATH]; // Path of the original PE which as launched the current process
	//getting the Base Address
	W::DWORD_PTR hMod = GetExeModuleBase(pid);
	if(!hMod){
		MYINFO("Can't find PID");
	}
	
	MYINFO("GetExeModuleBase %08x", hMod);

	//Dumping Process
	BOOL success = GetFilePathFromPID(pid,originalExe);
	if(!success){
		MYINFO("Error in getting original Path from Pid: %d",pid);
		return SCYLLA_ERROR_FILE_FROM_PID;
	}
	
	MYINFO("Original Exe Path: %s    ",originalExe);
	ScyllaWrapperInterface *scylla_wrapper = ScyllaWrapperInterface::getInstance();
		
	scylla_wrapper->loadScyllaLibary();
	success = scylla_wrapper->ScyllaDumpProcessA(pid,originalExe,hMod,curEip,tmpDumpFile);
	scylla_wrapper->unloadScyllaLibrary();
	if(!success){
		MYINFO("[SCYLLA DUMP] Error Dumping  Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,curEip,tmpDumpFile);
		return SCYLLA_ERROR_DUMP;
	}
	MYINFO("[SCYLLA DUMP] Successfully dumped Pid: %d, FileToDump: %S, Hmod: %X, oep: %X, output: %S ",pid,originalExe,hMod,curEip,tmpDumpFile);
	return 0;
}


/**
Extract the .EXE file which has lauched the process having PID pid
**/
BOOL DumpingModule::GetFilePathFromPID(W::DWORD dwProcessId, char *filename){
	
	W::HANDLE processHandle = NULL;

	processHandle = W::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	if (processHandle) {
		W::DWORD size = MAX_PATH;
		if (W::QueryFullProcessImageName(processHandle,0, filename, &size) == 0) {
		

			MYERRORE("Failed to get module filename.\n");
			return false;
		}
	CloseHandle(processHandle);
	} else {
		MYERRORE("Failed to open process.\n" );
		return false;
	}
		MYINFO("Process file path %s ",filename);
	return true;
	
}


W::DWORD_PTR DumpingModule::GetExeModuleBase(W::DWORD dwProcessId)
{
	W::MODULEENTRY32 lpModuleEntry = { 0 };
	W::HANDLE hSnapShot = W::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	Module32First(hSnapShot, &lpModuleEntry);

	CloseHandle(hSnapShot);

	return (W::DWORD_PTR)lpModuleEntry.modBaseAddr;
}


UINT32 DumpingModule::DumpLibrary(ADDRINT curEip, string tmpDump){
	MYINFO("Dumping Library ");
	LibraryItem* lib = pinfo->getLibraryItem(curEip);
	if (lib == NULL){
		return SCYLLA_ERROR_DUMP;

	}
	string name = lib->name;
	ADDRINT start_addr = lib->StartAddress;
	ADDRINT end_addr = lib->EndAddress;
	UINT32 size_write_set = end_addr - start_addr;
	MYINFO("detected inside library execution %08x name %s start %08x end %08x size %08x",curEip,name.c_str(),start_addr,end_addr,size_write_set);
	
	string outputFile = config->getWorkingDumpPath();
		//prepare the buffer to copy inside the stuff into the heap section to dump 		  
	unsigned char *Buffer = (unsigned char *)malloc( size_write_set );
		// copy the heap zone into the buffer 
	PIN_SafeCopy(Buffer , (void const *)start_addr , size_write_set);	
	bool res = Helper::writeBufferToFile(Buffer,size_write_set,tmpDump);
	free(Buffer);
	return res;

}