#pragma once
#include "pin.H"
#include "ProcInfo.h"
#include "Config.h"
#include "ScyllaWrapperInterface.h"

#define SCYLLA_ERROR_FILE_FROM_PID -4
#define SCYLLA_ERROR_DUMP -3

class DumpingModule
{
public:
	DumpingModule(void);
	~DumpingModule(void);
	UINT32 DumpLibrary(ADDRINT curEip, string tmpDump);
	UINT32 DumpMainModule(W::DWORD pid,ADDRINT curEip,char *tmpDumpFile);

private:
	W::DWORD_PTR GetExeModuleBase(W::DWORD dwProcessId);
	BOOL GetFilePathFromPID(W::DWORD dwProcessId, char *filename);


	ProcInfo *pinfo;
	Config *config;
};

