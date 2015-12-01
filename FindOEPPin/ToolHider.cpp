#include "ToolHider.h"


ToolHider::ToolHider(void)
{
}


ToolHider::~ToolHider(void)
{
}

void ToolHider::avoidEvasion(INS ins){

	if(INS_IsMemoryRead(ins)){
		//analyze if this instruction reads a memory region that belong to pinvm.dll / pintool / 
	}

	//pattern match

	//timing countermeasures

	//JIT detection
}




// This code belongs to the TitanEngine framework http://www.reversinglabs.com/products/TitanEngine.php
long long FindEx(W::HANDLE hProcess, W::LPVOID MemoryStart, W::DWORD MemorySize, W::LPVOID SearchPattern, W::DWORD PatternSize, W::LPBYTE WildCard){

	int i = NULL;
	int j = NULL;
	W::ULONG_PTR Return = NULL;
	W::LPVOID ueReadBuffer = NULL;
	W::PUCHAR SearchBuffer = NULL;
	W::PUCHAR CompareBuffer = NULL;
	W::ULONG_PTR ueNumberOfBytesRead = NULL;
	W::LPVOID currentSearchPosition = NULL;
	W::DWORD currentSizeOfSearch = NULL;
	W::BYTE nWildCard = NULL;

	if(WildCard == NULL){WildCard = &nWildCard;}
	if(hProcess != NULL && MemoryStart != NULL && MemorySize != NULL){
		if(hProcess != W::GetCurrentProcess()){
			ueReadBuffer = W::VirtualAlloc(NULL, MemorySize, MEM_COMMIT, PAGE_READWRITE);
			if(!W::ReadProcessMemory(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead)){
				W::VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
				return(NULL);
			}else{
				SearchBuffer = (W::PUCHAR)ueReadBuffer;
			}
		}else{
			SearchBuffer = (W::PUCHAR)MemoryStart;
		}
		__try{
			CompareBuffer = (W::PUCHAR)SearchPattern;
			for(i = 0; i < (int)MemorySize && Return == NULL; i++){
				for(j = 0; j < (int)PatternSize; j++){
					if(CompareBuffer[j] != *(W::PUCHAR)WildCard && SearchBuffer[i + j] != CompareBuffer[j]){
						break;
					}
				}
				if(j == (int)PatternSize){
					Return = (W::ULONG_PTR)MemoryStart + i;
				}
			}
			W::VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(Return);
		}__except(EXCEPTION_EXECUTE_HANDLER){
			W::VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(NULL);
		}
	}else{
		return(NULL);
	}
}

W::DWORD SearchPinVM()
{
	W::MEMORY_BASIC_INFORMATION mbi;
	W::SIZE_T numBytes;
	W::DWORD MyAddress = 0;
	int find =0;

	do
	{
		numBytes = W::VirtualQuery((W::LPCVOID)MyAddress, &mbi, sizeof(mbi));
		
		if((mbi.State == MEM_COMMIT) && (mbi.Protect == PAGE_EXECUTE_READWRITE))
		{
			printf("\n\n---------\n");
			printf("BaseAddress: %x\n", mbi.BaseAddress);
			printf("Size: %x\n", mbi.RegionSize);

			find = FindEx(W::GetCurrentProcess(),mbi.BaseAddress,mbi.RegionSize, "@CHARM", strlen("@CHARM"), NULL);
			
			if(find) printf("FOUND PINVMDLL in %x",mbi.BaseAddress);
		}

		MyAddress += mbi.RegionSize;

	}
	while(numBytes);

	return 0;
}