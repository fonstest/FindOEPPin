#include "HookSyscalls.h"

//----------------------------- SYSCALL HOOKS -----------------------------//
static int testing = 0;
void HookSyscalls::syscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){

	//get the syscall number
	unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);

	// int 0x2e probably leaves ctx in a corrupted state and we have an undefined behavior here, 
	// the syscall_number will result in a 0 and this isn't correct, the crash is inside the function PIN_GetSyscallArguments.
	// According to PIN documentation: Applying PIN_GetSyscallArguments() to an inappropriate context results in undefined behavior and even may cause 
	// crash on systems in which system call arguments are located in memory.
	// The incriminated syscall is executed after the int 0x2e, before the next instruction, just for now filter out the 0 syscall since we don't use it at all...
	if(syscall_number == 0){
		MYINFO("Number of syscall is %d\n", syscall_number);
		return;
	}


	if(syscall_number == 0x12b){
		MYINFO("Invoked WaitReply of syscall is %08x %d\n",PIN_GetContextReg(ctx,REG_EIP), syscall_number);
		
	}


	//fill the structure with the provided info
	syscall_t *sc = &((syscall_t *) v)[thread_id];	
	sc->syscall_number = syscall_number;

	//get the arguments pointer
	// 8 = number of the argument to be passed
	// 0 .. 7 -> &sc->arg0 .. &sc->arg7 = correspondence between the index of the argument and the struct field to be loaded
	HookSyscalls::syscallGetArguments(ctx, std, 8, 0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3, 4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7);

	//HookSyscalls::printArgs(sc);
	std::map<unsigned long, string>::iterator syscallMapItem = syscallsMap.find(sc->syscall_number);
	//search for an hook on entry
	if(syscallMapItem !=  syscallsMap.end()){
		//search if we have an hook for the syscall
		std::map<string, syscall_hook>::iterator syscallHookItem = syscallsHooks.find(syscallMapItem->second + "_entry");
		if(syscallHookItem != syscallsHooks.end()){
			//if so call the hook
			syscallHookItem->second(sc, ctx, std);
		}
	}

}

void HookSyscalls::syscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	
	

	//get the structure with the informations on the systemcall
	syscall_t *sc = &((syscall_t *) v)[thread_id];
	//search forn an hook on exit
	std::map<unsigned long, string>::iterator syscallMapItem = syscallsMap.find(sc->syscall_number);

	if(syscallMapItem !=  syscallsMap.end()){
		//serch if we have an hook for the syscall
		std::map<string, syscall_hook>::iterator syscallHookItem = syscallsHooks.find(syscallMapItem->second + "_exit");
		if(syscallHookItem != syscallsHooks.end()){
			//if so call the hook
			syscallHookItem->second(sc, ctx, std);
		}
	}
	
}




void HookSyscalls::NtAllocateVirtualMemoryHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){

	W::PVOID base_address_pointer = (W::PVOID) sc->arg1;
	W::PSIZE_T region_size_address = (W::PSIZE_T) sc->arg3;

	ADDRINT heap_address = *(ADDRINT *)base_address_pointer;
	W::SIZE_T region_size = *(W::SIZE_T *)region_size_address;

    ProcInfo *proc_info = ProcInfo::getInstance();

	HeapZone hz;
	hz.begin = heap_address;
	hz.size = region_size;
    hz.end = region_size+heap_address;
  
	MYINFO("NtAllocateVirtualMemoryHook insert in Heap Zone %08x -> %08x",hz.begin,hz.end);

	//saving this heap zone in the map inside ProcInfo
	proc_info->insertHeapZone(hz); 

}


//----------------------------- END HOOKS -----------------------------//


//----------------------------- HELPER METHODS -----------------------------//

// stole this lovely source code from godware from the rreat library.
void HookSyscalls::enumSyscalls()
{
    // no boundary checking at all, I assume ntdll is not malicious..
    // besides that, we are in our own process, _should_ be fine..
    unsigned char *image = (unsigned char *) W::GetModuleHandle("ntdll");

    W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;

    W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image +
        dos_header->e_lfanew);

    W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    W::IMAGE_EXPORT_DIRECTORY *export_directory =(W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);

    unsigned long *address_of_names = (unsigned long *)(image + export_directory->AddressOfNames);

    unsigned long *address_of_functions = (unsigned long *)(image + export_directory->AddressOfFunctions);

    unsigned short *address_of_name_ordinals = (unsigned short *)(image + export_directory->AddressOfNameOrdinals);

    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);

    for (unsigned long i = 0; i < number_of_names; i++) {

        const char *name = (const char *)(image + address_of_names[i]);

        unsigned char *addr = image + address_of_functions[address_of_name_ordinals[i]];

        if(!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
            // does the signature match?
            // either:   mov eax, syscall_number ; mov ecx, some_value
            // or:       mov eax, syscall_number ; xor ecx, ecx
            // or:       mov eax, syscall_number ; mov edx, 0x7ffe0300
            if(*addr == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
                unsigned long syscall_number = *(unsigned long *)(addr + 1);
				string syscall_name = string(name);
				//MYINFO("Number %d Syscall %s\n", syscall_number, syscall_name.c_str());
				syscallsMap.insert(std::pair<unsigned long,string>(syscall_number,syscall_name));
				
            }
        }
    }
}

void HookSyscalls::initHooks(){



	syscallsHooks.insert(std::pair<string,syscall_hook>("NtAllocateVirtualMemory_exit",&HookSyscalls::NtAllocateVirtualMemoryHook));


	static syscall_t sc[256] = {0};
	PIN_AddSyscallEntryFunction(&HookSyscalls::syscallEntry,&sc);
    PIN_AddSyscallExitFunction(&HookSyscalls::syscallExit,&sc);

}

//get the pointer to the syscall arguments
//stole this lovely source code from godware
void HookSyscalls::syscallGetArguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...)
{
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        int index = va_arg(args, int);
        ADDRINT *ptr = va_arg(args, ADDRINT *);
        *ptr = PIN_GetSyscallArgument(ctx, std, index);
    }
    va_end(args);
}

void HookSyscalls::printArgs(syscall_t * sc){
	printf("arg0 : %08x\n", sc->arg0);
	printf("arg1 : %08x\n", sc->arg1);
	printf("arg2 : %08x\n", sc->arg2);
	printf("arg3 : %08x\n", sc->arg3);
	printf("arg4 : %08x\n", sc->arg4);
	printf("arg5 : %08x\n", sc->arg5);
	printf("arg6 : %08x\n", sc->arg6);
	printf("arg7 : %08x\n", sc->arg7);
}

void HookSyscalls::printRegs(CONTEXT *ctx){
	printf("EAX : %08x\n", PIN_GetContextReg(ctx, REG_EAX));
	printf("EBX : %08x\n", PIN_GetContextReg(ctx, REG_EBX));
	printf("ECX : %08x\n", PIN_GetContextReg(ctx, REG_ECX));
	printf("EDX : %08x\n", PIN_GetContextReg(ctx, REG_EDX));
}

