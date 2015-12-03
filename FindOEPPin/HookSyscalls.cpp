#include "HookSyscalls.h"

//----------------------------- SYSCALL HOOKS -----------------------------//

void HookSyscalls::syscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	//get the syscall number
	unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);
	//fill the structure with the provided info
	syscall_t *sc = &((syscall_t *) v)[thread_id];
	sc->syscall_number = syscall_number;
	if(syscall_number == 261){
		 //get the arguments pointer
		 // 8 = number of the argument to be passed
		 // 0 .. 7 -> &sc->arg0 .. &sc->arg7 = correspondence between the index of the argument and the struct field to be loaded
		 HookSyscalls::syscallGetArguments(ctx, std, 8, 0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3, 4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7);
	}
}

void HookSyscalls::syscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	 //get the structure with the informations on the systemcall
	 syscall_t *sc = &((syscall_t *) v)[thread_id];
	 //NtSystemQueryInformation detected
	 if(sc->syscall_number == 261){
		 syscall_hook hook = syscallsHooks.at("NtQuerySystemInformation");
		 hook(sc);
	 }
}

//NtSystemQueryInformation detected
void HookSyscalls::NtQuerySystemInformationHook(syscall_t *sc){
	//cast to our structure in order to retrieve the information returned from the NtSystemQueryInformation function
	PSYSTEM_PROCESS_INFO spi;
	spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
	//iterate through all processes 
	while(spi->NextEntryOffset){
		//if the process is pin change it's name in cmd.exe in order to avoid evasion
		if(spi->ImageName.Buffer && ( (wcscmp(spi->ImageName.Buffer, L"pin.exe") == 0))){
			wcscpy(spi->ImageName.Buffer, L"cmd.exe");
		}
		spi=(PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi+spi->NextEntryOffset); // Calculate the address of the next entry.
	} 
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
				syscallsMap.insert(std::pair<unsigned long,string>(syscall_number,syscall_name));
				
            }
        }
    }
}

void HookSyscalls::initHooks(){

	syscallsHooks.insert(std::pair<string,syscall_hook>("NtQuerySystemInformation",&HookSyscalls::NtQuerySystemInformationHook));

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

