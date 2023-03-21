#define _CRT_SECURE_NO_WARNINGS
#include <ctime>
#include <stdio.h>
#include <stdlib.h>

#include "emu.h"



SEG_MAP segs[] = {
	//base			size			file name
	//{0x0019C000,	0x00004000,	"0019C000",	NULL},	//stack
	//{0x004C9000,	0x0074B000,	"004C9000",	NULL},	//svmp1
	//{0x03250000,	0x0000A000,	"03250000",	NULL},	//mem

};



#define INIT_EAX			0xFFFFFFFF
#define INIT_EBX			0x00000001
#define INIT_ECX			0x033B0C80
#define INIT_EDX			0x0019F564
#define INIT_EBP			0x0019F4C8
#define INIT_ESP			0x0019F494
#define INIT_ESI			0x004B1840
#define INIT_EDI			0x000007D8
#define INIT_EIP			0x00B2983E
#define INIT_EFL			0x00000202
//!注意EFL的TF如果置位会引发异常


uc_engine *uc;

REGS regs;


void print_stack(DWORD esp)
{
	DWORD val;
	uc_mem_read(uc, esp, &val, 4);
	printf("ESP  -> |%p|\n", val);
	esp+=4;
	for(int i = 1; i<10; i++)
	{
		uc_mem_read(uc, esp, &val, 4);
		printf("\t|%p|\n", val);
		esp+=4;
	}
}



void read_regs()
{
	uc_reg_read(uc, UC_X86_REG_EAX,    &regs.regs.r_eax);
	uc_reg_read(uc, UC_X86_REG_ECX,    &regs.regs.r_ecx);
	uc_reg_read(uc, UC_X86_REG_EDX,    &regs.regs.r_edx);
	uc_reg_read(uc, UC_X86_REG_EBX,    &regs.regs.r_ebx);
	uc_reg_read(uc, UC_X86_REG_ESP,    &regs.regs.r_esp);
	uc_reg_read(uc, UC_X86_REG_EBP,    &regs.regs.r_ebp);
	uc_reg_read(uc, UC_X86_REG_ESI,    &regs.regs.r_esi);
	uc_reg_read(uc, UC_X86_REG_EDI,    &regs.regs.r_edi);
	uc_reg_read(uc, UC_X86_REG_EIP,    &regs.regs.r_eip);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &regs.regs.r_efl);
}
void write_regs(){
	uc_reg_write(uc, UC_X86_REG_EAX,    &regs.regs.r_eax);
	uc_reg_write(uc, UC_X86_REG_ECX,    &regs.regs.r_ecx);
	uc_reg_write(uc, UC_X86_REG_EDX,    &regs.regs.r_edx);
	uc_reg_write(uc, UC_X86_REG_EBX,    &regs.regs.r_ebx);
	uc_reg_write(uc, UC_X86_REG_ESP,    &regs.regs.r_esp);
	uc_reg_write(uc, UC_X86_REG_EBP,    &regs.regs.r_ebp);
	uc_reg_write(uc, UC_X86_REG_ESI,    &regs.regs.r_esi);
	uc_reg_write(uc, UC_X86_REG_EDI,    &regs.regs.r_edi);
	uc_reg_write(uc, UC_X86_REG_EIP,    &regs.regs.r_eip);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &regs.regs.r_efl);
}
void print_regs(){
	printf("eax = %p\n", regs.regs.r_eax);
	printf("ebx = %p\n", regs.regs.r_ebx);
	printf("ecx = %p\n", regs.regs.r_ecx);
	printf("edx = %p\n", regs.regs.r_edx);
	printf("ebp = %p\n", regs.regs.r_ebp);
	printf("esp = %p\n", regs.regs.r_esp);
	printf("esi = %p\n", regs.regs.r_esi);
	printf("edi = %p\n", regs.regs.r_edi);
	printf("eip = %p\n", regs.regs.r_eip);
	printf("efl = %p\n", regs.regs.r_efl);
}

DWORD reg_value(const char* reg_name)
{
	if(strcmp(reg_name, "eax") == 0)
		return regs.regs.r_eax;
	else if(strcmp(reg_name, "ebx") == 0)
		return regs.regs.r_ebx;
	else if(strcmp(reg_name, "ecx") == 0)
		return regs.regs.r_ecx;
	else if(strcmp(reg_name, "edx") == 0)
		return regs.regs.r_edx;
	else if(strcmp(reg_name, "ebp") == 0)
		return regs.regs.r_ebp;
	else if(strcmp(reg_name, "esp") == 0)
		return regs.regs.r_esp;
	else if(strcmp(reg_name, "esi") == 0)
		return regs.regs.r_esi;
	else if(strcmp(reg_name, "edi") == 0)
		return regs.regs.r_edi;
	else if(strcmp(reg_name, "eip") == 0)
		return regs.regs.r_eip;
	else if(strcmp(reg_name, "efl") == 0)
		return regs.regs.r_efl;
	else
		return 0;
}


int main(int argc, char **argv, char **envp)
{
	time_t t_begin=clock();
	time_t t_end=0;
	regs.regs.r_eax = INIT_EAX;
	regs.regs.r_ecx = INIT_ECX;			 
	regs.regs.r_edx = INIT_EDX;     
	regs.regs.r_ebx = INIT_EBX;
	regs.regs.r_esp = INIT_ESP;
	regs.regs.r_ebp = INIT_EBP;
	regs.regs.r_esi = INIT_ESI;
	regs.regs.r_edi = INIT_EDI;
	regs.regs.r_eip = INIT_EIP;
	regs.regs.r_efl = INIT_EFL;
	
	uc_err err;
	csh handle;
	cs_insn* insn;

	printf("Emulate i386 code\n");
	
	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}
	err = uc_mem_map(uc, 0x0010C000, 0x00090000, UC_PROT_ALL);
	for(int i = 0; i < sizeof(segs)/sizeof(SEG_MAP); i++) {
		segs[i].buf = (unsigned char *)malloc(segs[i].size);
		FILE *fp = fopen(segs[i].file_name, "rb");
		fread(segs[i].buf, segs[i].size, 1, fp);
		fclose(fp);
		// map memory for this emulation
		err = uc_mem_map(uc, segs[i].base, segs[i].size, UC_PROT_ALL);
		// write machine code to be emulated to memory
		err = uc_mem_write(uc, segs[i].base, segs[i].buf, segs[i].size);
		free(segs[i].buf);
	} 
	

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	write_regs();
	init_gdt(uc);

	BYTE code[32];
	int count = 0;
	// emulate code in infinite time & unlimited instructions
	while (1){
		count++;
		uc_mem_read(uc, regs.regs.r_eip, code, 32);
		cs_disasm(handle, code, 32, regs.regs.r_eip, 1, &insn);

		switch (regs.regs.r_eip)
		{
		default:
			{
				if (
					regs.regs.r_eip==0x42510c
					)
				{
					//printf("eax = %d\n",regs.regs.r_eax);
					DWORD handler_addr;
					BYTE handler[256];
					cs_insn* handler_insn;

					uc_mem_read(uc, insn->detail->x86.disp+4*regs.regs.r_eax, &handler_addr, 4);
					uc_mem_read(uc, handler_addr, handler, 256);
					cs_disasm(handle, handler, 256, handler_addr, 8, &handler_insn);

					if(strcmp(handler_insn[0].mnemonic,"and")==0&&
						handler_insn[0].detail->x86.operands[0].reg==X86_REG_AL&&
						strcmp(handler_insn[2].mnemonic,"add")==0&&
						handler_insn[2].detail->x86.operands[1].imm==4
						
						)
					{
						DWORD target;
						DWORD dst;
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[1].detail->x86.operands[1].mem.base)), &target, 4);
						dst=reg_value(cs_reg_name(handle,handler_insn[3].detail->x86.operands[0].mem.base))
							+reg_value(cs_reg_name(handle,handler_insn[3].detail->x86.operands[0].mem.index))&(0xFFFFFF00|handler_insn[0].detail->x86.operands[1].imm);
						printf("GetStack32 [%0#10x] = %0#10x\n",dst,target);
					}
					else if(strcmp(handler_insn[0].mnemonic,"and")==0&&
						handler_insn[0].detail->x86.operands[0].reg==X86_REG_AL&&
						strcmp(handler_insn[2].mnemonic,"sub")==0&&
						handler_insn[2].detail->x86.operands[1].imm==4
						)
					{
						DWORD target;
						DWORD dst;
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[1].detail->x86.operands[1].mem.base))
							+reg_value(cs_reg_name(handle,handler_insn[1].detail->x86.operands[1].mem.index))&(0xFFFFFF00|handler_insn[0].detail->x86.operands[1].imm)
							, &target, 4);
						dst=reg_value(cs_reg_name(handle,handler_insn[3].detail->x86.operands[0].mem.base))-4;
						printf("SetStack32_from_VMstack [%0#10x] = %0#10x\n",dst,target);

					}
					else if(strcmp(handler_insn[0].mnemonic,"mov")==0&&
						handler_insn[0].detail->x86.operands[0].reg==X86_REG_AX&&
						strcmp(handler_insn[1].mnemonic,"cwde")==0
						)
					{
						short target;
						DWORD dst;
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[0].detail->x86.operands[1].mem.base)), &target, 2);
						dst = reg_value(cs_reg_name(handle,handler_insn[2].detail->x86.operands[0].reg))-4;
						printf("SetStack16 [%0#10x] = %0#10x\n",dst,target);

					}
					else if(strcmp(handler_insn[0].mnemonic,"mov")==0&&
						strcmp(handler_insn[1].mnemonic,"sub")==0&&
						strcmp(handler_insn[2].mnemonic,"mov")==0
						)
					{
						DWORD target;
						DWORD dst;
						target = reg_value(cs_reg_name(handle,handler_insn[1].detail->x86.operands[0].reg));
						dst = reg_value(cs_reg_name(handle,handler_insn[1].detail->x86.operands[0].reg))-4;
						printf("SetStack32_StackBase [%0#10x] = %0#10x\n",dst,target);
					}
					else if(strcmp(handler_insn[0].mnemonic,"movzx")==0&&
						strcmp(handler_insn[1].mnemonic,"cbw")==0&&
						strcmp(handler_insn[2].mnemonic,"cwde")==0
						)
					{
						unsigned char target;
						DWORD dst;
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[0].detail->x86.operands[1].mem.base)), &target, 1);
						dst = regs.regs.r_ebp-4;
						printf("SetStack32_imm [%0#10x] = %0#10x\n",dst,target);
					}
					else if(strcmp(handler_insn[0].mnemonic,"mov")==0&&
						strcmp(handler_insn[1].mnemonic,"add")==0&&
						strcmp(handler_insn[2].mnemonic,"pushfd")==0&&
						strcmp(handler_insn[3].mnemonic,"pop")==0
						)
					{
						printf("Add\n");
					}
					else if(strcmp(handler_insn[2].mnemonic,"not")==0&&
						strcmp(handler_insn[3].mnemonic,"not")==0&&
						strcmp(handler_insn[4].mnemonic,"and")==0
						)
					{
						printf("Nand\n");
					}
					else if(strcmp(handler_insn[0].mnemonic,"mov")==0&&
						strcmp(handler_insn[1].mnemonic,"mov")==0&&
						strcmp(handler_insn[2].mnemonic,"mov")==0&&
						strcmp(handler_insn[3].mnemonic,"jmp")==0
						)
					{
						DWORD dst;
						DWORD tmp;
						dst= reg_value(cs_reg_name(handle,handler_insn[0].detail->x86.operands[1].mem.base));
						uc_mem_read(uc, dst, &tmp, 4);
						uc_mem_read(uc, tmp, &tmp, 4);
						printf("GetMem [%0#10x] = %0#10x\n",dst,tmp);
					}
					else if(strcmp(handler_insn[0].mnemonic,"mov")==0&&
						strcmp(handler_insn[1].mnemonic,"jmp")==0
						)
					{
						DWORD tmp;
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[0].detail->x86.operands[1].mem.base)), &tmp, 4);
						printf("SetStackPointer = %0#10x\n",tmp);
					}
					else if(strcmp(handler_insn[2].mnemonic,"sub")==0&&
						strcmp(handler_insn[3].mnemonic,"shr")==0
						)
					{
						printf("Shr\n");
					}
					else if(strcmp(handler_insn[0].mnemonic,"mov")==0&&
						handler_insn[0].detail->x86.operands[0].reg==X86_REG_ESI&&
						strcmp(handler_insn[1].mnemonic,"add")==0
						)
					{
						DWORD new_eip;
						DWORD key;
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[0].detail->x86.operands[1].mem.base)), &new_eip, 4);
						uc_mem_read(uc, reg_value(cs_reg_name(handle,handler_insn[0].detail->x86.operands[1].mem.base))+4, &key, 4);
						printf("SetVMEip = %0#10x\n",DWORD(new_eip + key));
					}
					else if((strcmp(handler_insn[1].mnemonic,"pop")==0||strcmp(handler_insn[0].mnemonic,"popfd")==0)&&
						(strcmp(handler_insn[2].mnemonic,"pop")==0||strcmp(handler_insn[1].mnemonic,"popfd")==0)&&
						(strcmp(handler_insn[3].mnemonic,"pop")==0||strcmp(handler_insn[1].mnemonic,"popfd")==0)
						)
					{
						printf("VMExit\n");
					}
					else
					{
						printf("unknown handler eax = %d\n",regs.regs.r_eax);
					}
					cs_free(handler_insn, 8);


					// if (regs.regs.r_eip >= segs[2].base && regs.regs.r_eip < segs[2].base+segs[2].size)
					// {
					// 	if (strcmp(insn->mnemonic, "ret") == 0)
					// 	{
					// 		//print_stack(regs.regs.r_esp);
					// 		DWORD ret_address;
					// 		uc_mem_read(uc, regs.regs.r_esp, &ret_address, sizeof(ret_address));
					// 		if (regs.regs.r_esp == INIT_ESP - 4)
					// 		{
					// 			if (ret_address < segs[2].base || ret_address>= segs[2].base+segs[2].size)
					// 			{
					// 				printf("EIP = %08X VM_Exit/OEP : %08X\n", regs.regs.r_eip, ret_address);
					// 				print_stack(regs.regs.r_esp);
					// 				printf("\n");
					// 				goto emu_end;
					// 				break;
					// 			}
					// 		}
					// 		printf("EIP = %08X API Call : %08X\n", regs.regs.r_eip, ret_address);
					// 		print_stack(regs.regs.r_esp);
					// 		printf("\n");
					// 	}
					// }
					//

				}
			}
		}
		
		err=uc_emu_start(uc, regs.regs.r_eip, 0xffffffff, 0, 1);
		if (err) {
			printf("Exception with error returned %u: %s\n",
				err, uc_strerror(err));
			printf("%p %s %s\n",regs.regs.r_eip,insn->mnemonic,insn->op_str);
			print_regs();
			print_stack(regs.regs.r_esp);
			
			//__asm int 3
			break;
		}

		read_regs();

		cs_free(insn, 1);

	}

	emu_end:
	printf("count = %d\n", count);

	cs_close(&handle);
	uc_close(uc);

	t_end=clock();
	printf("elapsed time: %.2f\n",float(t_end-t_begin)/1000);
	system("pause");
	return 0;
}