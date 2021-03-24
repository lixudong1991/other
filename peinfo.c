#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <time.h>
COORD loc;
static int startlocy;
#define SETLOC(x,y) {loc.X = (x);loc.Y = ((y)+startlocy);SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),loc);}	

DWORD getRawDataAddr(DWORD rvaaddr, DWORD size, IMAGE_NT_HEADERS *nthead, IMAGE_SECTION_HEADER *sechead)
{

	for (int i=0;i< nthead->FileHeader.NumberOfSections;i++)
	{
		if (rvaaddr >= sechead[i].VirtualAddress &&
			(rvaaddr + size) <= (sechead[i].VirtualAddress + sechead[i].SizeOfRawData))
			return sechead[i].PointerToRawData + (rvaaddr - sechead[i].VirtualAddress);
	}
	return 0;
}
void showtabletitle()
{
	SETLOC(0, 0)
		printf("-----------");
	SETLOC(0, 0)
	printf("+");
	SETLOC(0, 1)
	printf("| %s", "Name");

	SETLOC(11, 0)
		printf("-----------");
	SETLOC(11, 0)
	printf("+");
	SETLOC(11,  1);
	printf("| %s", "PhysAddr");

	SETLOC(22, 0)
		printf("-----------");
	SETLOC(22, 0)
	printf("+");
	SETLOC(22, 1);
	printf("| %s", "VirSize");

	SETLOC(33, 0)
		printf("-----------");
	SETLOC(33, 0);
	printf("+");
	SETLOC(33, 1);
	printf("| %s", "VirAddr");

	SETLOC(44, 0)
		printf("-----------");
	SETLOC(44, 0)
	printf("+");
	SETLOC(44,  1)
	printf("| %s", "RawSize");

	SETLOC(55, 0)
		printf("-----------");
	SETLOC(55, 0)
	printf("+");
	SETLOC(55, 1)
	printf("| %s","RawPoint");

	SETLOC(66, 0)
		printf("-----------");
	SETLOC(66, 0)
	printf("+");
	SETLOC(66, 1)
	printf("| %s", "RelPoint");

	SETLOC(77, 0)
		printf("-----------");
	SETLOC(77, 0)
	printf("+");
	SETLOC(77, 1)
	printf("| %s", "LnumPoint");

	SETLOC(88, 0)
		printf("-----------");
	SETLOC(88, 0)
	printf("+");
	SETLOC(88, 1)
	printf("| %s", "RelNum");

	SETLOC(99, 0)
		printf("-----------");
	SETLOC(99, 0)
	printf("+");
	SETLOC(99, 1)
	printf("| %s", "LnumNum");

	SETLOC(110, 0)
		printf("-----------");
	SETLOC(110, 0)
	printf("+");
	SETLOC(110, 1)
	printf("| %s", "Chs");

	SETLOC(121, 0)
		printf("-");
	SETLOC(121, 0)
	printf("+");
	SETLOC(121, 1)
	printf("|");
}
int main(int argc ,char **argv)
{
	IMAGE_DOS_HEADER *doshead;
	IMAGE_NT_HEADERS *nthead;
	IMAGE_SECTION_HEADER *sechead,*sehead;
	IMAGE_IMPORT_DESCRIPTOR *importtabel, temp;
	IMAGE_THUNK_DATA *thunkdata,*firsthunck;
	IMAGE_IMPORT_BY_NAME *funname;
	char *filebuff = NULL;

	FILE *file;
	size_t desaddr,filesize,index,indexthunk;
	DWORD thunkval;
	time_t time;
	struct tm *tmp;
	char buf[64], namebuf[9] = { 0 };
	CONSOLE_SCREEN_BUFFER_INFO cinf;

	if (argc < 2)
	{
		printf("输入文件\n");
		return 0;
	}
	if ((file = fopen(argv[1], "rb")) == NULL)
		return -1;
	fseek(file, 0, SEEK_END);
	filesize=ftell(file);
	fseek(file, 0, SEEK_SET);

	if (filesize <= (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)))
	{
		fclose(file);
		goto retlabel;
	}
		

	if ((filebuff=malloc(filesize))==NULL||
		(fread(filebuff, 1, filesize, file) != filesize))
	{
		printf("打开或读取文件失败\n");
		goto retlabel;
	}
	fclose(file);
	doshead =(IMAGE_DOS_HEADER*)filebuff;
	if (doshead->e_lfanew <= sizeof(IMAGE_DOS_HEADER)
		||(doshead->e_lfanew+ sizeof(IMAGE_NT_HEADERS)>= filesize))
		goto retlabel;
	nthead = filebuff + doshead->e_lfanew;
	if ((doshead->e_lfanew+ sizeof(IMAGE_NT_HEADERS)+ nthead->FileHeader.NumberOfSections* sizeof(IMAGE_SECTION_HEADER))>= filesize)
		goto retlabel;
	sechead = filebuff + doshead->e_lfanew + sizeof(IMAGE_NT_HEADERS);

	desaddr = (size_t)getRawDataAddr(nthead->OptionalHeader.DataDirectory[1].VirtualAddress,
		nthead->OptionalHeader.DataDirectory[1].Size,
		nthead, sechead);

	time = nthead->FileHeader.TimeDateStamp;
	tmp = localtime(&time);
	strftime(buf, 64, "%F %X", tmp);
	printf("================IMAGE_NT_HEADERS.Signature===================\n");
	printf("Signature: 0x%x\n", nthead->Signature);
	printf("==================IMAGE_NT_HEADERS.FileHeader=================\n");
	printf("Machine:0x%x\n", nthead->FileHeader.Machine);
	printf("NumberOfSections:0x%x\n", nthead->FileHeader.NumberOfSections);
	printf("TimeDateStamp:%s\n", buf);
	printf("PointerToSymbolTable:0x%x\n", nthead->FileHeader.PointerToSymbolTable);
	printf("NumberOfSymbols:0x%x\n", nthead->FileHeader.NumberOfSymbols);
	printf("SizeOfOptionalHeader:0x%x\n", nthead->FileHeader.SizeOfOptionalHeader);
	printf("Characteristics:0x%x\n", nthead->FileHeader.Characteristics);
	printf("=================IMAGE_NT_HEADERS.OptionalHeader==================\n");
	printf("Magic:0x%x\n", nthead->OptionalHeader.Magic);
	printf("MajorLinkerVersion:0x%x\n", nthead->OptionalHeader.MajorLinkerVersion);
	printf("MinorLinkerVersion:0x%x\n", nthead->OptionalHeader.MinorLinkerVersion);
	printf("SizeOfCode:0x%x\n", nthead->OptionalHeader.SizeOfCode);
	printf("SizeOfInitializedData:0x%x\n", nthead->OptionalHeader.SizeOfInitializedData);
	printf("SizeOfUninitializedData:0x%x\n", nthead->OptionalHeader.SizeOfUninitializedData);
	printf("AddressOfEntryPoint:0x%x\n", nthead->OptionalHeader.AddressOfEntryPoint);
	printf("BaseOfCode:0x%x\n", nthead->OptionalHeader.BaseOfCode);
	printf("BaseOfData:0x%x\n", nthead->OptionalHeader.BaseOfData);

	printf("ImageBase:0x%x\n", nthead->OptionalHeader.ImageBase);
	printf("SectionAlignment:0x%x\n", nthead->OptionalHeader.SectionAlignment);
	printf("FileAlignment:0x%x\n", nthead->OptionalHeader.FileAlignment);
	printf("MajorOperatingSystemVersion:0x%x\n", nthead->OptionalHeader.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion:0x%x\n", nthead->OptionalHeader.MinorOperatingSystemVersion);
	printf("MajorImageVersion:0x%x\n", nthead->OptionalHeader.MajorImageVersion);
	printf("MinorImageVersion:0x%x\n", nthead->OptionalHeader.MinorImageVersion);
	printf("MajorSubsystemVersion:0x%x\n", nthead->OptionalHeader.MajorSubsystemVersion);
	printf("MinorSubsystemVersion:0x%x\n", nthead->OptionalHeader.MinorSubsystemVersion);
	printf("Win32VersionValue:0x%x\n", nthead->OptionalHeader.Win32VersionValue);
	printf("SizeOfImage:0x%x\n", nthead->OptionalHeader.SizeOfImage);
	printf("SizeOfHeaders:0x%x\n", nthead->OptionalHeader.SizeOfHeaders);
	printf("CheckSum:0x%x\n", nthead->OptionalHeader.CheckSum);
	printf("Subsystem:0x%x\n", nthead->OptionalHeader.Subsystem);
	printf("DllCharacteristics:0x%x\n", nthead->OptionalHeader.DllCharacteristics);
	printf("SizeOfStackReserve:0x%x\n", nthead->OptionalHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit:0x%x\n", nthead->OptionalHeader.SizeOfStackCommit);
	printf("SizeOfHeapReserve:0x%x\n", nthead->OptionalHeader.SizeOfHeapReserve);
	printf("SizeOfHeapCommit:0x%x\n", nthead->OptionalHeader.SizeOfHeapCommit);
	printf("LoaderFlags:0x%x\n", nthead->OptionalHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes:0x%x\n", nthead->OptionalHeader.NumberOfRvaAndSizes);
	for (int i=0;i< IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++)
	{
		printf("DataDirectory[%d]: VirtualAddress=0x%x,Size=0x%x\n",i, nthead->OptionalHeader.DataDirectory[i].VirtualAddress, nthead->OptionalHeader.DataDirectory[i].Size);
	}
	printf("=================IMAGE_SECTION_HEADER==================\n");
	
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cinf);
	startlocy = cinf.dwCursorPosition.Y;
	showtabletitle();
	
	for (int i=1;i< nthead->FileHeader.NumberOfSections+1;i++)
	{
		sehead = &(sechead[i-1]);
		SETLOC( 0, i * 2)
		printf("-----------");
		SETLOC(0,i * 2);
		printf("+");
		SETLOC(0,i * 2+1);
		memcpy(namebuf,sehead->Name,8);
		printf("| %s", namebuf);

		SETLOC(11, i * 2)
			printf("-----------");
		SETLOC(11, i * 2);
		printf("+");
		SETLOC(11, i * 2 + 1);
		printf("| %x", sehead->Misc.PhysicalAddress);

		SETLOC(22, i * 2)
			printf("-----------");
		SETLOC(22, i * 2);
		printf("+");
		SETLOC(22, i * 2 + 1);
		printf("| %x", sehead->Misc.VirtualSize);

		SETLOC(33, i * 2)
			printf("-----------");
		SETLOC(33, i * 2);
		printf("+");
		SETLOC(33, i * 2 + 1);
		printf("| %x", sehead->VirtualAddress);

		SETLOC(44, i * 2)
			printf("-----------");
		SETLOC(44, i * 2);
		printf("+");
		SETLOC(44, i * 2 + 1);
		printf("| %x", sehead->SizeOfRawData);

		SETLOC(55, i * 2)
			printf("-----------");
		SETLOC(55, i * 2);
		printf("+");
		SETLOC(55, i * 2 + 1);
		printf("| %x", sehead->PointerToRawData);

		SETLOC(66, i * 2)
			printf("-----------");
		SETLOC(66, i * 2);
		printf("+");
		SETLOC(66, i * 2 + 1);
		printf("| %x", sehead->PointerToRelocations);

		SETLOC(77, i * 2)
			printf("-----------");
		SETLOC(77, i * 2);
		printf("+");
		SETLOC(77, i * 2 + 1);
		printf("| %x", sehead->PointerToLinenumbers);

		SETLOC(88, i * 2)
			printf("-----------");
		SETLOC(88, i * 2);
		printf("+");
		SETLOC(88, i * 2 + 1);
		printf("| %x", sehead->NumberOfRelocations);

		SETLOC(99, i * 2)
			printf("-----------");
		SETLOC(99, i * 2);
		printf("+");
		SETLOC(99, i * 2 + 1);
		printf("| %x", sehead->NumberOfLinenumbers);

		SETLOC(110, i * 2)
			printf("-----------");
		SETLOC(110, i * 2);
		printf("+");
		SETLOC(110, i * 2 + 1);
		printf("| %x", sehead->Characteristics);

		SETLOC(121, i * 2)
			printf("-");
		SETLOC(121, i * 2)
		printf("+");
		SETLOC(121, i * 2 + 1)
		printf("|");
	}
	for (int i=0;i<11;i++)
	{
		SETLOC(i*11,(nthead->FileHeader.NumberOfSections+1) * 2 )
			printf("-----------");
		SETLOC(i * 11, (nthead->FileHeader.NumberOfSections + 1) * 2)
		printf("+");
	}
	SETLOC(11*11, (nthead->FileHeader.NumberOfSections + 1) * 2)
		printf("-");
	SETLOC(11 * 11, (nthead->FileHeader.NumberOfSections + 1) * 2)
	printf("+\n\n");
	fflush(stdout);
	printf("==============================IMAGE_IMPORT_DESCRIPTOR================================\n");
	memset(&temp,0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	importtabel = filebuff + desaddr;
	index = 0;
	while (1)
	{
		if (memcmp(&(importtabel[index]), &temp, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
			break;
		printf("--------------------------------------------------------------\n");
		printf("Characteristics: 0x%x\n", importtabel[index].Characteristics);
		printf("OriginalFirstThunk: 0x%x\n", importtabel[index].OriginalFirstThunk);
		time = importtabel[index].TimeDateStamp;
		tmp = localtime(&time);
		strftime(buf, 64, "%F %X", tmp);
		printf("TimeDateStamp: %s\n", buf);
		printf("ForwarderChain: 0x%x\n", importtabel[index].ForwarderChain);
		printf("Name: %s(rva:0x%x)\n",filebuff+getRawDataAddr(importtabel[index].Name,0,nthead,sechead),importtabel[index].Name);
		printf("FirstThunk: 0x%x\n", importtabel[index].FirstThunk);
		thunkdata = filebuff+ getRawDataAddr(importtabel[index].OriginalFirstThunk, 0, nthead, sechead);
		firsthunck = importtabel[index].FirstThunk;
		indexthunk = 0;
		while (*(DWORD*)(thunkdata+indexthunk)!=0)
		{
			thunkval = *(DWORD*)(thunkdata + indexthunk);
			if (thunkval&IMAGE_ORDINAL_FLAG32)
			{
				printf("function: rva=0x%x,no=0x%x\n", firsthunck,thunkval&0x7FFFFFFF);
			}
			else {
				funname = filebuff + getRawDataAddr(thunkval, 0, nthead, sechead);
				printf("function: rva=0x%x,no=0x%x,name=%s\n", firsthunck,funname->Hint,funname->Name);
			}
			firsthunck++;
			indexthunk++;
		}
		index++;
	}
retlabel:
	if (filebuff)
		free(filebuff);
	return 0;
}
