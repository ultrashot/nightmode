// JCW_+ 2008.07.18 START
//=============================================================================================================================
// Thread Structure
//=============================================================================================================================
typedef struct Thread THREAD;
typedef THREAD *PTHREAD;

typedef struct Process PROCESS;
typedef PROCESS *PPROCESS;

typedef struct PROXY *LPPROXY;
typedef struct PROXY {
    LPPROXY pQPrev;						// Previous proxy for this object queue, must be first for ReQueueByPriority	
    LPPROXY pQNext;						// Next proxy for this object queue												
    LPPROXY pQUp;
    LPPROXY pQDown;
    LPPROXY pThLinkNext;				// Next proxy for this thread													
    LPBYTE  pObject;					// Pointer to object we're blocked on											
    BYTE    bType;						// Type of object we're blocked on												
    BYTE    prio;						// Current prio we're enqueued on												
    WORD    wCount;						// Count matching thread's wCount												
    PTHREAD pTh;						// Thread "owning" this proxy													
    DWORD   dwRetVal;					// Return value if this is why we wake up										
} PROXY;

#define PRIORITY_LEVELS_HASHSIZE 32

typedef struct CRIT *LPCRIT;
typedef struct CRIT {
    LPCRITICAL_SECTION lpcs;			// Pointer to critical_section structure										
    LPPROXY pProxList;
    LPPROXY pProxHash[PRIORITY_LEVELS_HASHSIZE];
    LPCRIT  pPrev;						// previous event in list														
    BYTE bListed;						// Is this on someone's owner list												
    BYTE bListedPrio;
    BYTE iOwnerProc;					// Index of owner process														
    BYTE bPad;
    struct CRIT * pPrevOwned;			// Prev crit/mutex (for prio inversion)											
    struct CRIT * pNextOwned;			// Next crit/mutex section owned (for prio inversion)							
    struct CRIT * pUpOwned;
    struct CRIT * pDownOwned;
    LPCRIT pNext;						// Next CRIT in list															
} CRIT;

typedef struct TContext CPUCONTEXT;
struct TContext {
    ULONG   TcxGs;
    ULONG   TcxFs;
    ULONG   TcxEs;
    ULONG   TcxDs;
    ULONG   TcxEdi;
    ULONG   TcxEsi;
    ULONG   TcxEbp;
    ULONG   TcxNotEsp;
    ULONG   TcxEbx;
    ULONG   TcxEdx;
    ULONG   TcxEcx;
    ULONG   TcxEax;
    ULONG   TcxError;
    ULONG   TcxEip;
    ULONG   TcxCs;
    ULONG   TcxEFlags;
    ULONG   TcxEsp;
    ULONG   TcxSs;
};

typedef struct CLEANEVENT {
    struct CLEANEVENT *ceptr;
    LPVOID base;
    DWORD size;
    DWORD op;
} CLEANEVENT, *LPCLEANEVENT;

typedef struct {
    HANDLE hFirstThrd;					// first thread being debugged by this thread
    HANDLE hNextThrd;					// next thread being debugged
    PCONTEXT psavedctx;					// pointer to saved context, if any
    HANDLE hEvent;						// handle to wait on for debug event for this thread
    HANDLE hBlockEvent;					// handle that thread is waiting on
    DEBUG_EVENT dbginfo;				// debug info
    BOOL bDispatched;
} THRDDBG, *LPTHRDDBG;

typedef void (*RETADDR)();

typedef ulong ACCESSKEY;

/* Thread Call stack structure
 *
 *  This structure is used by the IPC mechanism to track
 * current process, access key, and return addresses for
 * IPC calls which are in progress. It is also used by
 * the exception handling code to hold critical thread
 * state while switching modes.
 */ 
typedef struct CALLSTACK {
    struct CALLSTACK *pcstkNext;
    RETADDR     retAddr;				// return address																
    PPROCESS    pprcLast;				// previous process																
    ACCESSKEY   akyLast;				// previous access key															
    uint        extra;					// extra CPU dependent data														
//#if defined(MIPS)
//    ulong       pPad;					// so that excinfo fits in a callstack											
//#endif
#if defined(x86)
    ulong       ExEsp;					// saved Esp value for exception												
    ulong       ExEbp;					// saved Ebp   "																
    ulong       ExEbx;					// saved Ebx   "																
    ulong       ExEsi;					// saved Esi   "																
    ulong       ExEdi;					// saved Edi   "																
#endif
    ulong       dwPrevSP;				// SP of caller																	
    ulong       dwPrcInfo;				// information about the caller (mode, callback?, etc)							
} CALLSTACK;							// CallStack																	
typedef CALLSTACK *PCALLSTACK;

struct Thread {
    WORD        wInfo;					// 00: various info about thread, see above										
    BYTE        bSuspendCnt;			// 02: thread suspend count														
    BYTE        bWaitState;				// 03: state of waiting loop													
    LPPROXY     pProxList;				// 04: list of proxies to threads blocked on this thread						
    PTHREAD     pNextInProc;			// 08: next thread in this process												
    PPROCESS    pProc;					// 0C: pointer to current process												
    PPROCESS    pOwnerProc;				// 10: pointer to owner process													
    ACCESSKEY   aky;					// 14: keys used by thread to access memory & handles							
    PCALLSTACK  pcstkTop;				// 18: current api call info													
    DWORD       dwOrigBase;				// 1C: Original stack base														
    DWORD       dwOrigStkSize;			// 20: Size of the original thread stack										
    LPDWORD     tlsPtr;					// 24: tls pointer																
    DWORD       dwWakeupTime;			// 28: sleep count, also pending sleepcnt on waitmult							
    LPDWORD     tlsSecure;				// 2c: TLS for secure stack														
    LPDWORD     tlsNonSecure;			// 30: TLS for non-secure stack													
    LPPROXY     lpProxy;				// 34: first proxy this thread is blocked on									
    DWORD       dwLastError;			// 38: last error																
    HANDLE      hTh;					// 3C: Handle to this thread, needed by NextThread								
    BYTE        bBPrio;					// 40: base priority															
    BYTE        bCPrio;					// 41: curr priority															
    WORD        wCount;					// 42: nonce for blocking lists													
    PTHREAD     pPrevInProc;			// 44: previous thread in this process											
    LPTHRDDBG   pThrdDbg;				// 48: pointer to thread debug structure, if any								
    LPBYTE      pSwapStack;				// 4c																			
    FILETIME    ftCreate;				// 50: time thread is created													
    CLEANEVENT *lpce;					// 58: cleanevent for unqueueing blocking lists									
    DWORD       dwStartAddr;			// 5c: thread PC at creation, used to get thread name							
    CPUCONTEXT  ctx;					// 60: thread's cpu context information											
    PTHREAD     pNextSleepRun;			// ??: next sleeping thread, if sleeping, else next on runq if runnable			
    PTHREAD     pPrevSleepRun;			// ??: back pointer if sleeping or runnable										
    PTHREAD     pUpRun;					// ??: up run pointer (circulaar)												
    PTHREAD     pDownRun;				// ??: down run pointer (circular)												
    PTHREAD     pUpSleep;				// ??: up sleep pointer (null terminated)										
    PTHREAD     pDownSleep;				// ??: down sleep pointer (null terminated)										
    LPCRIT      pOwnedList;				// ??: list of crits and mutexes for priority inversion							
    LPCRIT      pOwnedHash[PRIORITY_LEVELS_HASHSIZE];
    DWORD       dwQuantum;				// ??: thread quantum															
    DWORD       dwQuantLeft;			// ??: quantum left																
    LPPROXY     lpCritProxy;			// ??: proxy from last critical section block, in case stolen back				
    LPPROXY     lpPendProxy;			// ??: pending proxies for queueing												
    DWORD       dwPendReturn;			// ??: return value from pended wait											
    DWORD       dwPendTime;				// ??: timeout value of wait operation											
    PTHREAD     pCrabPth;
    WORD        wCrabCount;
    WORD        wCrabDir;
    DWORD       dwPendWakeup;			// ??: pending timeout															
    WORD        wCount2;				// ??: nonce for SleepList														
    BYTE        bPendSusp;				// ??: pending suspend count													
    BYTE        bDbgCnt;				// ??: recurse level in debug message											
    HANDLE      hLastCrit;				// ??: Last crit taken, cleared by nextthread									
    //DWORD     dwCrabTime;
    CALLSTACK   IntrStk;
    DWORD       dwKernTime;				// ??: elapsed kernel time														
    DWORD       dwUserTime;				// ??: elapsed user time														
    HANDLE      hTok;					// ??: thread token																
};  // Thread 

//=============================================================================================================================
// Process Structure
//=============================================================================================================================
typedef struct o32_lite {
    unsigned long       o32_vsize;
    unsigned long       o32_rva;
    unsigned long       o32_realaddr;
    unsigned long       o32_access;
    unsigned long       o32_flags;
    unsigned long       o32_psize;
    unsigned long       o32_dataptr;
} o32_lite, *LPo32_lite;

#define LITE_EXTRA      7				// Only first 7 used by NK														

struct info {							// Extra information header block												
    unsigned long   rva;				// Virtual relative address of info												
    unsigned long   size;				// Size of information block													
};

typedef struct e32_lite {				// PE 32-bit .EXE header														
    unsigned short  e32_objcnt;			// Number of memory objects														
    BYTE            e32_cevermajor;		// version of CE built for														
    BYTE            e32_ceverminor;		// version of CE built for														
    unsigned long   e32_stackmax;		// Maximum stack size															
    unsigned long   e32_vbase;			// Virtual base address of module												
    unsigned long   e32_vsize;			// Virtual size of the entire image												
    unsigned long	e32_sect14rva;		// section 14 rva																
    unsigned long	e32_sect14size;		// section 14 size																
    unsigned long   e32_timestamp;		// Time EXE/DLL was created/modified											
    struct info     e32_unit[LITE_EXTRA];// Array of extra info units													
} e32_lite, *LPe32_list;

typedef struct _PGPOOL_Q {
    WORD    idxHead;					// head of the queue															
    WORD    idxTail;					// tail of the queue															
} PGPOOL_Q, *PPGPOOL_Q;

typedef struct {
    WORD wPool;
    WCHAR name[MAX_PATH];				// name of item																	
} Name, * LPName;

typedef struct TOCentry {				// MODULE BIB section structure
    DWORD dwFileAttributes;
    FILETIME ftTime;
    DWORD nFileSize;
    LPSTR   lpszFileName;
    ULONG   ulE32Offset;				// Offset to E32 structure
    ULONG   ulO32Offset;				// Offset to O32 structure
    ULONG   ulLoadOffset;				// MODULE load buffer offset
} TOCentry, *LPTOCentry;

typedef struct openexe_t {
    union {
        HANDLE hf;						// object store handle
        TOCentry *tocptr;				// rom entry pointer
    };
    BYTE filetype;
    BYTE bIsOID;
    WORD pagemode;
    union {
        DWORD offset;
        DWORD dwExtRomAttrib;
    };
    union {
        Name *lpName;
        CEOID ceOid;
    };
} openexe_t;

#define MAX_PROCESSES 32

typedef struct Module MODULE;
typedef MODULE *PMODULE, *LPMODULE;
typedef struct Module {
    LPVOID      lpSelf;                 // Self pointer for validation													
    PMODULE     pMod;                   // Next module in chain															
    LPWSTR      lpszModName;            // Module name																	
    DWORD       inuse;                  // Bit vector of use															
    WORD        refcnt[MAX_PROCESSES];  // Reference count per process													
    LPVOID      BasePtr;                // Base pointer of dll load (not 0 based)										
    DWORD       DbgFlags;               // Debug flags																	
    LPDBGPARAM  ZonePtr;                // Debug zone pointer															
    ulong       startip;                // 0 based entrypoint															
    openexe_t   oe;                     // Pointer to executable file handle											
    e32_lite    e32;                    // E32 header																	
    o32_lite    *o32_ptr;               // O32 chain ptr																
    DWORD       dwNoNotify;             // 1 bit per process, set if notifications disabled								
    WORD        wFlags;
    BYTE        bTrustLevel;
    BYTE        bPadding;
    PMODULE     pmodResource;           // module that contains the resources											
    DWORD       rwLow;                  // base address of RW section for ROM DLL										
    DWORD       rwHigh;                 // high address RW section for ROM DLL											
    PGPOOL_Q    pgqueue;                // list of the page owned by the module											
    LPVOID      pShimInfo;              // pointer to shim information													
} Module;

#define BLOCK_MASK				0x1FF
#define SECTION_MASK			0x03F
#define RESERVED_SECTIONS		1		// reserve section 0 for current process

// Bit offsets of page, block & section in a virtual address:
#define VA_BLOCK				16
#define VA_SECTION				25

#if (defined(ARMV4) || defined(ARMV4T) || defined(ARMV4I))     // uses 4K page tables
#define VA_PAGE					12
#define L2_MASK					0xFF    // For a 4K page size (small pages)
#define PAGE_SIZE				4096
#elif defined(ARM920)					// uses 1K page tables
#define VA_PAGE					10
#define L2_MASK					0x3FF
#define PAGE_SIZE				1024
#elif defined(x86)
#define VA_PAGE					12
#define PAGE_SIZE				4096      /* page size */
#endif

#define PAGES_PER_BLOCK			(0x10000 / PAGE_SIZE)

// # of pages needed for Page Table per process
#define HARDWARE_PT_PER_PROC	8

typedef struct _MODULELIST {
    struct _MODULELIST *pNext;			// next entry
    PMODULE             pMod;			// the module
} MODULELIST, *PMODULELIST;

// Any time this structure is redefined, we need to recalculate
// the offset used in the SHx profiler ISR located at
// %_WINCEROOT%\platform\ODO\kernel\profiler\shx\profisr.src
struct Process {
    BYTE        procnum;				// 00: ID of this process [ie: it's slot number]								
    BYTE        DbgActive;				// 01: ID of process currently DebugActiveProcess'ing this process				
    BYTE        bChainDebug;			// 02: Did the creator want to debug child processes?							
    BYTE        bTrustLevel;			// 03: level of trust of this exe												
#define OFFSET_TRUSTLVL     3			// offset of the bTrustLevel member in Process structure
    LPPROXY     pProxList;				// 04: list of proxies to threads blocked on this process						
    HANDLE      hProc;					// 08: handle for this process, needed only for SC_GetProcFromPtr				
    DWORD       dwVMBase;				// 0C: base of process's memory section, or 0 if not in use						
    PTHREAD     pTh;					// 10: first thread in this process												
    ACCESSKEY   aky;					// 14: default address space key for process's threads							
    LPVOID      BasePtr;				// 18: Base pointer of exe load													
    HANDLE      hDbgrThrd;				// 1C: handle of thread debugging this process, if any							
    LPWSTR      lpszProcName;			// 20: name of process															
    DWORD       tlsLowUsed;				// 24: TLS in use bitmask (first 32 slots)										
    DWORD       tlsHighUsed;			// 28: TLS in use bitmask (second 32 slots)										
    PEXCEPTION_ROUTINE pfnEH;			// 2C: process exception handler												
    LPDBGPARAM  ZonePtr;				// 30: Debug zone pointer														
    PTHREAD     pMainTh;				// 34  primary thread in this process											
    PMODULE     pmodResource;			// 38: module that contains the resources										
    LPName      pStdNames[3];			// 3C: Pointer to names for stdio												
    LPCWSTR     pcmdline;				// 48: Pointer to command line													
    DWORD       dwDyingThreads;			// 4C: number of pending dying threads											
    openexe_t   oe;						// 50: Pointer to executable file handle										
    e32_lite    e32;					// ??: structure containing exe header											
    o32_lite    *o32_ptr;				// ??: o32 array pointer for exe												
    LPVOID      pExtPdata;				// ??: extend pdata																
    BYTE        bPrio;					// ??: highest priority of all threads of the process							
    BYTE        fNoDebug;				// ??: this process cannot be debugged											
    WORD        wModCount;				// ??: # of modules in pLastModList												
    PGPOOL_Q    pgqueue;				// ??: list of the page owned by the process									
    PMODULELIST pLastModList;			// ??: the list of modules that just loaded/unloaded into the process			
    HANDLE      hTok;					// ??: process default token													
#if HARDWARE_PT_PER_PROC
    ulong       pPTBL[HARDWARE_PT_PER_PROC];// hardware page tables														
#endif
    LPVOID      pShimInfo;				// pointer to shim information													
};  // Process 


//=============================================================================================================================
// Kernel Data Struct
//=============================================================================================================================
#if defined(_ARM_)
#define PUserKData ((LPBYTE)0xFFFFC800)
#else
#define PUserKData ((LPBYTE)0x00005800)
#endif

#define NUM_SYS_HANDLES  32

#define SYSINTR_MAX_DEVICES 64

typedef struct EVENT *LPEVENT;

typedef struct EVENT {
    HANDLE hNext;						// Next event in list															
    LPPROXY pProxList;
    LPPROXY pProxHash[PRIORITY_LEVELS_HASHSIZE];
    HANDLE hPrev;						// previous event in list														
    BYTE onequeue;
    BYTE state;							// TRUE: signalled, FALSE: unsignalled											
    BYTE manualreset;					// TRUE: manual reset, FALSE: autoreset											
    BYTE bMaxPrio;
    Name *name;							// points to name of event														
    LPPROXY pIntrProxy;
    DWORD dwData;						// data associated with the event (CE extention)								
} EVENT;

typedef ulong ACCESSLOCK;

/* Memory Block
 *   This structure maps a 64K block of memory. All memory reservations
 * must begin on a 64k boundary.
 */
struct MemBlock {
    ACCESSLOCK  alk;					/* 00: key code for this set of pages */
    uchar       cUses;					/* 04: # of page table entries sharing this leaf */
    uchar       flags;					/* 05: mapping flags */
    short       ixBase;					/* 06: first block in region */
    short       hPf;					/* 08: handle to pager */
    short       cLocks;					/* 0a: lock count */
#if HARDWARE_PT_PER_PROC
    ulong       *aPages;				/* 0c: pointer to the VA of hardware page table */
#else
    ulong       aPages[PAGES_PER_BLOCK];/* 0c: entrylo values */
#endif
}; /* MemBlock */

typedef struct MemBlock MEMBLOCK;
typedef MEMBLOCK *SECTION[BLOCK_MASK+1];
typedef SECTION *PSECTION;

#if defined(x86)

struct KDataStruct {
    LPDWORD lpvTls;						/* 0x000 Current thread local storage pointer */
    HANDLE  ahSys[NUM_SYS_HANDLES];		/* 0x004 If this moves, change kapi.h */
    char    bResched;					/* 0x084 reschedule flag */
    char    cNest;						/* 0x085 kernel exception nesting */
    char    bPowerOff;					/* 0x086 TRUE during "power off" processing */
    char    bProfileOn;					/* 0x087 TRUE if profiling enabled */
    ulong   cMsec;						/* 0x088 # of milliseconds since boot */
    ulong   cDMsec;						/* 0x08c # of mSec since last TimerCallBack */
    DWORD   dwKCRes;					/* 0x090 was process breakpoint */
    ulong   handleBase;					/* 0x094 base address of handle table */
    PTHREAD pCurThd;					/* 0x098 ptr to current THREAD struct */
    PPROCESS pCurPrc;					/* 0x09c ptr to current PROCESS struct */
    PSECTION aSections[64];				/* 0x0a0 section table for virutal memory */
    LPEVENT alpeIntrEvents[SYSINTR_MAX_DEVICES];/* 0x1a0 */
    ulong   pAPIReturn;					/* 0x2a0 direct API return address for kernel mode */
    DWORD   dwInDebugger;				/* 0x2a4 - !0 when in debugger */
    long    nMemForPT;					/* 0x2a8 - Memory used for PageTables */
    DWORD   dwCpuCap;					/* 0x2ac - CPU capability bits */
    DWORD   aPend1;						/* 0x2b0 - low (int 0-31) dword of interrupts pending (must be 8-byte aligned) */
    DWORD   aPend2;						/* 0x2b4 - high (int 32-63) dword of interrupts pending */
    long    alPad[18];					/* 0x2b8 - padding */
    DWORD   aInfo[32];					/* 0x300 - misc. kernel info */
										/* 0x380-0x400 reserved */
										/* 0x400 - end */
};  /* KDataStruct */

#ifndef KData
#define KData			(*(KDataStruct *)NULL)
#endif

#elif defined(ARM)

struct KDataStruct {
    LPDWORD lpvTls;						// 0x000 Current thread local storage pointer									
    HANDLE  ahSys[NUM_SYS_HANDLES];		// 0x004 If this moves, change kapi.h											
    char    bResched;					// 0x084 reschedule flag														
    char    cNest;						// 0x085 kernel exception nesting												
    char    bPowerOff;					// 0x086 TRUE during "power off" processing										
    char    bProfileOn;					// 0x087 TRUE if profiling enabled												
    ulong   unused;						// 0x088 unused																	
    ulong   rsvd2;						// 0x08c was DiffMSec															
    PPROCESS pCurPrc;					// 0x090 ptr to current PROCESS struct											
    PTHREAD pCurThd;					// 0x094 ptr to current THREAD struct											
    DWORD   dwKCRes;					// 0x098																		
    ulong   handleBase;					// 0x09c handle table base address												
    PSECTION aSections[64];				// 0x0a0 section table for virutal memory										
    LPEVENT alpeIntrEvents[SYSINTR_MAX_DEVICES];// 0x1a0																
    ulong   pAPIReturn;					// 0x2a0 direct API return address for kernel mode								
    uchar   *pMap;						// 0x2a4 ptr to MemoryMap array													
    DWORD   dwInDebugger;				// 0x2a8 !0 when in debugger													
    PTHREAD pCurFPUOwner;				// 0x2ac current FPU owner														
    PPROCESS pCpuASIDPrc;				// 0x2b0 current ASID proc														
    long    nMemForPT;					// 0x2b4 - Memory used for PageTables											

    DWORD   aPend1;						// 0x2b8 - low (int 0-31) dword of interrupts pending (must be 8-byte aligned)	
    DWORD   aPend2;						// 0x2bc - high (int 32-63) dword of interrupts pending							

    long    alPad[16];					// 0x2c0 - padding																
    DWORD   aInfo[32];					// 0x300 - misc. kernel info													
										// 0x380 - interlocked api code													
										// 0x400 - end																	
};  // KDataStruct

typedef struct ARM_HIGH {
    ulong   firstPT[4096];				// 0xFFFD0000: 1st level page table
    char    reserved2[0x20000-0x4000];

    char    exVectors[0x400];			// 0xFFFF0000: exception vectors
    char    reserved3[0x2400-0x400];

    char    intrStack[0x400];			// 0xFFFF2400: interrupt stack
    char    reserved4[0x4900-0x2800];

    char    abortStack[0x700];			// 0xFFFF4900: abort stack
    char    reserved5[0x6800-0x5000];

    char    fiqStack[0x100];			// 0xFFFF6800: FIQ stack
    char    reserved6[0xC000-0x6900];

    char    kStack[0x800];				// 0xFFFFC000: kernel stack
    struct KDataStruct kdata;			// 0xFFFFC800: kernel data page
} ARM_HIGH;

// KData is already a define on ARM.  Ignore anyone's attempt to
// predefine it.
#ifdef KData
#undef KData
#endif

#define ArmHigh			((ARM_HIGH *)0xFFFD0000)
#define FirstPT			(ArmHigh->firstPT)
#define KData			(ArmHigh->kdata)
#define VKData			(*(volatile struct KDataStruct *)&KData)

#endif

//=============================================================================================================================
//
//=============================================================================================================================
#define EXP             0				// Export table position														
#define IMP             1				// Import table position														
#define RES             2				// Resource table position														
#define EXC             3				// Exception table position														
#define SEC             4				// Security table position														
#define FIX             5				// Fixup table position															
#define DEB             6				// Debug table position															
#define IMD             7				// Image description table position												
#define MSP             8				// Machine specific table position												
#define TLS             9				// Thread Local Storage															
#define CBK            10				// Callbacks																	
#define RS1            11				// Reserved																		
#define RS2            12				// Reserved																		
#define RS3            13				// Reserved																		
#define RS4            14				// Reserved																		
#define RS5            15				// Reserved																		

#define HasModRefProcPtr(pMod,pProc) ((pMod)->refcnt[(pProc)->procnum] != 0)

/* indices for for UserKInfo array in kernel data page */
#define UserKInfo  ((long *)(PUserKData+KINFO_OFFSET))

#define KINX_PROCARRAY			0		// address of process array 
#define KINX_PAGESIZE			1		// system page size 
#define KINX_PFN_SHIFT			2		// shift for page # in PTE 
#define KINX_PFN_MASK			3		// mask for page # in PTE 
#define KINX_PAGEFREE			4		// # of free physical pages 
#define KINX_SYSPAGES			5		// # of pages used by kernel 
#define KINX_KHEAP				6		// ptr to kernel heap array 
#define KINX_SECTIONS			7		// ptr to SectionTable array 
#define KINX_MEMINFO			8		// ptr to system MemoryInfo struct 
#define KINX_MODULES			9		// ptr to module list 
#define KINX_DLL_LOW			10		// lower bound of DLL shared space 
#define KINX_NUMPAGES			11		// total # of RAM pages 
#define KINX_PTOC				12		// ptr to ROM table of contents 
#define KINX_KDATA_ADDR			13		// kernel mode version of KData 
#define KINX_GWESHEAPINFO		14		// Current amount of gwes heap in use 
#define KINX_TIMEZONEBIAS		15		// Fast timezone bias info 
#define KINX_PENDEVENTS			16		// bit mask for pending interrupt events 
#define KINX_KERNRESERVE		17		// number of kernel reserved pages 
#define KINX_API_MASK			18		// bit mask for registered api sets 
#define KINX_NLS_CP				19		// hiword OEM code page, loword ANSI code page 
#define KINX_NLS_SYSLOC			20		// Default System locale 
#define KINX_NLS_USERLOC		21		// Default User locale 
#define KINX_HEAP_WASTE			22		// Kernel heap wasted space 
#define KINX_DEBUGGER			23		// For use by debugger for protocol communication 
#define KINX_APISETS			24		// APIset pointers 
#define KINX_MINPAGEFREE		25		// water mark of the minimum number of free pages 
#define KINX_CELOGSTATUS		26		// CeLog status flags 
#define KINX_NKSECTION			27		// Address of NKSection 
#define KINX_PTR_CURTOKEN		28		// Events to be set after power on 
#define KINX_TIMECHANGECOUNT	29		// # of times time changed 

/* Fast path for file system mapping of multiple pointers quickly */
#define SECTION_SHIFT			25		// Must be in sync with VA_SECTION in kapi.h, mem_*.h
// secure section related defs
#define SECURE_SECTION			0x61	// VM at 0xC2XXXXXX
#define SECURE_VMBASE			(SECURE_SECTION << SECTION_SHIFT)
#define IsSecureVa(va)			(SECURE_SECTION == ((DWORD) (va) >> SECTION_SHIFT))

#define MAX_PROCESSES			32
#define RESERVED_SECTIONS		1		// reserve section 0 for current process

#define FIRST_MAPPER_ADDRESS	((MAX_PROCESSES+RESERVED_SECTIONS) << SECTION_SHIFT)
#define LAST_MAPPER_ADDRESS		0x7C000000

#define ZeroPtrABS(P) ((((DWORD)(P) & 0x80000000) && !IsSecureVa(P)) ? (DWORD)(P) : ((DWORD)(P) & ((1<<SECTION_SHIFT)-1)))

#define ZeroPtr(P) ((((DWORD)(P) < (2<<SECTION_SHIFT)) || ((int) (P) >= FIRST_MAPPER_ADDRESS)) ? (DWORD) (P) : ZeroPtrABS(P))

#define MapPtrWithBits(Ptr, Bits) (!(Ptr) || ((DWORD)(Ptr)>>SECTION_SHIFT) ? (LPVOID)(Ptr) : (LPVOID)((DWORD)(Ptr)|(Bits)))

#define CECOMPRESS_ALLZEROS		0
#define CECOMPRESS_FAILED		0xffffffffUL
#define CEDECOMPRESS_FAILED		0xffffffffUL

#if 1

typedef DWORD (WINAPI* SETKMODE)(DWORD);
typedef LPVOID (WINAPI* MAPPTRTOPROCESS)(LPVOID, HANDLE);
typedef DWORD (WINAPI* SETPROCPERMISSIONS)(DWORD);
typedef BOOL (WINAPI* VIRTUALPROTECTEX)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);

#else

DWORD SetKMode(DWORD);
LPVOID MapPtrToProcess(LPVOID lpv, HANDLE hProc);
DWORD SetProcPermissions(DWORD newperms);
BOOL WINAPI VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

#endif
// JCW_+ 2008.07.18 END