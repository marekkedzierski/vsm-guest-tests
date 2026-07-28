//
// vsm_ktest_kvmvsm.c -- Driver handlers for Sections 23-34
//
// KVM-specific VSM/VTL implementation verification tests.
// Covers: VTL switch latency, per-VTL MSR isolation, VP register
// round-trip, GPA granularity, XSAVE isolation, reenlightenment MSRs,
// crash MSRs, CR4 intercept, SynIC signal/post, TLB flush, and
// VP assist page VTL entry fields.
//
// Build alongside vsm_ktest.c and vsm_ktest_isolation.c:
//   cl /kernel /O2 /GS- /c vsm_ktest.c vsm_ktest_isolation.c vsm_ktest_kvmvsm.c
//   link ... vsm_ktest.obj vsm_ktest_isolation.obj vsm_ktest_kvmvsm.obj vsm_vmcall.obj
//

#include <ntddk.h>

#define VSMT_SENTINEL  0xFFFFFFFFFFFFFFFFull

// Safe MSR read -- extern from vsm_ktest.c
extern UINT64 SafeReadMsr(ULONG msr);

// VMCALL stubs -- extern from vsm_vmcall.asm
extern UINT64 VsmtFastHypercall(UINT64 callCode, UINT64 inputVal);
extern UINT64 VsmtSlowHypercall(UINT64 callCode, UINT64 inGpa, UINT64 outGpa);

// FXSAVE/FXRSTOR stubs -- extern from vsm_vmcall.asm
extern void VsmtFxSave(void* saveArea);
extern void VsmtFxRstor(void* saveArea);

// ---------------------------------------------------------------------------
// Structures (must match vsm_test_kvmvsm.cpp)
// All boolean fields are UINT32 to match user-mode BOOL (DWORD).
// ---------------------------------------------------------------------------

#define VTL_LATENCY_SAMPLES 100

typedef struct {
    UINT64   MinCycles;
    UINT64   MaxCycles;
    UINT64   MedianCycles;
    UINT64   AvgCycles;
    UINT32   SampleCount;
    NTSTATUS Status;
} VSMT_VTL_LATENCY;

typedef struct {
    UINT64   Vtl0Sint0;
    UINT64   Vtl0Sint1;
    UINT64   Vtl0Stimer0Config;
    UINT64   Vtl0Scontrol;
    UINT64   Vtl0Simp;
    UINT64   Vtl0Siefp;
    UINT32   Sint0MatchesVtl1;
    UINT32   Sint1MatchesVtl1;
    UINT32   Stimer0MatchesVtl1;
    NTSTATUS Status;
} VSMT_MSR_ISOLATION;

typedef struct {
    UINT64   VtlConfigValue;
    UINT64   CodePageOffsets;
    UINT64   HvStatusRead;
    UINT32   SecureVtlConfigNonZero;
    UINT32   ConsistentReads;
    NTSTATUS Status;
} VSMT_SETVPREG;

typedef struct {
    UINT32   DataReadOk;
    UINT32   PoolReadOk;
    UINT32   DataExecBlocked;
    UINT64   TestPagePa;
    NTSTATUS Status;
} VSMT_GPA_GRANULARITY;

typedef struct {
    UINT32   XmmPreserved;
    INT32    CorruptedRegister;
    UINT64   Xmm0Before;
    UINT64   Xmm0After;
    NTSTATUS Status;
} VSMT_XSAVE_ISOLATION;

typedef struct {
    UINT64   ReenlightenCtrl;
    UINT64   TscEmulCtrl;
    UINT64   TscEmulStatus;
    UINT32   ReenlightenGpFault;
    UINT32   TscEmulCtrlGpFault;
    UINT32   TscEmulStatusGpFault;
    NTSTATUS Status;
} VSMT_REENLIGHTEN;

typedef struct {
    UINT64   CrashCtl;
    UINT64   CrashP0;
    UINT64   CrashP1;
    UINT64   CrashP2;
    UINT64   CrashP3;
    UINT64   CrashP4;
    UINT32   CrashCtlGpFaulted;
    UINT32   CrashDataGpFaulted;
    NTSTATUS Status;
} VSMT_CRASH_MSRS;

typedef struct {
    UINT64   OrigCr4;
    UINT64   PostWriteCr4;
    UINT32   SmepPreserved;
    UINT32   ExceptionRaised;
    NTSTATUS Status;
} VSMT_CR4_INTERCEPT;

typedef struct {
    UINT64   SignalEventStatus;
    UINT64   PostMessageStatus;
    NTSTATUS Status;
} VSMT_SYNIC_SIGNAL;

typedef struct {
    UINT64   FlushSpaceStatus;
    UINT64   FlushListStatus;
    NTSTATUS Status;
} VSMT_FLUSH;

typedef struct {
    UINT64   VtlControlRegValue;
    UINT64   VtlControlPagePa;
    UINT32   VtlEntryReason;
    UINT32   VtlControlAccessible;
    UINT64   HvStatusGetReg;
    NTSTATUS Status;
} VSMT_VTL_CONTROL;

// FXSAVE area XMM register offsets (x86-64 layout)
#define FXSAVE_SIZE    512
#define FXSAVE_XMM0    160
#define FXSAVE_XMM1    176
#define FXSAVE_XMM2    192
#define FXSAVE_XMM3    208

// ---------------------------------------------------------------------------
// HANDLER: HandleVtlLatency (0x80E, Section 23)
//
// Measures VTL switch latency by timing HvCallGetVpRegisters calls
// for a VTL1 register (0x00090013 VpAssistPage).  Runs at DISPATCH_LEVEL
// to prevent thread preemption from inflating measurements.
// ---------------------------------------------------------------------------

NTSTATUS HandleVtlLatency(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    UINT64 samples[VTL_LATENCY_SAMPLES];
    PHYSICAL_ADDRESS lo, hi;
    PHYSICAL_ADDRESS inPhys, outPhys;
    PVOID inPage, outPage;
    PUINT64 inp;
    KIRQL oldIrql;
    UINT64 totalCycles, temp;
    int i, j;

    if (outLen < sizeof(VSMT_VTL_LATENCY)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_VTL_LATENCY* s = (VSMT_VTL_LATENCY*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    lo.QuadPart = 0;
    hi.QuadPart = 0x7FFFFFFF;
    inPage  = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    outPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage || !outPage) {
        if (inPage)  MmFreeContiguousMemory(inPage);
        if (outPage) MmFreeContiguousMemory(outPage);
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_VTL_LATENCY);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(inPage, 4096);
    RtlZeroMemory(outPage, 4096);

    // HvCallGetVpRegisters input: PartitionId, VpIndex, InputVtl, register name
    inp = (PUINT64)inPage;
    inp[0] = 0xFFFFFFFFFFFFFFFFull;       // PartitionId = self
    ((PUINT32)inPage)[2] = 0xFFFFFFFEu;   // VpIndex = current VP
    ((PUINT8)inPage)[12] = 0xFF;           // InputVtl = current
    inp[2] = 0x00090013ull;                // HvRegisterVpAssistPage

    inPhys  = MmGetPhysicalAddress(inPage);
    outPhys = MmGetPhysicalAddress(outPage);

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    for (i = 0; i < VTL_LATENCY_SAMPLES; i++) {
        UINT64 before, after;
        _mm_lfence();
        before = __rdtsc();
        VsmtSlowHypercall(0x0050ull | (1ull << 32),
                          inPhys.QuadPart, outPhys.QuadPart);
        _mm_lfence();
        after = __rdtsc();
        samples[i] = after - before;
    }

    KeLowerIrql(oldIrql);

    // Insertion sort for median
    for (i = 1; i < VTL_LATENCY_SAMPLES; i++) {
        temp = samples[i];
        j = i - 1;
        while (j >= 0 && samples[j] > temp) {
            samples[j + 1] = samples[j];
            j--;
        }
        samples[j + 1] = temp;
    }

    totalCycles = 0;
    s->MinCycles = samples[0];
    s->MaxCycles = samples[VTL_LATENCY_SAMPLES - 1];
    s->MedianCycles = samples[VTL_LATENCY_SAMPLES / 2];
    for (i = 0; i < VTL_LATENCY_SAMPLES; i++)
        totalCycles += samples[i];
    s->AvgCycles = totalCycles / VTL_LATENCY_SAMPLES;
    s->SampleCount = VTL_LATENCY_SAMPLES;

    MmFreeContiguousMemory(inPage);
    MmFreeContiguousMemory(outPage);

    KdPrint(("VsmTest: VTL latency min=%llu median=%llu max=%llu avg=%llu\n",
             s->MinCycles, s->MedianCycles, s->MaxCycles, s->AvgCycles));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_VTL_LATENCY);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleMsrIsolation (0x80F, Section 24)
//
// Reads SynIC/STIMER MSRs from VTL0 context and checks whether they
// return VTL1-specific values.  If so, KVM's per-VTL MSR banking is broken.
//
// Expected VTL1 values (from securekernel ShvlpInitializeSynic):
//   SINT0 = 0x200F0, SINT1 = 0x20051, STIMER0_CONFIG = 0x10008
// ---------------------------------------------------------------------------

NTSTATUS HandleMsrIsolation(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_MSR_ISOLATION)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_MSR_ISOLATION* s = (VSMT_MSR_ISOLATION*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    s->Vtl0Sint0         = SafeReadMsr(0x40000090u);
    s->Vtl0Sint1         = SafeReadMsr(0x40000091u);
    s->Vtl0Stimer0Config = SafeReadMsr(0x400000B0u);
    s->Vtl0Scontrol      = SafeReadMsr(0x40000080u);
    s->Vtl0Simp          = SafeReadMsr(0x40000082u);
    s->Vtl0Siefp         = SafeReadMsr(0x40000083u);

    s->Sint0MatchesVtl1    = (s->Vtl0Sint0 == 0x200F0ull) ? TRUE : FALSE;
    s->Sint1MatchesVtl1    = (s->Vtl0Sint1 == 0x20051ull) ? TRUE : FALSE;
    s->Stimer0MatchesVtl1  = (s->Vtl0Stimer0Config == 0x10008ull) ? TRUE : FALSE;

    KdPrint(("VsmTest: MSR isolation VTL0 SINT0=0x%llX SINT1=0x%llX STIMER0=0x%llX\n",
             s->Vtl0Sint0, s->Vtl0Sint1, s->Vtl0Stimer0Config));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_MSR_ISOLATION);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleSetVpReg (0x810, Section 25)
//
// Validates that HvCallSetVpRegisters works by reading VP registers that
// securekernel must have written during VTL1 initialization.
//
// Reads:
//   0x000D0006 HvRegisterVsmVpSecureVtlConfig
//   0x000D0002 HvRegisterVsmCodePageOffsets
// ---------------------------------------------------------------------------

static UINT64 ReadOneVpRegister(UINT32 regId, PVOID inPage, PVOID outPage,
                                 PHYSICAL_ADDRESS inPhys, PHYSICAL_ADDRESS outPhys)
{
    PUINT64 inp = (PUINT64)inPage;
    PUINT64 outp = (PUINT64)outPage;
    UINT64 hvStatus;

    RtlZeroMemory(inPage, 4096);
    RtlZeroMemory(outPage, 4096);

    inp[0] = 0xFFFFFFFFFFFFFFFFull;
    ((PUINT32)inPage)[2] = 0xFFFFFFFEu;
    ((PUINT8)inPage)[12] = 0xFF;
    inp[2] = (UINT64)regId;

    hvStatus = VsmtSlowHypercall(0x0050ull | (1ull << 32),
                                  inPhys.QuadPart, outPhys.QuadPart);
    if ((hvStatus & 0xFFFF) == 0)
        return outp[0];
    return VSMT_SENTINEL;
}

NTSTATUS HandleSetVpReg(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    PHYSICAL_ADDRESS lo, hi, inPhys, outPhys;
    PVOID inPage, outPage;
    UINT64 val1, val2;

    if (outLen < sizeof(VSMT_SETVPREG)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_SETVPREG* s = (VSMT_SETVPREG*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    lo.QuadPart = 0;
    hi.QuadPart = 0x7FFFFFFF;
    inPage  = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    outPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage || !outPage) {
        if (inPage)  MmFreeContiguousMemory(inPage);
        if (outPage) MmFreeContiguousMemory(outPage);
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_SETVPREG);
        return STATUS_SUCCESS;
    }

    inPhys  = MmGetPhysicalAddress(inPage);
    outPhys = MmGetPhysicalAddress(outPage);

    s->VtlConfigValue = ReadOneVpRegister(0x000D0006u, inPage, outPage, inPhys, outPhys);
    s->SecureVtlConfigNonZero = (s->VtlConfigValue != 0 && s->VtlConfigValue != VSMT_SENTINEL);

    val1 = ReadOneVpRegister(0x000D0002u, inPage, outPage, inPhys, outPhys);
    val2 = ReadOneVpRegister(0x000D0002u, inPage, outPage, inPhys, outPhys);
    s->CodePageOffsets = val1;
    s->ConsistentReads = (val1 == val2 && val1 != VSMT_SENTINEL);
    s->HvStatusRead = (val1 != VSMT_SENTINEL) ? 0 : VSMT_SENTINEL;

    KdPrint(("VsmTest: SetVpReg VtlConfig=0x%llX CodePageOffsets=0x%llX consistent=%d\n",
             s->VtlConfigValue, s->CodePageOffsets, s->ConsistentReads));

    MmFreeContiguousMemory(inPage);
    MmFreeContiguousMemory(outPage);

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_SETVPREG);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleGpaGranularity (0x811, Section 26)
//
// Tests EPT/NPT permission granularity beyond write-protect.
// Allocates a NonPagedPool page, maps by PA via MmMapIoSpace, tests:
//   1. Read via PA mapping (should succeed)
//   2. Execute from PA mapping (should be blocked if MBEC/HVCI active)
// ---------------------------------------------------------------------------

NTSTATUS HandleGpaGranularity(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    PVOID pool, mapped;
    PHYSICAL_ADDRESS pa;
    static const UCHAR shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 };

    if (outLen < sizeof(VSMT_GPA_GRANULARITY)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_GPA_GRANULARITY* s = (VSMT_GPA_GRANULARITY*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'GPAG');
    if (!pool) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_GPA_GRANULARITY);
        return STATUS_SUCCESS;
    }

    RtlCopyMemory(pool, shellcode, sizeof(shellcode));
    KeMemoryBarrier();

    pa = MmGetPhysicalAddress(pool);
    s->TestPagePa = pa.QuadPart;

    if (pa.QuadPart == 0) {
        ExFreePool(pool);
        s->Status = STATUS_NOT_FOUND;
        *outInfo = sizeof(VSMT_GPA_GRANULARITY);
        return STATUS_SUCCESS;
    }

    mapped = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
    if (!mapped) {
        ExFreePool(pool);
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_GPA_GRANULARITY);
        return STATUS_SUCCESS;
    }

    // Read test via PA mapping
    {
        UCHAR dummy = 0;
        __try {
            dummy = ((volatile UCHAR*)mapped)[0];
            (void)dummy;
            s->DataReadOk = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->DataReadOk = FALSE;
        }
    }

    // Direct pool read
    {
        UCHAR dummy2 = 0;
        __try {
            dummy2 = ((volatile UCHAR*)pool)[0];
            (void)dummy2;
            s->PoolReadOk = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->PoolReadOk = FALSE;
        }
    }

    // Execute test from PA-mapped address
    {
        typedef UINT64 (*fn_t)(void);
        __try {
            UINT64 r = ((fn_t)mapped)();
            (void)r;
            s->DataExecBlocked = FALSE;
            KdPrint(("VsmTest: GPA granularity: exec from PA mapping SUCCEEDED\n"));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->DataExecBlocked = TRUE;
            KdPrint(("VsmTest: GPA granularity: exec from PA mapping BLOCKED\n"));
        }
    }

    MmUnmapIoSpace(mapped, PAGE_SIZE);
    ExFreePool(pool);

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_GPA_GRANULARITY);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleXsaveIsolation (0x812, Section 28)
//
// Tests that FPU/SSE state is preserved across VTL switches.
//
// Uses FXSAVE/FXRSTOR (via asm stubs in vsm_vmcall.asm) to load known
// patterns into XMM0-3, trigger a VTL switch via hypercall, then save
// and compare.  The /kernel flag disables compiler SSE codegen, so XMM
// registers are untouched between our explicit FXRSTOR and FXSAVE --
// the only thing that can corrupt them is the hypervisor's VTL switch
// state save/restore path.
//
// FXSAVE area layout (x86-64):
//   Offset 160: XMM0 (16 bytes)
//   Offset 176: XMM1 (16 bytes)
//   Offset 192: XMM2 (16 bytes)
//   Offset 208: XMM3 (16 bytes)
// ---------------------------------------------------------------------------

NTSTATUS HandleXsaveIsolation(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    XSTATE_SAVE xstateSave;
    NTSTATUS xst;
    PHYSICAL_ADDRESS lo, hi, inPhys, outPhys;
    PVOID inPage, outPage;
    PUCHAR fxBuf;
    PUCHAR fxOrig, fxMod, fxAfter;
    PUINT64 inp;
    int i;
    UINT32 allMatch;

    if (outLen < sizeof(VSMT_XSAVE_ISOLATION)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_XSAVE_ISOLATION* s = (VSMT_XSAVE_ISOLATION*)outBuf;
    RtlZeroMemory(s, sizeof(*s));
    s->CorruptedRegister = -1;

    // 3 x 512-byte FXSAVE areas (ExAllocatePool2 returns 16-byte aligned on x64)
    fxBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, FXSAVE_SIZE * 3, 'FXSV');
    if (!fxBuf) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_XSAVE_ISOLATION);
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(fxBuf, FXSAVE_SIZE * 3);
    fxOrig  = fxBuf;
    fxMod   = fxBuf + FXSAVE_SIZE;
    fxAfter = fxBuf + FXSAVE_SIZE * 2;

    lo.QuadPart = 0;
    hi.QuadPart = 0x7FFFFFFF;
    inPage  = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    outPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage || !outPage) {
        if (inPage)  MmFreeContiguousMemory(inPage);
        if (outPage) MmFreeContiguousMemory(outPage);
        ExFreePool(fxBuf);
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_XSAVE_ISOLATION);
        return STATUS_SUCCESS;
    }

    // Build hypercall input (read VpAssistPage -- triggers VTL switch)
    RtlZeroMemory(inPage, 4096);
    RtlZeroMemory(outPage, 4096);
    inp = (PUINT64)inPage;
    inp[0] = 0xFFFFFFFFFFFFFFFFull;
    ((PUINT32)inPage)[2] = 0xFFFFFFFEu;
    ((PUINT8)inPage)[12] = 0xFF;
    inp[2] = 0x00090013ull;

    inPhys  = MmGetPhysicalAddress(inPage);
    outPhys = MmGetPhysicalAddress(outPage);

    xst = KeSaveExtendedProcessorState(XSTATE_MASK_LEGACY_SSE, &xstateSave);
    if (!NT_SUCCESS(xst)) {
        MmFreeContiguousMemory(inPage);
        MmFreeContiguousMemory(outPage);
        ExFreePool(fxBuf);
        s->Status = xst;
        *outInfo = sizeof(VSMT_XSAVE_ISOLATION);
        return STATUS_SUCCESS;
    }

    // Save current FPU/SSE state
    VsmtFxSave(fxOrig);

    // Copy original, then write known patterns into XMM0-3 slots
    RtlCopyMemory(fxMod, fxOrig, FXSAVE_SIZE);
    *(UINT64*)(fxMod + FXSAVE_XMM0)     = 0xDEADBEEFCAFEBABEull;
    *(UINT64*)(fxMod + FXSAVE_XMM0 + 8) = 0x1111111111111111ull;
    *(UINT64*)(fxMod + FXSAVE_XMM1)     = 0x0123456789ABCDEFull;
    *(UINT64*)(fxMod + FXSAVE_XMM1 + 8) = 0x2222222222222222ull;
    *(UINT64*)(fxMod + FXSAVE_XMM2)     = 0xFEDCBA9876543210ull;
    *(UINT64*)(fxMod + FXSAVE_XMM2 + 8) = 0x3333333333333333ull;
    *(UINT64*)(fxMod + FXSAVE_XMM3)     = 0xA5A5A5A55A5A5A5Aull;
    *(UINT64*)(fxMod + FXSAVE_XMM3 + 8) = 0x4444444444444444ull;

    s->Xmm0Before = *(UINT64*)(fxMod + FXSAVE_XMM0);

    // Load known patterns into XMM registers
    VsmtFxRstor(fxMod);

    // Trigger VTL switch via hypercall
    VsmtSlowHypercall(0x0050ull | (1ull << 32),
                      inPhys.QuadPart, outPhys.QuadPart);

    // Save state after VTL switch
    VsmtFxSave(fxAfter);

    // Restore original FPU/SSE state before KeRestore
    VsmtFxRstor(fxOrig);

    KeRestoreExtendedProcessorState(&xstateSave);

    // Compare XMM0-3 in fxMod vs fxAfter
    allMatch = TRUE;
    for (i = 0; i < 4; i++) {
        ULONG off = FXSAVE_XMM0 + (ULONG)(i * 16);
        UINT64 modLo  = *(UINT64*)(fxMod + off);
        UINT64 modHi  = *(UINT64*)(fxMod + off + 8);
        UINT64 aftLo  = *(UINT64*)(fxAfter + off);
        UINT64 aftHi  = *(UINT64*)(fxAfter + off + 8);
        if (modLo != aftLo || modHi != aftHi) {
            allMatch = FALSE;
            if (s->CorruptedRegister == -1)
                s->CorruptedRegister = i;
        }
    }

    s->Xmm0After = *(UINT64*)(fxAfter + FXSAVE_XMM0);
    s->XmmPreserved = allMatch;

    MmFreeContiguousMemory(inPage);
    MmFreeContiguousMemory(outPage);
    ExFreePool(fxBuf);

    KdPrint(("VsmTest: XSAVE isolation: preserved=%d corrupted=%d\n",
             s->XmmPreserved, s->CorruptedRegister));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_XSAVE_ISOLATION);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleReenlighten (0x813, Section 29)
//
// Reads reenlightenment and TSC emulation MSRs.  Critical for live
// migration of VSM guests.
//   0x40000106 -- HV_X64_MSR_REENLIGHTENMENT_CONTROL
//   0x40000107 -- HV_X64_MSR_TSC_EMULATION_CONTROL
//   0x40000108 -- HV_X64_MSR_TSC_EMULATION_STATUS
// ---------------------------------------------------------------------------

NTSTATUS HandleReenlighten(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_REENLIGHTEN)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_REENLIGHTEN* s = (VSMT_REENLIGHTEN*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    s->ReenlightenCtrl = SafeReadMsr(0x40000106u);
    s->TscEmulCtrl     = SafeReadMsr(0x40000107u);
    s->TscEmulStatus   = SafeReadMsr(0x40000108u);

    s->ReenlightenGpFault   = (s->ReenlightenCtrl == VSMT_SENTINEL);
    s->TscEmulCtrlGpFault   = (s->TscEmulCtrl == VSMT_SENTINEL);
    s->TscEmulStatusGpFault = (s->TscEmulStatus == VSMT_SENTINEL);

    KdPrint(("VsmTest: Reenlighten: ctrl=0x%llX emulCtrl=0x%llX emulStatus=0x%llX\n",
             s->ReenlightenCtrl, s->TscEmulCtrl, s->TscEmulStatus));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_REENLIGHTEN);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleCrashMsrs (0x814, Section 30)
//
// Non-destructive read of crash notification MSRs.
// 0x40000100-0x40000104: HV_X64_MSR_CRASH_P0 through P4
// 0x40000105: HV_X64_MSR_CRASH_CTL
//
// WARNING: DO NOT WRITE to these MSRs.  Writing to CrashCtl with
// CrashNotify bit set triggers a crash notification to the hypervisor.
// ---------------------------------------------------------------------------

NTSTATUS HandleCrashMsrs(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_CRASH_MSRS)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_CRASH_MSRS* s = (VSMT_CRASH_MSRS*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    s->CrashP0  = SafeReadMsr(0x40000100u);
    s->CrashP1  = SafeReadMsr(0x40000101u);
    s->CrashP2  = SafeReadMsr(0x40000102u);
    s->CrashP3  = SafeReadMsr(0x40000103u);
    s->CrashP4  = SafeReadMsr(0x40000104u);
    s->CrashCtl = SafeReadMsr(0x40000105u);

    s->CrashCtlGpFaulted = (s->CrashCtl == VSMT_SENTINEL);
    s->CrashDataGpFaulted = (s->CrashP0 == VSMT_SENTINEL ||
                             s->CrashP1 == VSMT_SENTINEL ||
                             s->CrashP2 == VSMT_SENTINEL ||
                             s->CrashP3 == VSMT_SENTINEL ||
                             s->CrashP4 == VSMT_SENTINEL);

    KdPrint(("VsmTest: CrashMsrs: ctl=0x%llX P0=0x%llX gpFault=%d\n",
             s->CrashCtl, s->CrashP0, s->CrashCtlGpFaulted));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_CRASH_MSRS);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleCr4Intercept (0x815, Section 31)
//
// Tests VTL1 CR4 write intercept.  VTL1 installs an intercept on CR4
// writes to prevent VTL0 from clearing SMEP/SMAP bits.
//
// HIGH RISK: if VTL1 intercept is NOT installed, the SMEP bit will
// actually be cleared.  Safety measures:
//   1. Skip if SMEP not set in CR4
//   2. Wrap in __try/__except
//   3. If SMEP was cleared, immediately restore original CR4
// ---------------------------------------------------------------------------

NTSTATUS HandleCr4Intercept(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    UINT64 origCr4;

    if (outLen < sizeof(VSMT_CR4_INTERCEPT)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_CR4_INTERCEPT* s = (VSMT_CR4_INTERCEPT*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    origCr4 = __readcr4();
    s->OrigCr4 = origCr4;

    // SMEP is bit 20.  If not set, skip the test.
    if (!(origCr4 & (1ull << 20))) {
        s->Status = STATUS_NOT_SUPPORTED;
        *outInfo = sizeof(VSMT_CR4_INTERCEPT);
        return STATUS_SUCCESS;
    }

    // Attempt to clear SMEP.  VTL1 intercept should block or revert this.
    __try {
        __writecr4(origCr4 & ~(1ull << 20));
        s->ExceptionRaised = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        s->ExceptionRaised = TRUE;
    }

    s->PostWriteCr4 = __readcr4();
    s->SmepPreserved = (s->PostWriteCr4 & (1ull << 20)) != 0;

    // SAFETY: if SMEP was actually cleared, restore immediately
    if (!s->SmepPreserved) {
        __try {
            __writecr4(origCr4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            KdPrint(("VsmTest: CR4 SMEP restore also intercepted!\n"));
        }
        KdPrint(("VsmTest: CR4 SMEP was cleared -- restored to 0x%llX\n", origCr4));
    }

    KdPrint(("VsmTest: CR4 intercept: orig=0x%llX post=0x%llX smepOk=%d except=%d\n",
             s->OrigCr4, s->PostWriteCr4, s->SmepPreserved, s->ExceptionRaised));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_CR4_INTERCEPT);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleSynicSignal (0x816, Section 32)
//
// Tests SynIC hypercall dispatch:
//   HvCallSignalEvent (0x005D) with connection ID = 0 (invalid)
//   HvCallPostMessage (0x005C) with connection ID = 0 (invalid)
//
// Expected: HV_STATUS != 0 but the hypercall infrastructure must not crash.
// ---------------------------------------------------------------------------

NTSTATUS HandleSynicSignal(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    PHYSICAL_ADDRESS lo, hi, inPhys;
    PVOID inPage;

    if (outLen < sizeof(VSMT_SYNIC_SIGNAL)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_SYNIC_SIGNAL* s = (VSMT_SYNIC_SIGNAL*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    lo.QuadPart = 0;
    hi.QuadPart = 0x7FFFFFFF;
    inPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_SYNIC_SIGNAL);
        return STATUS_SUCCESS;
    }

    // HvCallSignalEvent (0x005D) -- fast hypercall, connection ID in RDX
    s->SignalEventStatus = VsmtFastHypercall(0x005Dull | (1ull << 16), 0);

    // HvCallPostMessage (0x005C) -- slow hypercall
    // Input: +0x00 UINT32 ConnectionId, +0x04 UINT32 Reserved,
    //        +0x08 UINT32 MessageType, +0x0C UINT32 PayloadSize
    RtlZeroMemory(inPage, 4096);
    ((PUINT32)inPage)[0] = 0;   // ConnectionId = 0
    ((PUINT32)inPage)[2] = 1;   // MessageType = 1
    ((PUINT32)inPage)[3] = 0;   // PayloadSize = 0
    inPhys = MmGetPhysicalAddress(inPage);

    s->PostMessageStatus = VsmtSlowHypercall(0x005Cull, inPhys.QuadPart, 0);

    KdPrint(("VsmTest: SynIC signal: event=0x%llX post=0x%llX\n",
             s->SignalEventStatus, s->PostMessageStatus));

    MmFreeContiguousMemory(inPage);

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_SYNIC_SIGNAL);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleFlush (0x817, Section 33)
//
// Tests TLB flush hypercalls:
//   HvCallFlushVirtualAddressSpace (0x0002)
//   HvCallFlushVirtualAddressList  (0x0003)
//
// Stale TLB entries after a VTL switch could allow VTL0 to access
// re-protected pages -- a security vulnerability.
// ---------------------------------------------------------------------------

NTSTATUS HandleFlush(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    PHYSICAL_ADDRESS lo, hi, inPhys;
    PVOID inPage;
    PUINT64 inp;

    if (outLen < sizeof(VSMT_FLUSH)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_FLUSH* s = (VSMT_FLUSH*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    lo.QuadPart = 0;
    hi.QuadPart = 0x7FFFFFFF;
    inPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_FLUSH);
        return STATUS_SUCCESS;
    }

    inp = (PUINT64)inPage;

    // HvCallFlushVirtualAddressSpace (0x0002)
    // Input: {UINT64 AddressSpace, UINT64 Flags, HV_GENERIC_SET ProcessorSet}
    RtlZeroMemory(inPage, 4096);
    inp[0] = 0;                      // AddressSpace = 0 (current)
    inp[1] = (1ull | (1ull << 2));   // FLUSH_ALL_SPACES | FLUSH_ALL_PROCESSORS
    inp[2] = 0;                      // ProcessorMask (ignored with FLUSH_ALL_PROCESSORS)
    inPhys = MmGetPhysicalAddress(inPage);

    s->FlushSpaceStatus = VsmtSlowHypercall(0x0002ull, inPhys.QuadPart, 0);

    // HvCallFlushVirtualAddressList (0x0003) -- rep hypercall, 1 VA
    RtlZeroMemory(inPage, 4096);
    inp[0] = 0;                      // AddressSpace = 0
    inp[1] = (1ull << 2);            // FLUSH_ALL_PROCESSORS
    inp[2] = 0;                      // ProcessorMask
    inp[3] = 0;                      // First VA to flush

    s->FlushListStatus = VsmtSlowHypercall(0x0003ull | (1ull << 32),
                                            inPhys.QuadPart, 0);

    KdPrint(("VsmTest: Flush: space=0x%llX list=0x%llX\n",
             s->FlushSpaceStatus, s->FlushListStatus));

    MmFreeContiguousMemory(inPage);

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_FLUSH);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: HandleVtlControl (0x818, Section 34)
//
// Reads the VTL Control Page via VP register 0x000D0010 (VsmVpVtlControl).
//
// The VTL control page is SEPARATE from the VP assist page (0x40000073).
// Verified from securekernel disassembly: ShvlpConfigureVtlControls sets
// register 0xD0010, and securekernel reads VtlEntryReason at gs:10h -> [+0x00].
//
// VTL control page layout (version >= 2, from hvax64 binary):
//   +0x00 UINT32 VtlEntryReason   (0 = VtlCall, 1 = Interrupt delivery)
//   +0x08        Saved return register state (written by HV during VtlReturn)
//   +0x18        Additional return state
//
// VtlReturnAction is passed via ECX register during VtlReturn hypercall,
// NOT stored in any page.  Cannot be read from a mapped page.
// ---------------------------------------------------------------------------

NTSTATUS HandleVtlControl(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    PHYSICAL_ADDRESS lo, hi, inPhys, outPhys;
    PVOID inPage, outPage;
    PUINT64 inp, outp;
    UINT64 hvStatus;
    UINT64 regValue;
    PHYSICAL_ADDRESS ctlPa;
    PVOID mapped;

    if (outLen < sizeof(VSMT_VTL_CONTROL)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_VTL_CONTROL* s = (VSMT_VTL_CONTROL*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    lo.QuadPart = 0;
    hi.QuadPart = 0x7FFFFFFF;
    inPage  = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    outPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage || !outPage) {
        if (inPage)  MmFreeContiguousMemory(inPage);
        if (outPage) MmFreeContiguousMemory(outPage);
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_VTL_CONTROL);
        return STATUS_SUCCESS;
    }

    // HvCallGetVpRegisters for 0x000D0010 (VsmVpVtlControl)
    RtlZeroMemory(inPage, 4096);
    RtlZeroMemory(outPage, 4096);
    inp = (PUINT64)inPage;
    outp = (PUINT64)outPage;
    inp[0] = 0xFFFFFFFFFFFFFFFFull;       // PartitionId = self
    ((PUINT32)inPage)[2] = 0xFFFFFFFEu;   // VpIndex = current
    ((PUINT8)inPage)[12] = 0xFF;           // InputVtl = current
    inp[2] = 0x000D0010ull;                // HvRegisterVsmVpVtlControl

    inPhys  = MmGetPhysicalAddress(inPage);
    outPhys = MmGetPhysicalAddress(outPage);

    hvStatus = VsmtSlowHypercall(0x0050ull | (1ull << 32),
                                  inPhys.QuadPart, outPhys.QuadPart);
    s->HvStatusGetReg = hvStatus;

    if ((hvStatus & 0xFFFF) != 0) {
        MmFreeContiguousMemory(inPage);
        MmFreeContiguousMemory(outPage);
        s->Status = STATUS_NOT_FOUND;
        *outInfo = sizeof(VSMT_VTL_CONTROL);
        return STATUS_SUCCESS;
    }

    regValue = outp[0];
    s->VtlControlRegValue = regValue;

    // The register value is a PFN with enable bit 0, same format as VpAssistPage
    ctlPa.QuadPart = (LONGLONG)((regValue & ~0xFFFull));
    if (regValue & 1)
        ctlPa.QuadPart = (LONGLONG)((regValue >> 12) << 12);
    s->VtlControlPagePa = ctlPa.QuadPart;

    if (ctlPa.QuadPart == 0) {
        MmFreeContiguousMemory(inPage);
        MmFreeContiguousMemory(outPage);
        s->Status = STATUS_NOT_FOUND;
        *outInfo = sizeof(VSMT_VTL_CONTROL);
        return STATUS_SUCCESS;
    }

    mapped = MmMapIoSpace(ctlPa, PAGE_SIZE, MmCached);
    if (!mapped) {
        MmFreeContiguousMemory(inPage);
        MmFreeContiguousMemory(outPage);
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_VTL_CONTROL);
        return STATUS_SUCCESS;
    }

    // VtlEntryReason at offset +0x00 (DWORD)
    {
        PUCHAR pg = (PUCHAR)mapped;
        __try {
            s->VtlEntryReason = *(UINT32*)(pg + 0x000);
            s->VtlControlAccessible = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->VtlControlAccessible = FALSE;
            KdPrint(("VsmTest: VtlControl page read faulted (VTL1-protected?)\n"));
        }
    }

    MmUnmapIoSpace(mapped, PAGE_SIZE);
    MmFreeContiguousMemory(inPage);
    MmFreeContiguousMemory(outPage);

    KdPrint(("VsmTest: VtlControl: reg=0x%llX PA=0x%llX reason=%u accessible=%d\n",
             s->VtlControlRegValue, s->VtlControlPagePa,
             s->VtlEntryReason, s->VtlControlAccessible));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_VTL_CONTROL);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Dispatch function
// ---------------------------------------------------------------------------

#define VSMT_IOCTL_VTL_LATENCY      CTL_CODE(0x8000u, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_MSR_ISOLATION    CTL_CODE(0x8000u, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_SETVPREG         CTL_CODE(0x8000u, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_GPA_GRANULARITY  CTL_CODE(0x8000u, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_XSAVE_ISOLATION  CTL_CODE(0x8000u, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_REENLIGHTEN      CTL_CODE(0x8000u, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_CRASH_MSRS       CTL_CODE(0x8000u, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_CR4_INTERCEPT    CTL_CODE(0x8000u, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_SYNIC_SIGNAL     CTL_CODE(0x8000u, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_FLUSH            CTL_CODE(0x8000u, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_VTL_ENTRY_REASON CTL_CODE(0x8000u, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS VsmtKvmVsmDispatch(ULONG code, PVOID buf, ULONG inLen, ULONG outLen,
                             PULONG_PTR outInfo)
{
    (void)inLen;
    switch (code) {
    case VSMT_IOCTL_VTL_LATENCY:      return HandleVtlLatency(buf, outLen, outInfo);
    case VSMT_IOCTL_MSR_ISOLATION:    return HandleMsrIsolation(buf, outLen, outInfo);
    case VSMT_IOCTL_SETVPREG:         return HandleSetVpReg(buf, outLen, outInfo);
    case VSMT_IOCTL_GPA_GRANULARITY:  return HandleGpaGranularity(buf, outLen, outInfo);
    case VSMT_IOCTL_XSAVE_ISOLATION:  return HandleXsaveIsolation(buf, outLen, outInfo);
    case VSMT_IOCTL_REENLIGHTEN:      return HandleReenlighten(buf, outLen, outInfo);
    case VSMT_IOCTL_CRASH_MSRS:       return HandleCrashMsrs(buf, outLen, outInfo);
    case VSMT_IOCTL_CR4_INTERCEPT:    return HandleCr4Intercept(buf, outLen, outInfo);
    case VSMT_IOCTL_SYNIC_SIGNAL:     return HandleSynicSignal(buf, outLen, outInfo);
    case VSMT_IOCTL_FLUSH:            return HandleFlush(buf, outLen, outInfo);
    case VSMT_IOCTL_VTL_ENTRY_REASON: return HandleVtlControl(buf, outLen, outInfo);
    default: return STATUS_INVALID_DEVICE_REQUEST;
    }
}
