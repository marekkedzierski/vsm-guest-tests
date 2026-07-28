//
// vsm_ktest_isolation.c -- Driver handlers for Sections 17-22
//
// Add to vsm_ktest.c build:
//   cl /kernel /O2 /GS- /c vsm_ktest.c vsm_ktest_isolation.c
//   link ... vsm_ktest.obj vsm_ktest_isolation.obj vsm_vmcall.obj
//
// Implements IOCTL handlers for:
//   0x808  VSMT_IOCTL_LIVENESS_TEST  -- TIME_REF_COUNT / STIMER / VP_RUNTIME monotonicity
//   0x809  VSMT_IOCTL_REF_TSC        -- Reference TSC page content (TscSequence, TscScale)
//   0x80A  VSMT_IOCTL_PHYS_BYPASS    -- Physical mapping bypass write-protection test
//   0x80B  VSMT_IOCTL_MBEC_EXEC      -- Supervisor execute control (NonPagedPoolNx)
//   0x80C  VSMT_IOCTL_MULTIVCPU      -- Per-CPU VP_INDEX uniqueness
//   0x80D  VSMT_IOCTL_ASSIST_PAGE    -- VP assist page content
//

#include <ntddk.h>
#include <ntimage.h>   // PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS

// RtlPcToFileHeader: returns the base address of the image containing PcValue.
// Exported by ntoskrnl.exe; declaration needed because ntddk.h may guard it
// behind NTDDI_VERSION checks that don't match our project settings.
PVOID RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage);

// Sentinel returned when rdmsr GP-faults (MSR not implemented by KVM)
#define VSMT_SENTINEL  0xFFFFFFFFFFFFFFFFull

// Safe MSR read -- extern from vsm_ktest.c
extern UINT64 SafeReadMsr(ULONG msr);

// VMCALL stub -- extern from vsm_vmcall.asm
extern UINT64 VsmtSlowHypercall(UINT64 callCode, UINT64 inGpa, UINT64 outGpa);

// ---------------------------------------------------------------------------
// Structures (must match vsm_test_isolation.cpp)
// ---------------------------------------------------------------------------

typedef struct {
    UINT64   TimeRef1, TimeRef2;
    UINT64   Stimer0Count1, Stimer0Count2;
    UINT64   VpRuntime1, VpRuntime2;
    NTSTATUS Status;
} VSMT_LIVENESS;

typedef struct {
    UINT64   RefTscPage;
    UINT32   TscSequence;
    UINT32   Reserved;
    UINT64   TscScale;
    UINT64   TscOffset;
    NTSTATUS Status;
} VSMT_REF_TSC;

typedef struct {
    UINT64   NtoskrnlCodePagePa;
    UINT32   WriteBlocked;
    UINT32   ReadAllowed;
    NTSTATUS Status;
} VSMT_PHYS_BYPASS;

typedef struct {
    // Use UINT32 for all boolean fields -- matches BOOL (DWORD) on the user-mode side
    // so the struct layout is identical across the IOCTL boundary.

    // Method 1: NonPagedPoolNx supervisor execute
    UINT32   ExecBlocked;          // 1 = NX pool exec blocked from Ring 0
    UINT32   WriteProtBlocked;     // 1 = MmProtectMdl(RWX) blocked by HVCI

    // Method 2: user-GPA via MmMapIoSpace → supervisor execute attempt
    UINT32   UserGpaReadAllowed;   // 1 = kernel can still READ the user GPA
    UINT32   UserGpaExecBlocked;   // 1 = supervisor execute blocked (MBEC working)
    UINT64   UserGpaPhysAddr;      // PA of the user-mode page (reference)

    NTSTATUS Status;
} VSMT_MBEC_EXEC;

typedef struct {
    ULONG    CpuCount;
    UINT64   VpIndexPerCpu[64];
    UINT32   AllUnique;
    UINT32   MatchesCpuCount;
    NTSTATUS Status;
} VSMT_MULTIVCPU;

typedef struct {
    UINT64   AssistPagePa;
    UINT32   ApicAssist;
    UINT32   NestedEnlBit;
    UINT64   CurrentNestedVmcs;
    NTSTATUS Status;
} VSMT_ASSIST_PAGE;

// ---------------------------------------------------------------------------
// HANDLER: VSMT_IOCTL_LIVENESS_TEST
//
// Reads TIME_REF_COUNT, VP_RUNTIME, and STIMER0_COUNT twice with a 10ms
// sleep between reads. Non-advancing values indicate broken KVM MSR emulation.
//
// KEY INSIGHT: if TIME_REF_COUNT doesn't advance, KVM is returning a constant
// (or 0) for MSR 0x40000020. ntoskrnl uses this for guest time; a broken
// implementation causes all time-dependent kernel operations to malfunction.
//
// STIMER0_COUNT advancing confirms VTL1's scheduling timer is firing.
// ---------------------------------------------------------------------------

NTSTATUS HandleLivenessTest(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_LIVENESS)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_LIVENESS* s = (VSMT_LIVENESS*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    s->TimeRef1      = SafeReadMsr(0x40000020u);  // HV_MSR_TIME_REF_COUNT
    s->Stimer0Count1 = SafeReadMsr(0x400000B1u);  // HV_MSR_STIMER0_COUNT
    s->VpRuntime1    = SafeReadMsr(0x40000004u);  // HV_MSR_VP_RUNTIME

    // 10ms delay -- enough time for all three counters to advance visibly
    LARGE_INTEGER delay;
    delay.QuadPart = -100000LL;  // 10ms in 100ns units (negative = relative)
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    s->TimeRef2      = SafeReadMsr(0x40000020u);
    s->Stimer0Count2 = SafeReadMsr(0x400000B1u);
    s->VpRuntime2    = SafeReadMsr(0x40000004u);

    KdPrint(("VsmTest: TimeRef: %llu -> %llu (+%llu), STIMER0: %llu -> %llu\n",
             s->TimeRef1, s->TimeRef2, s->TimeRef2 - s->TimeRef1,
             s->Stimer0Count1, s->Stimer0Count2));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_LIVENESS);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: VSMT_IOCTL_REF_TSC
//
// Reads MSR 0x40000021 (HV_MSR_REFERENCE_TSC) and maps the physical page
// it points to. Reads HVTSC_REFERENCE_PAGE fields:
//   +0x000 UINT32 TscSequence   -- non-zero when page is active
//   +0x004 UINT32 Reserved      -- always 0
//   +0x008 UINT64 TscScale      -- TSC multiplier (scaled by 2^-64)
//   +0x010 INT64  TscOffset     -- addend after scaling
//
// KVM must write TscSequence != 0 when the reference TSC page is active.
// Without this, ntoskrnl falls back from HvlGetReferenceTimeUsingTscPage
// to a slower hypercall-based time path.
//
// TSC time formula: T(100ns) = (TSC * TscScale) >> 64 + TscOffset
// ---------------------------------------------------------------------------

NTSTATUS HandleRefTsc(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_REF_TSC)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_REF_TSC* s = (VSMT_REF_TSC*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    s->RefTscPage = SafeReadMsr(0x40000021u);

    if (s->RefTscPage == VSMT_SENTINEL || !(s->RefTscPage & 1)) {
        // MSR GP-faulted or page not enabled
        s->Status = STATUS_NOT_SUPPORTED;
        *outInfo = sizeof(VSMT_REF_TSC);
        return STATUS_SUCCESS;
    }

    // GPA is in bits [63:12]
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(s->RefTscPage & ~0xFFFull);

    // Map the physical page into kernel VA -- bypasses page table protections
    PVOID mapped = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
    if (!mapped) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_REF_TSC);
        return STATUS_SUCCESS;
    }

    // Read with SEH in case the page is protected (shouldn't be, but safe)
    {
        PUCHAR pg = (PUCHAR)mapped;  // declared before __try (C89)
        __try {
            s->TscSequence = *(UINT32*)(pg + 0x000);
            s->Reserved    = *(UINT32*)(pg + 0x004);
            s->TscScale    = *(UINT64*)(pg + 0x008);
            s->TscOffset   = *(UINT64*)(pg + 0x010);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            KdPrint(("VsmTest: RefTsc page read faulted (GPA=0x%llX)\n", pa.QuadPart));
            s->TscSequence = 0;
        }
    }

    MmUnmapIoSpace(mapped, PAGE_SIZE);

    KdPrint(("VsmTest: RefTsc GPA=0x%llX Seq=0x%X Scale=0x%llX Offset=0x%llX\n",
             pa.QuadPart, s->TscSequence, s->TscScale, s->TscOffset));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_REF_TSC);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: VSMT_IOCTL_PHYS_BYPASS
//
// Tests VTL1 SLAT (EPT/NPT) write-protection via physical address bypass.
//
// MmMapIoSpace creates a new kernel VA -> GPA mapping, completely bypassing
// the existing page table entries (CR3-based protections). The ONLY protection
// that applies to MmMapIoSpace accesses is the SLAT (EPT/NPT) -- exactly
// the layer that VTL1 controls via HvCallModifyVtlProtectionMask.
//
// Procedure:
//   1. Get PA of ntoskrnl's first code page (definitely VTL1 write-protected
//      when HVCI is active -- SkmiProtectPageRange marks code GPAs read-only)
//   2. Create new kernel mapping via MmMapIoSpace (different VA, same GPA)
//   3. READ: should succeed (VTL0 can read code)
//   4. WRITE: should fault if EPT W=0 (VTL1 set write-protect on this GPA)
//
// This directly validates HvCallModifyVtlProtectionMask (0x00B1) enforcement
// and SkmiProtectPageRange (securekernel).
//
// KVM: after HvCallModifyVtlProtectionMask clears W bit, the EPT entry for
// that GPA must have EPT_WRITABLE = 0. Any VTL0 write to that GPA must
// cause an EPT violation -> hypervisor injects #GP or PF into guest.
// ---------------------------------------------------------------------------

NTSTATUS HandlePhysBypass(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_PHYS_BYPASS)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_PHYS_BYPASS* s = (VSMT_PHYS_BYPASS*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    //
    // Get ntoskrnl's load address via RtlPcToFileHeader on a known ntoskrnl export.
    // RtlPcToFileHeader returns the base of the image that contains the given PC.
    // ExAllocatePool2 is always in ntoskrnl, so this reliably gives its load base.
    //
    PVOID base = NULL;
    RtlPcToFileHeader((PVOID)(ULONG_PTR)ExAllocatePool2, &base);
    if (!base) {
        s->Status = STATUS_OBJECT_NAME_NOT_FOUND;
        *outInfo = sizeof(VSMT_PHYS_BYPASS);
        return STATUS_SUCCESS;
    }

    // Find code section start (IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PUCHAR)base + dos->e_lfanew);
    PVOID codeVa = (PUCHAR)base + nt->OptionalHeader.BaseOfCode;

    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(codeVa);
    s->NtoskrnlCodePagePa = pa.QuadPart;

    KdPrint(("VsmTest: PhysBypass: ntoskrnl code VA=%p PA=0x%llX\n",
             codeVa, pa.QuadPart));

    if (pa.QuadPart == 0) {
        KdPrint(("VsmTest: MmGetPhysicalAddress returned 0 -- page not in VTL0 tables?\n"));
        s->Status = STATUS_NOT_FOUND;
        *outInfo = sizeof(VSMT_PHYS_BYPASS);
        return STATUS_SUCCESS;
    }

    // Map the same physical page under a NEW kernel VA (bypasses PTEs entirely)
    PVOID mapped = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
    if (!mapped) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_PHYS_BYPASS);
        return STATUS_SUCCESS;
    }

    // Test 1: READ -- VTL0 should be able to read code pages
    {
        UCHAR dummy = 0;  // declared before __try (C89)
        __try {
            dummy = ((volatile UCHAR*)mapped)[0];
            (void)dummy;
            s->ReadAllowed = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->ReadAllowed = FALSE;
            KdPrint(("VsmTest: PhysBypass READ faulted -- unexpected\n"));
        }
    }

    // Test 2: WRITE -- VTL1 should have cleared EPT W bit on this GPA
    {
        UCHAR orig = ((volatile UCHAR*)mapped)[0];  // read first, declared before __try
        __try {
            ((volatile UCHAR*)mapped)[0] = orig;  // write same value -- tests W bit only
            s->WriteBlocked = FALSE;
            KdPrint(("VsmTest: PhysBypass WRITE SUCCEEDED -- EPT W bit not cleared!\n"));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->WriteBlocked = TRUE;
            KdPrint(("VsmTest: PhysBypass WRITE faulted -- EPT W=0 enforced by VTL1.\n"));
        }
    }

    MmUnmapIoSpace(mapped, PAGE_SIZE);

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_PHYS_BYPASS);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: VSMT_IOCTL_MBEC_EXEC
//
// Tests MBEC (Mode-Based Execute Control) supervisor execute enforcement.
//
// Allocates NonPagedPoolNx (explicitly non-execute).
// Writes shellcode: xor rax,rax; ret (4 bytes).
// Attempts to execute it from kernel Ring 0.
//
// With MBEC + HVCI:
//   VTL1 sets EPT supervisor-execute = 0 on NX pool pages via
//   SkmiProtectPageRange -> HvCallModifyVtlProtectionMask.
//   Execute attempt -> EPT execute violation -> hypervisor injects fault.
//   ExecBlocked = TRUE.
//
// Without MBEC (HVCI write-protect only):
//   EPT W=0 prevents writing shellcode, but EPT supervisor-X=1 still allows
//   execution of data in pool pages. ExecBlocked = FALSE (weaker guarantee).
//   This is the key distinction between HVCI with and without MBEC.
//
// AMD KVM: GMET (VMCB bit) must be enabled. Without GMET, AMD NPT has no
//   separate supervisor/user execute control -- only a single X bit.
//   CPUID 0x8000000A EDX bit 23 must be set when GMET is enabled.
//
// Intel KVM: EPT secondary controls bit 22 (MODE_BASED_EPT_EXECUTE_CONTROL)
//   must be enabled in VMCS. EPT entries gain separate UserModeExecute bit.
//   CPUID 0x40000006[18] (MbecAvailable) must be set.
// ---------------------------------------------------------------------------

NTSTATUS HandleMbecExec(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_MBEC_EXEC)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_MBEC_EXEC* s = (VSMT_MBEC_EXEC*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    // Allocate non-paged, non-execute pool (pool tag 'MBEC' for diagnosis)
    PVOID pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'CEBM');
    if (!pool) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_MBEC_EXEC);
        return STATUS_SUCCESS;
    }

    // Write trivial shellcode: xor rax,rax; ret = 48 31 C0 C3
    // This returns 0 in RAX if execution reaches it.
    static const UCHAR shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 };
    RtlCopyMemory(pool, shellcode, sizeof(shellcode));

    // Memory barrier to ensure shellcode is visible before execution attempt
    KeMemoryBarrier();

    // Attempt supervisor-mode execute from NonPagedPoolNx
    // With MBEC/HVCI: EPT supervisor-X=0 -> VM exit -> hypervisor injects #GP
    typedef UINT64(*fn_t)(void);
    __try {
        UINT64 result = ((fn_t)pool)();
        (void)result;
        s->ExecBlocked = FALSE;
        KdPrint(("VsmTest: MBEC: Pool execute SUCCEEDED -- MBEC not enforcing! result=%llu\n",
                 result));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        s->ExecBlocked = TRUE;
        KdPrint(("VsmTest: MBEC: Pool execute BLOCKED (exception 0x%X) -- MBEC working.\n",
                 GetExceptionCode()));
    }

    // Secondary test: try to change the pool page to PAGE_EXECUTE_READWRITE
    // With HVCI: MmProtectMdlSystemAddress should fail (write-protect already set)
    // This tests the write-protection side separately from execute control
    PMDL mdl = IoAllocateMdl(pool, PAGE_SIZE, FALSE, FALSE, NULL);
    if (mdl) {
        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
            PVOID sysAddr = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
            if (sysAddr) {
                // Try to change protection to include execute
                NTSTATUS chgSt = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
                s->WriteProtBlocked = !NT_SUCCESS(chgSt);
                KdPrint(("VsmTest: MBEC: MmProtectMdlSystemAddress(RWX) -> 0x%X (%s)\n",
                         chgSt, NT_SUCCESS(chgSt) ? "succeeded" : "blocked"));
            }
            MmUnlockPages(mdl);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->WriteProtBlocked = TRUE;
        }
        IoFreeMdl(mdl);
    }

    ExFreePool(pool);

    // -------------------------------------------------------------------------
    // Method 2: user-GPA supervisor execute via MmMapIoSpace
    //
    // Definitively tests MBEC's per-privilege-level execute control.
    //
    // Key insight: MmMapIoSpace creates a new kernel PTE (U/S=0) for the same
    // physical page as a user-mode executable allocation.  SMEP is satisfied
    // (PTE U/S=0 → supervisor fetch allowed at page-table level).  The ONLY
    // thing that can still block execution is EPT supervisor-execute=0 — i.e.,
    // MBEC enforced by VTL1 via HvCallModifyVtlProtectionMask.
    //
    // Without MBEC: EPT has a single X bit; user executable page → X=1 for all
    //              rings → kernel execution succeeds (UserGpaExecBlocked = FALSE).
    // With MBEC:   VTL1 sets EPT supervisor-X=0 on user-mode GPAs;
    //              kernel execution faults (UserGpaExecBlocked = TRUE).
    // -------------------------------------------------------------------------
    {
        PVOID   userVa     = NULL;
        SIZE_T  regionSize = PAGE_SIZE;

        // Allocate a user-mode executable page in the calling process context.
        // We are in the IRP dispatch context so NtCurrentProcess() is correct.
        static const UCHAR sc[] = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax,rax; ret
        NTSTATUS allocSt = ZwAllocateVirtualMemory(
            NtCurrentProcess(), &userVa, 0, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (NT_SUCCESS(allocSt) && userVa) {
            // Write shellcode into user-mode page via SEH
            {
                ULONG i;
                __try {
                    for (i = 0; i < sizeof(sc); i++)
                        ((volatile UCHAR*)userVa)[i] = sc[i];
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    KdPrint(("VsmTest: M2: user page write faulted\n"));
                }
            }

            // Get physical address of the user-mode page
            {
                PHYSICAL_ADDRESS userPA = MmGetPhysicalAddress(userVa);
                s->UserGpaPhysAddr = userPA.QuadPart;

                KdPrint(("VsmTest: M2: user VA=%p PA=0x%llX\n", userVa, userPA.QuadPart));

                if (userPA.QuadPart != 0) {
                    // Create a kernel VA mapping to the same GPA.
                    // PTE U/S=0 → SMEP satisfied.
                    // EPT supervisor-execute bit is the only remaining gate.
                    PVOID kernMap = MmMapIoSpace(userPA, PAGE_SIZE, MmCached);
                    if (kernMap) {
                        // Read test: EPT R bit should still be 1 for user GPAs
                        {
                            UCHAR dummy = 0;
                            __try {
                                dummy = ((volatile UCHAR*)kernMap)[0];
                                (void)dummy;
                                s->UserGpaReadAllowed = TRUE;
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                s->UserGpaReadAllowed = FALSE;
                                KdPrint(("VsmTest: M2: kernel read of user GPA faulted\n"));
                            }
                        }

                        // Execute test: MBEC supervisor-execute=0 must block this
                        {
                            typedef UINT64(*fn_t)(void);
                            __try {
                                UINT64 r = ((fn_t)kernMap)();
                                (void)r;
                                s->UserGpaExecBlocked = FALSE;
                                KdPrint(("VsmTest: M2: kernel exec of user GPA SUCCEEDED"
                                         " -- MBEC supervisor-X not enforced!\n"));
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                s->UserGpaExecBlocked = TRUE;
                                KdPrint(("VsmTest: M2: kernel exec of user GPA BLOCKED"
                                         " -- EPT supervisor-X=0 confirmed.\n"));
                            }
                        }

                        MmUnmapIoSpace(kernMap, PAGE_SIZE);
                    }
                }
            }

            // Free user-mode allocation
            regionSize = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &userVa, &regionSize, MEM_RELEASE);
        } else {
            KdPrint(("VsmTest: M2: ZwAllocateVirtualMemory failed 0x%X\n", allocSt));
        }
    }

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_MBEC_EXEC);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: VSMT_IOCTL_MULTIVCPU
//
// Reads VP_INDEX (MSR 0x40000002) on each logical CPU.
// Every VP must have a unique index assigned by KVM.
//
// Bug to detect: KVM returning the same VP_INDEX (e.g., always 0) for all
// vCPUs. This breaks any enlightenment that identifies VPs by their index
// (e.g., STIMER delivery, IPI targeting, SynIC message delivery).
//
// Also checks that the indices span [0, N-1] where N = logical CPU count.
// ---------------------------------------------------------------------------

NTSTATUS HandleMultiVcpu(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_MULTIVCPU)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_MULTIVCPU* s = (VSMT_MULTIVCPU*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    ULONG cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpuCount > 64) cpuCount = 64;
    s->CpuCount = cpuCount;

    // Read VP_INDEX on each CPU using KeSetSystemGroupAffinityThread
    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {

        GROUP_AFFINITY ga = {}, old = {};
        ga.Group = 0;
        ga.Mask  = 1ull << cpu;

        KeSetSystemGroupAffinityThread(&ga, &old);
        __try {
            s->VpIndexPerCpu[cpu] = __readmsr(0x40000002u);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s->VpIndexPerCpu[cpu] = 0xFFFFFFFFFFFFFFFFull;
        }
        KeRevertToUserGroupAffinityThread(&old);

        KdPrint(("VsmTest: CPU %u -> VP_INDEX %llu\n", cpu, s->VpIndexPerCpu[cpu]));
    }

    // Verify uniqueness
    UINT64 maxIdx = 0;
    s->AllUnique = TRUE;
    for (ULONG i = 0; i < cpuCount; i++) {
        if (s->VpIndexPerCpu[i] == 0xFFFFFFFFFFFFFFFFull) {
            s->AllUnique = FALSE;
            continue;
        }
        if (s->VpIndexPerCpu[i] > maxIdx) maxIdx = s->VpIndexPerCpu[i];
        for (ULONG j = i + 1; j < cpuCount; j++) {
            if (s->VpIndexPerCpu[i] == s->VpIndexPerCpu[j]) {
                s->AllUnique = FALSE;
                KdPrint(("VsmTest: Duplicate VP_INDEX %llu on CPUs %u and %u\n",
                         s->VpIndexPerCpu[i], i, j));
            }
        }
    }

    s->MatchesCpuCount = (maxIdx == (UINT64)(cpuCount - 1));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_MULTIVCPU);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// HANDLER: VSMT_IOCTL_ASSIST_PAGE
//
// Maps and reads the VP assist page (MSR 0x40000073 bits[63:12] = GPA).
//
// VP assist page structure (HV_VP_ASSIST_PAGE in TLFS):
//   +0x000 UINT32 ApicAssist        -- bit 0 = EOI optimization active (no EOI required)
//   +0x004 UINT32 Reserved
//   +0x008 UINT32 NestedEnlightenments -- bit 0 = enlightened VMCS active
//   +0x010 UINT64 CurrentNestedVmcs -- GPA of current nested VMCS (nested virt)
//
// If ApicAssist bit 0 = 1: guest APIC EOI optimization is active.
//   The hypervisor reads this bit before intercepting EOI writes.
//   If KVM sets this but the bit is 0: APIC EOI path is unoptimized.
//
// NestedEnlightenments bit 0: indicates the guest is using enlightened VMCS.
//   Relevant for L2 guest management; should be 0 for non-nested guests.
// ---------------------------------------------------------------------------

NTSTATUS HandleAssistPage(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_ASSIST_PAGE)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_ASSIST_PAGE* s = (VSMT_ASSIST_PAGE*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    UINT64 assistMsr = SafeReadMsr(0x40000073u);
    if (assistMsr == 0 || assistMsr == 0xFFFFFFFFFFFFFFFFull) {
        KdPrint(("VsmTest: VP_ASSIST_PAGE MSR = 0x%llX (not active)\n", assistMsr));
        s->Status = STATUS_NOT_FOUND;
        *outInfo = sizeof(VSMT_ASSIST_PAGE);
        return STATUS_SUCCESS;
    }

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(assistMsr & ~0xFFFull);  // GPA from bits[63:12]
    s->AssistPagePa = pa.QuadPart;

    KdPrint(("VsmTest: VP_ASSIST_PAGE GPA=0x%llX\n", pa.QuadPart));

    PVOID mapped = MmMapIoSpace(pa, PAGE_SIZE, MmCached);
    if (!mapped) {
        s->Status = STATUS_INSUFFICIENT_RESOURCES;
        *outInfo = sizeof(VSMT_ASSIST_PAGE);
        return STATUS_SUCCESS;
    }

    {
        PUCHAR pg = (PUCHAR)mapped;  // declared before __try (C89)
        __try {
            s->ApicAssist        = *(UINT32*)(pg + 0x000);
            s->NestedEnlBit      = *(UINT32*)(pg + 0x008);
            s->CurrentNestedVmcs = *(UINT64*)(pg + 0x010);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            KdPrint(("VsmTest: Assist page read faulted\n"));
        }
    }

    MmUnmapIoSpace(mapped, PAGE_SIZE);

    KdPrint(("VsmTest: AssistPage ApicAssist=0x%X NestedEnl=0x%X NestedVmcs=0x%llX\n",
             s->ApicAssist, s->NestedEnlBit, s->CurrentNestedVmcs));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_ASSIST_PAGE);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Dispatch function -- call this from vsm_ktest.c VsmtDispatchIoctl switch
// ---------------------------------------------------------------------------

#define VSMT_IOCTL_LIVENESS_TEST  CTL_CODE(0x8000u, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_REF_TSC        CTL_CODE(0x8000u, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_PHYS_BYPASS    CTL_CODE(0x8000u, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_MBEC_EXEC      CTL_CODE(0x8000u, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_MULTIVCPU      CTL_CODE(0x8000u, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_ASSIST_PAGE    CTL_CODE(0x8000u, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS VsmtIsolationDispatch(ULONG code, PVOID buf, ULONG inLen, ULONG outLen,
                                PULONG_PTR outInfo)
{
    switch (code) {
    case VSMT_IOCTL_LIVENESS_TEST: return HandleLivenessTest(buf, outLen, outInfo);
    case VSMT_IOCTL_REF_TSC:       return HandleRefTsc(buf, outLen, outInfo);
    case VSMT_IOCTL_PHYS_BYPASS:   return HandlePhysBypass(buf, outLen, outInfo);
    case VSMT_IOCTL_MBEC_EXEC:     return HandleMbecExec(buf, outLen, outInfo);
    case VSMT_IOCTL_MULTIVCPU:     return HandleMultiVcpu(buf, outLen, outInfo);
    case VSMT_IOCTL_ASSIST_PAGE:   return HandleAssistPage(buf, outLen, outInfo);
    default: return STATUS_INVALID_DEVICE_REQUEST;
    }
}
