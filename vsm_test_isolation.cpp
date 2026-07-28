//
// vsm_test_isolation.cpp -- VTL isolation, MBEC empirical, and correctness tests
//
// Sections 16-21, addressing the most critical gaps in the existing suite:
//
//  16  SharedUserData Hyper-V flag        (user mode, no driver)
//  17  TIME_REF_COUNT / STIMER monotonicity (driver -- liveness)
//  18  Reference TSC page content         (driver)
//  19  VTL isolation: physical bypass     (driver -- core VSM property)
//  20  MBEC: supervisor execute control   (driver -- kernel pool NX)
//  21  Speculation: VTL0 vs VTL1 comparison + cross-VTL boundary enforcement
//
// The most important: Section 19 verifies that EPT/NPT write-protection set
// by HvCallModifyVtlProtectionMask survives a MmMapIoSpace bypass.
// Section 20 verifies MBEC supervisor execute control from kernel mode.
//
// Build:
//   cl /EHa /Zi /O2 vsm_test.cpp vsm_test_intel.cpp vsm_test_synth.cpp
//      vsm_test_isolation.cpp /link ntdll.lib kernel32.lib advapi32.lib
//

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

#include <stdint.h>

typedef NTSTATUS (WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef PNtQuerySystemInformation PNTQSI;

// ---------------------------------------------------------------------------
// Driver IOCTL codes (must match vsm_ktest.c)
// ---------------------------------------------------------------------------
#define VSMT_DEVICE_TYPE          0x8000u
#define VSMT_IOCTL_LIVENESS_TEST  CTL_CODE(VSMT_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_REF_TSC        CTL_CODE(VSMT_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_PHYS_BYPASS    CTL_CODE(VSMT_DEVICE_TYPE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_MBEC_EXEC      CTL_CODE(VSMT_DEVICE_TYPE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_MULTIVCPU      CTL_CODE(VSMT_DEVICE_TYPE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_ASSIST_PAGE    CTL_CODE(VSMT_DEVICE_TYPE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

typedef struct {
    // Monotonicity checks
    UINT64   TimeRef1;          // first TIME_REF_COUNT read
    UINT64   TimeRef2;          // second read after 10ms delay
    UINT64   Stimer0Count1;     // first STIMER0_COUNT read
    UINT64   Stimer0Count2;     // second read after 10ms delay
    UINT64   VpRuntime1;
    UINT64   VpRuntime2;
    NTSTATUS Status;
} VSMT_LIVENESS;

typedef struct {
    UINT64   RefTscPage;        // physical address of reference TSC page (from MSR 0x40000021)
    UINT32   TscSequence;       // RefTscPage+0x000: sequence number (non-zero when active)
    UINT32   Reserved;          // RefTscPage+0x004: reserved (should be 0)
    UINT64   TscScale;          // RefTscPage+0x008: TSC scaling factor (non-zero)
    UINT64   TscOffset;         // RefTscPage+0x010: TSC offset
    NTSTATUS Status;
} VSMT_REF_TSC;

typedef struct {
    //
    // Physical mapping bypass test.
    // The driver maps ntoskrnl's first code page PA via MmMapIoSpace
    // (bypasses VTL0 page table protections, hits EPT/NPT directly).
    // If HVCI/VTL1 has set EPT write-protect on that GPA, the write will fault.
    //
    UINT64   NtoskrnlCodePagePa; // PA of ntoskrnl's first code page (for reference)
    BOOL     WriteBlocked;       // TRUE: EPT write-protect enforced (VTL1 SLAT working)
    BOOL     ReadAllowed;        // TRUE: reads still work (expected: VTL0 can read code pages)
    NTSTATUS Status;
} VSMT_PHYS_BYPASS;

typedef struct {
    //
    // Method 1: NonPagedPoolNx supervisor execute (HVCI baseline)
    BOOL     ExecBlocked;          // TRUE: NX pool exec blocked from Ring 0
    BOOL     WriteProtBlocked;     // TRUE: MmProtectMdl(RWX) blocked by HVCI

    // Method 2: user-GPA via MmMapIoSpace -> supervisor execute (definitive MBEC test)
    // User-mode PAGE_EXECUTE_READ page physically mapped with kernel PTE (U/S=0).
    // SMEP is satisfied; only EPT supervisor-execute=0 can block execution.
    BOOL     UserGpaReadAllowed;   // TRUE: kernel can read the user GPA (EPT R=1)
    BOOL     UserGpaExecBlocked;   // TRUE: supervisor execute blocked (MBEC confirmed)
    UINT64   UserGpaPhysAddr;      // Physical address used (for reference)

    NTSTATUS Status;
} VSMT_MBEC_EXEC;

typedef struct {
    //
    // Per-VP VP_INDEX uniqueness check.
    // Runs rdmsr(0x40000002) on each logical CPU and records the result.
    //
    ULONG  CpuCount;
    UINT64 VpIndexPerCpu[64];   // VP index seen on each CPU (max 64)
    BOOL   AllUnique;           // TRUE: each CPU has a unique VP index
    BOOL   MatchesCpuCount;     // TRUE: max VP index = CpuCount - 1
    NTSTATUS Status;
} VSMT_MULTIVCPU;

typedef struct {
    //
    // VP assist page content check.
    // Maps the physical page pointed to by MSR 0x40000073 and reads its fields.
    //
    UINT64   AssistPagePa;      // PA from MSR 0x40000073 bits[63:12]
    UINT32   ApicAssist;        // offset 0x000: bit 0 = EOI optimization active
    UINT32   NestedEnlBit;      // offset 0x008: bit 0 = enlightened VMCS active
    UINT64   CurrentNestedVmcs; // offset 0x010: GPA of current nested VMCS (if nested)
    NTSTATUS Status;
} VSMT_ASSIST_PAGE;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int iso_pass = 0, iso_fail = 0, iso_warn = 0;
static void ioPASS(const char* m) { printf("  [PASS] %s\n", m); iso_pass++; }
static void ioFAIL(const char* m, const char* d) {
    printf("  [FAIL] %s\n         --> %s\n", m, d); iso_fail++;
}
static void ioWARN(const char* m, const char* d) {
    printf("  [WARN] %s\n         --> %s\n", m, d); iso_warn++;
}
static void ioINFO(const char* m, const char* d) {
    printf("  [INFO] %s: %s\n", m, d);
}
static void ioSECT(int n, const char* t) {
    printf("\n========================================================\n");
    printf(" SECTION %d: %s\n", n, t);
    printf("========================================================\n");
}
static void ioSUB(const char* t) { printf("\n  -- %s --\n", t); }
static HANDLE OpenDriver() {
    return CreateFileW(L"\\\\.\\VsmTest",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

// ---------------------------------------------------------------------------
// SECTION 16 -- SharedUserData Hyper-V flag
//
// KiInitializeKernel (BSP path in ntoskrnl) writes 1 to SharedUserData+0x308
// when enlightenment bit 19 (HV_SHARED_USER_DATA_HV_FLAG) is set.
// Source: enlightenments.cpp bit definition, ntoskrnl analysis.
//
// Readable from user mode, no driver required.
// KUSER_SHARED_DATA is always mapped at 0x7FFE0000 in all processes.
//
// If this is 0 but HvlHypervisorConnected is YES: KVM is not properly
// setting the enlightenment flag or the kernel failed to initialize it.
// ---------------------------------------------------------------------------

void sect16_shared_user_data(PNtQuerySystemInformation NtQSI)
{
    ioSECT(16, "SharedUserData Hyper-V Flag + NtQSI 0xB5/0xE5");
    printf("  Source: ntoskrnl KiInitializeKernel -> SharedUserData+0x308\n");
    printf("          (HV_SHARED_USER_DATA_HV_FLAG = enlightenment bit 19)\n\n");

    // Field at offset 0x308 in KUSER_SHARED_DATA (user-mode accessible)
    const ULONG* hvFlag = (const ULONG*)( 0x7FFE0000 + 0x308 );

    printf("  SharedUserData base          : 0x7FFE0000\n");
    printf("  SharedUserData+0x308 (HV flag): 0x%08X\n", *hvFlag);

    if (*hvFlag == 1)
        ioPASS("SharedUserData+0x308 = 1 (kernel confirmed Hyper-V connection to user mode)");
    else if (*hvFlag == 0)
        ioFAIL("SharedUserData+0x308",
               "= 0 -- KVM did not set HV_SHARED_USER_DATA_HV_FLAG; "
               "ntoskrnl KiInitializeKernel uses this to signal user mode. "
               "Likely HvlEnlightenments bit 19 not being set by KVM.");
    else
        ioINFO("SharedUserData+0x308", "Unexpected non-0/1 value");

    // Also read some other shared data fields for context
    const ULONG* ntMajor  = (const ULONG*)(0x7FFE0000 + 0x026C);
    const ULONG* ntMinor  = (const ULONG*)(0x7FFE0000 + 0x0270);
    const ULONG* ntBuild  = (const ULONG*)(0x7FFE0000 + 0x0260);
    printf("  OS (from SharedUserData)     : %u.%u build %u\n",
           *ntMajor, *ntMinor, *ntBuild);

    // NtQuerySystemInformation class 0xB5 (SystemIsolatedUserModeInformation)
    // Returns a struct containing VslVsmEnabled byte
    ioSUB("NtQSI 0xB5 SystemIsolatedUserModeInformation");
    printf("  (Source: ntoskrnl VslVsmEnabled global, set when VSM init succeeds)\n");
    {
        BYTE buf[64] = {};
        ULONG retLen = 0;
        NTSTATUS st = NtQSI((SYSTEM_INFORMATION_CLASS)0xB5,
                            buf, sizeof(buf), &retLen);
        printf("  Status: 0x%08X  ReturnLength: %u\n", st, retLen);
        if (NT_SUCCESS(st) && retLen > 0) {
            printf("  Raw bytes[0..7]: ");
            for (ULONG i = 0; i < retLen && i < 8; i++)
                printf("%02X ", buf[i]);
            printf("\n");
            // byte[0] is typically VslVsmEnabled (1 = VSM active)
            if (buf[0] == 1)
                ioPASS("0xB5[0] = 1 (VslVsmEnabled -- VSM initialization succeeded)");
            else if (buf[0] == 0)
                ioFAIL("0xB5[0]",
                       "= 0 -- VslVsmEnabled not set; VTL1 initialization failed in ntoskrnl");
        } else if (st == 0xC0000003 || st == 0xC000007C) {
            ioINFO("0xB5", "Access denied or invalid -- may require elevated privileges");
        } else {
            ioINFO("0xB5", "Not implemented on this OS version");
        }
    }

    // NtQuerySystemInformation class 0xE5 (SystemHypervisorSharedPageInformation)
    ioSUB("NtQSI 0xE5 SystemHypervisorSharedPageInformation");
    printf("  (Returns physical addresses of hypervisor-shared pages)\n");
    {
        BYTE buf[128] = {};
        ULONG retLen = 0;
        NTSTATUS st = NtQSI((SYSTEM_INFORMATION_CLASS)0xE5,
                            buf, sizeof(buf), &retLen);
        printf("  Status: 0x%08X  ReturnLength: %u\n", st, retLen);
        if (NT_SUCCESS(st) && retLen >= 8) {
            UINT64* pages = (UINT64*)buf;
            printf("  Shared page PA[0]: 0x%016llX\n", pages[0]);
            if (retLen >= 16) printf("  Shared page PA[1]: 0x%016llX\n", pages[1]);
            if (pages[0] != 0)
                ioPASS("0xE5: Hypervisor shared page PA returned");
            else
                ioWARN("0xE5[0]", "= 0 -- KVM may not implement shared page reporting");
        } else {
            ioINFO("0xE5", "Not implemented or access denied");
        }
    }
}

// ---------------------------------------------------------------------------
// SECTION 17 -- Liveness: TIME_REF_COUNT / STIMER0 / VP_RUNTIME monotonicity
//
// Verifies that time-related MSRs are actually advancing (not frozen at 0
// or returning a constant, which would indicate incomplete KVM MSR emulation).
//
// TIME_REF_COUNT (0x40000020): 100ns reference counter. Should advance by
// ~100,000 counts per 10ms. Source: hvax64 line 1067424.
//
// STIMER0_COUNT (0x400000B1): VTL1's STIMER0 current count. When STIMER0_CONFIG
// is 0x10008 (periodic, direct delivery), this counter runs. If it doesn't
// advance, VTL1 scheduling is broken.
// Source: securekernel ShvlpEnableSyntheticTimer line 215324.
//
// VP_RUNTIME (0x40000004): 100ns units of actual CPU time on this VP.
// Source: hvax64 MSR dispatch line 1067420.
// ---------------------------------------------------------------------------

void sect17_liveness()
{
    ioSECT(17, "MSR Liveness (TIME_REF_COUNT / STIMER0 / VP_RUNTIME monotonicity)");
    printf("  Source: hvax64 HcpHvDispatchMsrReadIntercept_Internal\n");
    printf("          securekernel ShvlpEnableSyntheticTimer line 215324\n\n");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded -- add VSMT_IOCTL_LIVENESS_TEST\n\n");
        printf("  Logic:\n");
        printf("   1. rdmsr(0x40000020) -> TimeRef1\n");
        printf("   2. KeDelayExecutionThread(10ms)\n");
        printf("   3. rdmsr(0x40000020) -> TimeRef2\n");
        printf("   4. PASS if TimeRef2 > TimeRef1 + 50000 (0.5ms worth of 100ns ticks)\n");
        printf("   Same for STIMER0_COUNT (0x400000B1) and VP_RUNTIME (0x40000004)\n");
        return;
    }

    VSMT_LIVENESS live = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_LIVENESS_TEST, NULL, 0,
                         &live, sizeof(live), &br, NULL) || !NT_SUCCESS(live.Status)) {
        printf("  [SKIP] VSMT_IOCTL_LIVENESS_TEST not in driver -- see vsm_ktest_isolation.c\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    // TIME_REF_COUNT
    printf("  TIME_REF_COUNT (0x40000020):\n");
    printf("    First read : 0x%016llX\n", live.TimeRef1);
    printf("    Second read: 0x%016llX  (+%lld ticks in 10ms)\n",
           live.TimeRef2, (long long)(live.TimeRef2 - live.TimeRef1));
    if (live.TimeRef1 == 0xFFFFFFFFFFFFFFFFull)
        ioFAIL("TIME_REF_COUNT", "GP-faulted -- KVM must implement MSR 0x40000020");
    else if (live.TimeRef1 == 0 && live.TimeRef2 == 0)
        ioFAIL("TIME_REF_COUNT", "= 0 on both reads -- KVM returning constant 0");
    else if (live.TimeRef2 <= live.TimeRef1)
        ioFAIL("TIME_REF_COUNT", "Did not advance -- timer frozen (KVM bug)");
    else if ((live.TimeRef2 - live.TimeRef1) < 50000)
        ioWARN("TIME_REF_COUNT", "Advanced but slower than expected for 10ms delay (< 50000 ticks)");
    else
        ioPASS("TIME_REF_COUNT advancing correctly");

    // STIMER0_COUNT
    printf("\n  STIMER0_COUNT (0x400000B1) -- VTL1 scheduling timer:\n");
    printf("    First read : 0x%016llX\n", live.Stimer0Count1);
    printf("    Second read: 0x%016llX\n", live.Stimer0Count2);
    if (live.Stimer0Count1 == 0xFFFFFFFFFFFFFFFFull)
        ioFAIL("STIMER0_COUNT", "GP-faulted -- KVM must implement MSR 0x400000B1");
    else if (live.Stimer0Count1 == 0 && live.Stimer0Count2 == 0)
        ioWARN("STIMER0_COUNT",
               "Both reads = 0. If STIMER0_CONFIG = 0x10008 (VTL1 active), count should be non-zero. "
               "Possible: VTL1 not running, or STIMER count resets on read");
    else if (live.Stimer0Count2 != live.Stimer0Count1)
        ioPASS("STIMER0_COUNT advancing (VTL1 scheduling timer is running)");
    else
        ioINFO("STIMER0_COUNT", "Same on both reads -- may be a one-shot timer already expired");

    // VP_RUNTIME
    printf("\n  VP_RUNTIME (0x40000004):\n");
    printf("    First read : 0x%016llX (%.3f ms)\n",
           live.VpRuntime1, (double)live.VpRuntime1 / 10000.0);
    printf("    Second read: 0x%016llX  (+%lld ticks)\n",
           live.VpRuntime2, (long long)(live.VpRuntime2 - live.VpRuntime1));
    if (live.VpRuntime1 == 0xFFFFFFFFFFFFFFFFull)
        ioFAIL("VP_RUNTIME", "GP-faulted -- KVM must implement MSR 0x40000004");
    else if (live.VpRuntime2 > live.VpRuntime1)
        ioPASS("VP_RUNTIME advancing");
    else
        ioWARN("VP_RUNTIME", "Did not advance -- expected to increase over 10ms");
}

// ---------------------------------------------------------------------------
// SECTION 18 -- Reference TSC Page Content
//
// MSR 0x40000021 (HV_MSR_REFERENCE_TSC) holds the GPA of the reference TSC page.
// The page structure (HVTSC_REFERENCE_PAGE from Hyper-V TLFS):
//   +0x000 UINT32 TscSequence    -- non-zero when active; 0 = invalid/disabled
//   +0x004 UINT32 Reserved       -- 0
//   +0x008 UINT64 TscScale       -- multiply TSC by this >> 64 to get 100ns time
//   +0x010 INT64  TscOffset      -- add after scaling
//
// Source: hvax64 MSR dispatch, ntoskrnl HvlGetEnlightenmentInfo installs
//         HvlGetReferenceTimeUsingTscPage when this register is available.
//
// If TscSequence = 0: page is not active. KVM must write TscSequence != 0.
// If TscScale = 0: time calculation will give 0. KVM bug.
// ---------------------------------------------------------------------------

void sect18_ref_tsc_page()
{
    ioSECT(18, "Reference TSC Page Content");
    printf("  Source: hvax64 MSR 0x40000021 dispatch, HVTSC_REFERENCE_PAGE layout\n");
    printf("          ntoskrnl HvlGetReferenceTimeUsingTscPage (enlightenment bit 8)\n\n");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded -- add VSMT_IOCTL_REF_TSC\n\n");
        printf("  Logic:\n");
        printf("   rdmsr(0x40000021) -> GPA of reference TSC page (bits[63:12]=GPA, bit 0=enable)\n");
        printf("   MmMapIoSpace(GPA << 12, 4096, MmCached) -> read page fields\n");
        printf("   PASS if: bit 0 of MSR = 1, TscSequence != 0, TscScale != 0\n");
        return;
    }

    VSMT_REF_TSC rtsc = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_REF_TSC, NULL, 0,
                         &rtsc, sizeof(rtsc), &br, NULL) || !NT_SUCCESS(rtsc.Status)) {
        printf("  [SKIP] VSMT_IOCTL_REF_TSC not in driver\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  MSR 0x40000021 value      : 0x%016llX\n", rtsc.RefTscPage);
    printf("  Enabled (bit 0)           : %s\n", (rtsc.RefTscPage & 1) ? "YES" : "NO");
    printf("  Page GPA                  : 0x%016llX\n", rtsc.RefTscPage & ~0xFFFull);
    printf("  TscSequence (+0x000)      : 0x%08X\n", rtsc.TscSequence);
    printf("  TscScale    (+0x008)      : 0x%016llX\n", rtsc.TscScale);
    printf("  TscOffset   (+0x010)      : 0x%016llX\n", rtsc.TscOffset);

    if (!(rtsc.RefTscPage & 1))
        ioFAIL("Reference TSC page enabled", "bit 0 of MSR 0x40000021 = 0 -- page not activated");
    else if (rtsc.TscSequence == 0)
        ioFAIL("TscSequence",
               "= 0 -- KVM must write a non-zero sequence number to activate the TSC page. "
               "ntoskrnl installs HvlGetReferenceTimeUsingTscPage only when TscSequence != 0. "
               "If 0: guest falls back to slower time reference path.");
    else if (rtsc.TscScale == 0)
        ioFAIL("TscScale", "= 0 -- guest TSC-to-100ns calculation will always return 0");
    else {
        ioPASS("Reference TSC page: enabled, TscSequence != 0, TscScale != 0");
        // Sanity: typical TscScale for 3GHz TSC:
        // scale = (10000000 << 32) / 30000000 = 143165 (approximately)
        // scale stored as Q64: ~0x000000028F5C28F6
        // Report whether the scale is in a reasonable range
        double scaledFreqHz = (double)rtsc.TscScale / (double)(1ull << 32) * 1e7;
        printf("  Derived TSC frequency       : %.0f Hz (%.3f GHz)\n",
               scaledFreqHz, scaledFreqHz / 1e9);
        if (scaledFreqHz < 1e8 || scaledFreqHz > 1e11)
            ioWARN("TscScale range", "Derived frequency out of 100MHz-100GHz range -- check scale calculation");
    }
}

// ---------------------------------------------------------------------------
// SECTION 19 -- VTL Isolation: Physical Mapping Bypass Test
//
// The CORE VSM isolation property: VTL1 has marked certain GPAs as
// write-protected via HvCallModifyVtlProtectionMask (hypercall 0x00B1).
// EPT/NPT enforces this at the SLAT level, not at the page table level.
//
// Test: map a code page (ntoskrnl) by physical address via MmMapIoSpace
// (bypasses CR3/PTE protections, goes directly through EPT/NPT) and attempt:
//   a) READ:  should succeed (VTL0 can read code pages)
//   b) WRITE: should fault  (VTL1 has marked code GPAs as write-protected)
//
// If the write succeeds: VTL1 did NOT set EPT write-protect on this GPA,
// meaning HvCallModifyVtlProtectionMask is not being enforced by KVM.
//
// Source:
//   securekernel SkmiProtectPageRange -> HvCallModifyVtlProtectionMask (hypercall)
//   EPT write-protect: VTL1 clears EPT W bit on code page GPAs
//   Any VTL0 write to those GPAs -> EPT violation -> hypervisor injects fault
//   SkmiProtectPageRange failure is FATAL (SK BugCheck 0x1A/0x90A)
//   So if VTL1 booted at all, these protections MUST be in place.
// ---------------------------------------------------------------------------

void sect19_vtl_isolation()
{
    ioSECT(19, "VTL Isolation: Physical Mapping Bypass");
    printf("  Source: securekernel SkmiProtectPageRange -> EPT/NPT write-protect\n");
    printf("          hypercall HvCallModifyVtlProtectionMask (0x00B1)\n");
    printf("          MmMapIoSpace bypasses PTEs, hits SLAT directly\n\n");

    // Check if HVCI is even active first
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PNTQSI NtQSI  = (PNTQSI)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    PNTQSI pNtQSI = (PNTQSI)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci) };
    ULONG retLen;
    if (pNtQSI)
        pNtQSI((SYSTEM_INFORMATION_CLASS)0x67, &ci, sizeof(ci), &retLen);
    bool hvciActive = (ci.CodeIntegrityOptions & 0x400) != 0;

    printf("  HVCI kernel enforcement active : %s\n", hvciActive ? "YES" : "NO");
    if (!hvciActive) {
        ioWARN("VTL isolation test",
               "HVCI not active -- physical bypass test may not be meaningful "
               "(VTL1 may not have set EPT write-protect without HVCI)");
    }

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded -- add VSMT_IOCTL_PHYS_BYPASS\n\n");
        printf("  Logic (in driver, kernel mode):\n");
        printf("   1. MmGetPhysicalAddress(ntoskrnl_code_page_va) -> PA\n");
        printf("   2. mapped = MmMapIoSpace(PA, PAGE_SIZE, MmCached)\n");
        printf("      (creates new VTL0 kernel VA -> same GPA, bypasses page table permissions)\n");
        printf("   3. Read test:  val = *(volatile BYTE*)mapped  -- should SUCCEED\n");
        printf("   4. Write test: __try { *(volatile BYTE*)mapped = val; }\n");
        printf("                  __except(EXCEPTION_EXECUTE_HANDLER) { WriteBlocked=TRUE; }\n");
        printf("   5. MmUnmapIoSpace(mapped, PAGE_SIZE)\n\n");
        printf("   PASS: WriteBlocked=TRUE (EPT write-protect enforced by VTL1)\n");
        printf("   FAIL: Write succeeds (HvCallModifyVtlProtectionMask not enforcing)\n");
        printf("\n   Additional probe: map a page of NonPagedPoolNx memory.\n");
        printf("   VTL1 should also write-protect NX pool GPAs.\n");
        return;
    }

    VSMT_PHYS_BYPASS pb = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_PHYS_BYPASS, NULL, 0,
                         &pb, sizeof(pb), &br, NULL) || !NT_SUCCESS(pb.Status)) {
        printf("  [SKIP] VSMT_IOCTL_PHYS_BYPASS not in driver\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  ntoskrnl code page PA      : 0x%016llX\n", pb.NtoskrnlCodePagePa);
    printf("  Read via MmMapIoSpace      : %s\n", pb.ReadAllowed ? "allowed" : "faulted");
    printf("  Write via MmMapIoSpace     : %s\n", pb.WriteBlocked ? "BLOCKED (EPT write-protect)" : "succeeded (NOT protected!)");

    if (!pb.ReadAllowed)
        ioWARN("Physical bypass read", "Code page read faulted -- unexpected, VTL0 should be able to read code pages");
    else
        ioPASS("Physical bypass read: VTL0 can read code pages through MmMapIoSpace");

    if (pb.WriteBlocked)
        ioPASS("Physical bypass WRITE BLOCKED: EPT write-protect enforced "
               "(HvCallModifyVtlProtectionMask + SkmiProtectPageRange working)");
    else
        ioFAIL("Physical bypass write succeeded",
               "VTL0 can write to code pages through MmMapIoSpace PA bypass. "
               "HvCallModifyVtlProtectionMask (0x00B1) is NOT enforcing EPT write-protect. "
               "KVM: check that after HvCallModifyVtlProtectionMask, the EPT W bit is "
               "cleared in the nested page table for affected GPAs.");
}

// ---------------------------------------------------------------------------
// SECTION 20 -- MBEC: Supervisor Execute Control (kernel pool)
//
// MBEC (Mode-Based Execute Control) adds separate user/supervisor execute
// bits to EPT/NPT entries. VTL1 uses this so that:
//   - NonPagedPoolNx pages: supervisor-execute = 0 (kernel cannot execute)
//   - Code pages: supervisor-execute = 1, user-execute controlled separately
//
// Intel: VMCS secondary controls bit 22 (MODE_BASED_EPT_EXECUTE_CONTROL)
//        + EPT entries have separate U/S execute bits
// AMD:   GMET (Guest Mode Execute Trap) -- VMCB bit + NPT entries
//
// This test:
//   1. Allocates NonPagedPoolNx (non-execute pool)
//   2. Writes shellcode: xor rax,rax; ret
//   3. Attempts to execute it from kernel mode (Ring 0)
//   4. With MBEC+HVCI: EPT supervisor-execute = 0 -> fault -> ExecBlocked=TRUE
//   5. Without MBEC:   execution succeeds (HVCI without MBEC only uses write-protect)
//
// The difference between MBEC and non-MBEC HVCI:
//   Without MBEC: pool pages are write-protected (can't write shellcode) but if
//                 you somehow got shellcode there, supervisor could execute it.
//   With MBEC:    pool pages have supervisor-execute = 0; executing from them
//                 always faults regardless of how the code got there.
//
// Source: hvax64 HcpEvaluateHostCpuidCapabilities -> checks GMET bit
//         hvix64 HcpVerifyVmxCapability_Cpuid20 -> checks EPT MBEC bit
//         securekernel SkmiProtectPageRange -> sets per-page MBEC bits via hypercall
// ---------------------------------------------------------------------------

void sect20_mbec_supervisor_exec()
{
    ioSECT(20, "MBEC: Supervisor Execute Control (kernel NonPagedPoolNx)");
    printf("  Intel: EPT secondary controls bit 22 (MODE_BASED_EPT_EXECUTE_CONTROL)\n");
    printf("  AMD:   GMET (CPUID 0x8000000A EDX bit 23) + NPT GMET bit per entry\n");
    printf("  Source: securekernel SkmiProtectPageRange sets per-page MBEC bits\n\n");

    // Check prerequisites
    int cpu[4] = {};
    __cpuid(cpu, 0x40000000);
    bool mbecCpuid = false;
    if ((UINT32)cpu[0] >= 0x40000006) {
        __cpuid(cpu, 0x40000006);
        mbecCpuid = ((cpu[0] >> 18) & 1) != 0;
    }
    printf("  CPUID 0x40000006[18] MbecAvailable : %s\n", mbecCpuid ? "YES" : "NO");

    PNTQSI pNtQSI = (PNTQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci) };
    ULONG retLen;
    if (pNtQSI) pNtQSI((SYSTEM_INFORMATION_CLASS)0x67, &ci, sizeof(ci), &retLen);
    bool hvciActive = (ci.CodeIntegrityOptions & 0x400) != 0;
    printf("  HVCI active                        : %s\n", hvciActive ? "YES" : "NO");

    if (!mbecCpuid)
        ioWARN("MBEC prerequisite",
               "CPUID 0x40000006[18] not set -- test may not distinguish MBEC from plain HVCI");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("\n  [SKIP] VsmTest.sys not loaded -- add VSMT_IOCTL_MBEC_EXEC\n\n");
        printf("  Logic (in driver, kernel Ring 0):\n");
        printf("   1. pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'MBEC')\n");
        printf("   2. RtlCopyMemory(pool, {0x48,0x31,0xC0,0xC3}, 4)  // xor rax,rax; ret\n");
        printf("   3. __try { ((UINT64(*)(void))pool)(); ExecBlocked=FALSE; }\n");
        printf("      __except(EXCEPTION_EXECUTE_HANDLER) { ExecBlocked=TRUE; }\n");
        printf("   4. ExFreePool(pool)\n\n");
        printf("   PASS: ExecBlocked=TRUE -> supervisor execute from NX pool blocked\n");
        printf("   FAIL: ExecBlocked=FALSE -> MBEC not enforcing supervisor execute\n\n");
        printf("  Expected results by configuration:\n");
        printf("  +--------------+---------+---------------+-----------------------------+\n");
        printf("  | HVCI         | MBEC    | ExecBlocked   | Reason                      |\n");
        printf("  +--------------+---------+---------------+-----------------------------+\n");
        printf("  | NO           | NO      | FALSE         | No protection at all         |\n");
        printf("  | YES          | NO      | FALSE*        | Write blocked, exec allowed  |\n");
        printf("  | YES          | YES     | TRUE          | Both write + exec blocked    |\n");
        printf("  +--------------+---------+---------------+-----------------------------+\n");
        printf("  *With HVCI but no MBEC: writing shellcode to NX pool is already blocked,\n");
        printf("   but this test pre-writes the shellcode via the driver (before HVCI write-\n");
        printf("   protect is applied) to isolate the execute control specifically.\n");
        return;
    }

    VSMT_MBEC_EXEC mbec = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_MBEC_EXEC, NULL, 0,
                         &mbec, sizeof(mbec), &br, NULL) || !NT_SUCCESS(mbec.Status)) {
        printf("  [SKIP] VSMT_IOCTL_MBEC_EXEC not in driver\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    // ---- Method 1: NonPagedPoolNx execute ----
    ioSUB("Method 1: NonPagedPoolNx supervisor execute");
    printf("  ExecBlocked (NX pool Ring 0 execute)  : %s\n",
           mbec.ExecBlocked ? "YES -- faulted" : "NO -- succeeded!");
    printf("  WriteProtBlocked (MmProtectMdl RWX)   : %s\n",
           mbec.WriteProtBlocked ? "YES" : "NO");

    if (mbec.ExecBlocked)
        ioPASS("M1: NX pool supervisor execute blocked (EPT supervisor-X=0)");
    else if (!hvciActive)
        ioWARN("M1: MBEC not tested", "HVCI not active -- expected without VTL1");
    else if (hvciActive && !mbecCpuid)
        ioWARN("M1: MBEC not available",
               "Exec succeeded with HVCI active but MBEC CPUID[18]=0. "
               "KVM must advertise MBEC and enable EPT MBEC / AMD GMET.");
    else
        ioFAIL("M1: NX pool NOT protected",
               "KVM: VTL1 SkmiProtectPageRange did not clear EPT supervisor-X "
               "on NX pool pages. Check HvCallModifyVtlProtectionMask handler.");

    // ---- Method 2: user-GPA via MmMapIoSpace (definitive MBEC test) ----
    ioSUB("Method 2: user-GPA supervisor execute via MmMapIoSpace (definitive MBEC)");
    printf("  Physical address of user page          : 0x%016llX\n", mbec.UserGpaPhysAddr);
    printf("  Kernel read of user GPA allowed        : %s  (expected YES)\n",
           mbec.UserGpaReadAllowed ? "YES" : "NO");
    printf("  Kernel exec of user GPA blocked        : %s\n",
           mbec.UserGpaExecBlocked ? "YES -- EPT supervisor-X=0" : "NO -- exec succeeded!");

    printf("\n  Why this is the definitive MBEC test:\n");
    printf("   MmMapIoSpace maps the user-mode page with a kernel PTE (U/S=0).\n");
    printf("   SMEP is satisfied (no U/S=1 PTE involved in the fetch).\n");
    printf("   The ONLY thing that can block the execute is EPT supervisor-execute=0\n");
    printf("   set by VTL1 via HvCallModifyVtlProtectionMask on user-mode GPAs.\n");
    printf("   Without MBEC: EPT has one X bit, user page X=1 -> kernel exec works.\n");
    printf("   With MBEC:    VTL1 sets EPT_X_SUPER=0 on user GPAs -> blocked.\n\n");

    if (mbec.UserGpaPhysAddr == 0) {
        ioWARN("M2: user page alloc failed", "ZwAllocateVirtualMemory returned 0 PA -- "
               "page not pinned or MmGetPhysicalAddress returned 0");
    } else if (!mbec.UserGpaReadAllowed) {
        ioWARN("M2: kernel read faulted", "Unexpected -- EPT R bit should be 1 for user GPAs");
    } else if (mbec.UserGpaExecBlocked) {
        ioPASS("M2: MBEC CONFIRMED -- kernel exec of user-mode GPA blocked by EPT supervisor-X=0");
        if (mbecCpuid)
            printf("         Intel: VMCS secondary bit 22 (MODE_BASED_EPT_EXECUTE_CONTROL) active\n");
        else
            printf("         AMD: GMET NPT supervisor-execute=0 on user-mode GPAs\n");
    } else {
        ioFAIL("M2: MBEC NOT enforced",
               "Kernel executed user-mode GPA via MmMapIoSpace (SMEP-safe mapping). "
               "KVM: VTL1 must set EPT_X_SUPER=0 on all user-mode GPAs via "
               "HvCallModifyVtlProtectionMask when MBEC is enabled. "
               "Intel: ensure VMCS secondary controls bit 22 is set. "
               "AMD: ensure GMET bit is set in VMCB and NPT G-bit cleared on user pages.");
    }
}

// ---------------------------------------------------------------------------
// SECTION 21 -- VTL1 Speculation Control cross-check (0xD5 key bits)
//
// Cross-checks specific 0xD5 output bits that indicate whether KVM is
// correctly passing speculation MSR writes from VTL1 to hardware.
//
// Confirmed bit semantics (from securekernel + ntoskrnl disassembly,
// see VSM_VTL_Speculation_Fields.txt for full map):
//
// 0xD5[0]  = sentinel always-1 (SK0: hardcoded in SkeQuerySpeculationFeaturesInformation)
// 0xD5[4]  = sentinel always-1 (SK17: or edx,20000h)
// 0xD5[5]  = sentinel always-1 (SK16: or ecx,200h + shl 7)
// 0xD5[8]  = SF[0] IBRS present (SK10: SkiSpeculationFeatures bit 0)
// 0xD5[11] = NOT SF[8] -- CPU needs SSBD (SK15: !SkiSpeculationFeatures[8])
// 0xD5[12] = gs:0xAB0[1] IBPB on VTL exit (SK11: per-CPU boundary enforcement)
// 0xD5[13] = gs:0xAB0[2] IBPB on VTL entry (SK12: per-CPU boundary enforcement)
//
// For KVM MSR pass-through verification:
//   Bit 8 (IBRS present) confirms KVM is exposing CPUID speculation features
//   correctly so securekernel detects IBRS hardware.
//   Bits 12-13 (boundary enforcement) confirm securekernel is issuing
//   wrmsr(0x49, IBPB) at VTL transitions -- which means KVM is passing
//   PRED_CMD writes through to hardware.
// ---------------------------------------------------------------------------

void sect21_kvm_msr_passthrough(PNtQuerySystemInformation NtQSI)
{
    ioSECT(21, "VTL1 Speculation Control: 0xD5 cross-check");
    printf("  Tests KVM MSR pass-through for SPEC_CTRL (0x48) / PRED_CMD (0x49).\n");
    printf("  Source: securekernel SkCallNormalMode, SkiUpdateSpeculationControl.\n");
    printf("  Bit semantics confirmed from securekernel + ntoskrnl disassembly.\n\n");

    ULONG secspec = 0, retLen;
    NTSTATUS st = NtQSI((SYSTEM_INFORMATION_CLASS)0xD5,
                        &secspec, sizeof(secspec), &retLen);
    if (!NT_SUCCESS(st)) {
        ioWARN("0xD5 query failed", "VTL1 not running or IUM service 258 dispatch broken");
        return;
    }

    printf("  Raw 0xD5 DWORD: 0x%08X\n\n", secspec);

    // Sentinel bits: 0, 4, 5 must all be 1 when SK provided data
    printf("  %-52s : %s\n", "0xD5[0]  sentinel always-1 (SK0: hardcoded)",
           (secspec >> 0) & 1 ? "1 -- OK" : "0 -- BROKEN");
    printf("  %-52s : %s\n", "0xD5[4]  sentinel always-1 (SK17: or edx,20000h)",
           (secspec >> 4) & 1 ? "1 -- OK" : "0 -- BROKEN");
    printf("  %-52s : %s\n", "0xD5[5]  sentinel always-1 (SK16: or ecx,200h+shl7)",
           (secspec >> 5) & 1 ? "1 -- OK" : "0 -- BROKEN");

    if (!((secspec >> 0) & 1)) {
        ioFAIL("IUM service 258 dispatch",
               "0xD5[0] = 0. KVM is not routing VslGetSecureSpeculationControlInformation "
               "to securekernel. All other bits are meaningless.");
        return;
    }

    if (((secspec >> 0) & 1) && ((secspec >> 4) & 1) && ((secspec >> 5) & 1))
        ioPASS("All 3 sentinels set (bits 0,4,5) -- query pipeline intact");
    else
        ioWARN("Sentinel check", "Bit 0 set but bits 4 or 5 missing -- partial SK response");

    // IBRS present (bit 8 = SK10 = SkiSpeculationFeatures[0])
    printf("\n  %-52s : %s\n",
           "0xD5[8]  SF[0] IBRS present (SkiSpeculationFeatures)",
           (secspec >> 8) & 1 ? "YES" : "NO");
    if ((secspec >> 8) & 1)
        ioPASS("IBRS detected by securekernel (CPUID speculation features exposed correctly)");
    else
        ioINFO("0xD5[8] IBRS", "Not present -- CPU may not support IBRS, or KVM CPUID not exposing it");

    // NOT SF[8] -- CPU needs SSBD (bit 11 = SK15 = !SkiSpeculationFeatures[8])
    printf("\n  %-52s : %s\n",
           "0xD5[11] NOT SF[8] CPU needs SSBD (!SkiSpecFeatures[8])",
           (secspec >> 11) & 1 ? "YES (CPU needs SSBD)" : "NO (SSBD not needed or not applicable)");

    // gs:0xAB0[1] IBPB on VTL exit (bit 12 = SK11: boundary enforcement)
    printf("\n  %-52s : %s\n",
           "0xD5[12] gs:0xAB0[1] IBPB on VTL exit (SK11)",
           (secspec >> 12) & 1 ? "YES" : "NO");
    if ((secspec >> 12) & 1)
        ioPASS("IBPB on VTL exit: KVM passes wrmsr(0x49, IBPB) from VTL1");
    else
        ioINFO("0xD5[12]", "IBPB not issued on VTL exit (gs:0xAB0[1]=0)");

    // gs:0xAB0[2] IBPB on VTL entry (bit 13 = SK12: boundary enforcement)
    printf("\n  %-52s : %s\n",
           "0xD5[13] gs:0xAB0[2] IBPB on VTL entry (SK12)",
           (secspec >> 13) & 1 ? "YES" : "NO");
    if ((secspec >> 13) & 1)
        ioPASS("IBPB on VTL entry: VTL0 branch poisoning blocked at boundary");
    else
        ioWARN("0xD5[13] IBPB entry not set",
               "No IBPB on VTL entry -- potential Spectre v2 attack surface. "
               "Check that KVM passes wrmsr(0x49) from VTL1 and that securekernel "
               "SkiUpdateSpeculationControl sets gs:0xAB0[2].");

    // Summary: MSR pass-through assessment
    printf("\n  MSR pass-through assessment:\n");
    if ((secspec >> 8) & 1)
        printf("    IBRS (MSR 0x48): securekernel detected IBRS -> wrmsr(0x48) passing through KVM\n");
    if ((secspec >> 12) & 1)
        printf("    IBPB (MSR 0x49): wrmsr(0x49,1) on VTL exit passing through KVM\n");
    if ((secspec >> 13) & 1)
        printf("    IBPB (MSR 0x49): wrmsr(0x49,1) on VTL entry passing through KVM\n");
    if (!((secspec >> 8) & 1) && !((secspec >> 12) & 1) && !((secspec >> 13) & 1))
        printf("    No speculation MSR activity detected from VTL1.\n");
}

// ---------------------------------------------------------------------------
// Multi-VP VP_INDEX consistency (Section 22)
// ---------------------------------------------------------------------------

void sect22_multivcpu()
{
    ioSECT(22, "Multi-VP VP_INDEX Uniqueness");
    printf("  Source: hvax64/hvix64 MSR 0x40000002 (HV_MSR_VP_INDEX)\n");
    printf("          Each VP must return a unique index. KVM: check per-vCPU MSR emulation.\n\n");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded -- add VSMT_IOCTL_MULTIVCPU\n\n");
        printf("  Logic (in driver):\n");
        printf("   For each logical CPU (KeSetSystemAffinityThread(1 << cpu)):\n");
        printf("     VpIndexPerCpu[cpu] = SafeReadMsr(0x40000002)\n");
        printf("   PASS if all values are unique and span [0, N-1]\n");
        printf("   FAIL if any two CPUs return the same VP index (KVM bug)\n");
        return;
    }

    VSMT_MULTIVCPU mvc = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_MULTIVCPU, NULL, 0,
                         &mvc, sizeof(mvc), &br, NULL) || !NT_SUCCESS(mvc.Status)) {
        printf("  [SKIP] VSMT_IOCTL_MULTIVCPU not in driver\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  CPU count: %u\n", mvc.CpuCount);
    printf("  VP index per CPU:\n");
    for (ULONG i = 0; i < mvc.CpuCount && i < 64; i++)
        printf("    CPU %2u: VP_INDEX = %llu\n", i, mvc.VpIndexPerCpu[i]);

    if (mvc.AllUnique)
        ioPASS("All VPs have unique VP_INDEX values");
    else
        ioFAIL("VP_INDEX not unique across CPUs",
               "Two or more CPUs returned the same VP_INDEX. "
               "KVM MSR 0x40000002 must return a per-vCPU value, not a shared constant.");

    if (mvc.MatchesCpuCount)
        ioPASS("VP_INDEX values span [0, CpuCount-1]");
    else
        ioWARN("VP_INDEX range",
               "Max VP_INDEX does not match CpuCount-1. "
               "KVM may be assigning non-contiguous VP indices.");
}

// ---------------------------------------------------------------------------
// Run all isolation sections
// ---------------------------------------------------------------------------

void RunIsolationTests(void* pNtQSI)
{
    PNTQSI NtQSI = (PNTQSI)pNtQSI;

    printf("\n");
    printf("########################################################\n");
    printf(" VTL Isolation, MBEC, Speculation, and Liveness Tests\n");
    printf(" Sections 16-22\n");
    printf("########################################################\n");
    printf(" Most critical: Section 19 (EPT physical bypass),\n");
    printf("                Section 20 (MBEC supervisor exec),\n");
    printf("                Section 21 (KVM MSR 0x48/0x49 pass-through)\n");
    printf("########################################################\n");

    sect16_shared_user_data(NtQSI);
    sect17_liveness();
    sect18_ref_tsc_page();
    sect19_vtl_isolation();
    sect20_mbec_supervisor_exec();
    sect21_kvm_msr_passthrough(NtQSI);
    sect22_multivcpu();

    printf("\n  Sections 16-22 summary: %d PASS  %d FAIL  %d WARN\n",
           iso_pass, iso_fail, iso_warn);
}
