//
// vsm_test_kvmvsm.cpp -- KVM VSM implementation verification tests
//
// Sections 23-34: targeted tests for KVM's VSM/VTL implementation
// correctness covering latency, MSR banking, FPU isolation, TLB flush,
// CR4 intercepts, SynIC dispatch, and VP assist page fields.
//
// Build:
//   cl /EHa /Zi /O2 vsm_test.cpp vsm_test_intel.cpp vsm_test_synth.cpp
//      vsm_test_isolation.cpp vsm_test_kvmvsm.cpp
//      /link ntdll.lib kernel32.lib advapi32.lib tbs.lib
//

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <process.h>

#include <stdint.h>

typedef NTSTATUS (WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef PNtQuerySystemInformation PNTQSI;

// ---------------------------------------------------------------------------
// Driver IOCTL codes (must match vsm_ktest_kvmvsm.c)
// ---------------------------------------------------------------------------
#define VSMT_DEVICE_TYPE            0x8000u
#define VSMT_IOCTL_VTL_LATENCY     CTL_CODE(VSMT_DEVICE_TYPE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_MSR_ISOLATION   CTL_CODE(VSMT_DEVICE_TYPE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_SETVPREG        CTL_CODE(VSMT_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_GPA_GRANULARITY CTL_CODE(VSMT_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_XSAVE_ISOLATION CTL_CODE(VSMT_DEVICE_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_REENLIGHTEN     CTL_CODE(VSMT_DEVICE_TYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_CRASH_MSRS      CTL_CODE(VSMT_DEVICE_TYPE, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_CR4_INTERCEPT   CTL_CODE(VSMT_DEVICE_TYPE, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_SYNIC_SIGNAL    CTL_CODE(VSMT_DEVICE_TYPE, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_FLUSH           CTL_CODE(VSMT_DEVICE_TYPE, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_VTL_ENTRY_REASON CTL_CODE(VSMT_DEVICE_TYPE, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Structures (must match vsm_ktest_kvmvsm.c)
// ---------------------------------------------------------------------------

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
    BOOL     Sint0MatchesVtl1;
    BOOL     Sint1MatchesVtl1;
    BOOL     Stimer0MatchesVtl1;
    NTSTATUS Status;
} VSMT_MSR_ISOLATION;

typedef struct {
    UINT64   VtlConfigValue;
    UINT64   CodePageOffsets;
    UINT64   HvStatusRead;
    BOOL     SecureVtlConfigNonZero;
    BOOL     ConsistentReads;
    NTSTATUS Status;
} VSMT_SETVPREG;

typedef struct {
    BOOL     DataReadOk;
    BOOL     PoolReadOk;
    BOOL     DataExecBlocked;
    UINT64   TestPagePa;
    NTSTATUS Status;
} VSMT_GPA_GRANULARITY;

typedef struct {
    BOOL     XmmPreserved;
    INT32    CorruptedRegister;
    UINT64   Xmm0Before;
    UINT64   Xmm0After;
    NTSTATUS Status;
} VSMT_XSAVE_ISOLATION;

typedef struct {
    UINT64   ReenlightenCtrl;
    UINT64   TscEmulCtrl;
    UINT64   TscEmulStatus;
    BOOL     ReenlightenGpFault;
    BOOL     TscEmulCtrlGpFault;
    BOOL     TscEmulStatusGpFault;
    NTSTATUS Status;
} VSMT_REENLIGHTEN;

typedef struct {
    UINT64   CrashCtl;
    UINT64   CrashP0;
    UINT64   CrashP1;
    UINT64   CrashP2;
    UINT64   CrashP3;
    UINT64   CrashP4;
    BOOL     CrashCtlGpFaulted;
    BOOL     CrashDataGpFaulted;
    NTSTATUS Status;
} VSMT_CRASH_MSRS;

typedef struct {
    UINT64   OrigCr4;
    UINT64   PostWriteCr4;
    BOOL     SmepPreserved;
    BOOL     ExceptionRaised;
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int kvsm_pass = 0, kvsm_fail = 0, kvsm_warn = 0;

static void kvPASS(const char* m) { printf("  [PASS] %s\n", m); kvsm_pass++; }
static void kvFAIL(const char* m, const char* d) {
    printf("  [FAIL] %s\n         --> %s\n", m, d); kvsm_fail++;
}
static void kvWARN(const char* m, const char* d) {
    printf("  [WARN] %s\n         --> %s\n", m, d); kvsm_warn++;
}
static void kvINFO(const char* m, const char* d) {
    printf("  [INFO] %s: %s\n", m, d);
}
static void kvSECT(int n, const char* t) {
    printf("\n========================================================\n");
    printf(" SECTION %d: %s\n", n, t);
    printf("========================================================\n");
}
static void kvSUB(const char* t) { printf("\n  -- %s --\n", t); }
static HANDLE kvOpenDriver() {
    return CreateFileW(L"\\\\.\\VsmTest",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

// ---------------------------------------------------------------------------
// SECTION 23 -- VTL Switch Latency
//
// Two-pronged measurement:
//   A) User-mode: RDTSC around NtQuerySystemInformation(0xD5) which triggers
//      IUM service 258 (VTL0 -> VTL1 -> VTL0).
//   B) Kernel-mode: RDTSC around HvCallGetVpRegisters at DISPATCH_LEVEL.
//
// Reports min/median/max/avg cycle counts over 100 samples.
// Excessive latency (>100k cycles) indicates suboptimal VTL switch path.
// ---------------------------------------------------------------------------

#define VTL_LATENCY_SAMPLES 100

static void sect23_vtl_latency(PNTQSI NtQSI)
{
    kvSECT(23, "VTL Switch Latency");
    printf("  Measures round-trip VTL0->VTL1->VTL0 switch cost.\n\n");

    // Part A: user-mode RDTSC around 0xD5
    kvSUB("Part A: user-mode (NtQSI 0xD5 = IUM service 258)");
    {
        UINT64 samples[VTL_LATENCY_SAMPLES];
        int i, j;
        UINT64 totalCycles = 0, temp;

        for (i = 0; i < VTL_LATENCY_SAMPLES; i++) {
            ULONG secspec = 0, retLen = 0;
            _mm_lfence();
            UINT64 before = __rdtsc();
            NtQSI((SYSTEM_INFORMATION_CLASS)0xD5, &secspec, sizeof(secspec), &retLen);
            _mm_lfence();
            UINT64 after = __rdtsc();
            samples[i] = after - before;
        }

        // Sort for median
        for (i = 1; i < VTL_LATENCY_SAMPLES; i++) {
            temp = samples[i];
            j = i - 1;
            while (j >= 0 && samples[j] > temp) {
                samples[j + 1] = samples[j];
                j--;
            }
            samples[j + 1] = temp;
        }

        for (i = 0; i < VTL_LATENCY_SAMPLES; i++)
            totalCycles += samples[i];

        UINT64 uMin = samples[0];
        UINT64 uMax = samples[VTL_LATENCY_SAMPLES - 1];
        UINT64 uMed = samples[VTL_LATENCY_SAMPLES / 2];
        UINT64 uAvg = totalCycles / VTL_LATENCY_SAMPLES;

        printf("  User-mode (%d samples):\n", VTL_LATENCY_SAMPLES);
        printf("    Min:    %llu cycles\n", uMin);
        printf("    Median: %llu cycles\n", uMed);
        printf("    Max:    %llu cycles\n", uMax);
        printf("    Avg:    %llu cycles\n", uAvg);

        if (uMed == 0)
            kvWARN("VTL switch latency", "Median = 0 -- 0xD5 may not be triggering VTL switch");
        else if (uMed > 100000)
            kvWARN("VTL switch latency", "Median > 100k cycles -- suboptimal VTL switch path");
        else
            kvPASS("User-mode VTL switch latency measured successfully");
    }

    // Part B: kernel-mode via driver
    kvSUB("Part B: kernel-mode (HvCallGetVpRegisters at DISPATCH_LEVEL)");
    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_VTL_LATENCY lat = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_VTL_LATENCY, NULL, 0,
                         &lat, sizeof(lat), &br, NULL) || !NT_SUCCESS(lat.Status)) {
        printf("  [SKIP] IOCTL 0x80E not in driver (Status=0x%08X)\n", lat.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  Kernel-mode (%u samples at DISPATCH_LEVEL):\n", lat.SampleCount);
    printf("    Min:    %llu cycles\n", lat.MinCycles);
    printf("    Median: %llu cycles\n", lat.MedianCycles);
    printf("    Max:    %llu cycles\n", lat.MaxCycles);
    printf("    Avg:    %llu cycles\n", lat.AvgCycles);

    if (lat.MedianCycles == 0)
        kvWARN("Kernel VTL latency", "Median = 0 -- hypercall may not be triggering VTL switch");
    else if (lat.MedianCycles > 100000)
        kvWARN("Kernel VTL latency", "Median > 100k cycles -- check KVM VTL switch fast path");
    else
        kvPASS("Kernel-mode VTL switch latency measured successfully");
}

// ---------------------------------------------------------------------------
// SECTION 24 -- Per-VTL MSR Isolation
//
// VTL0 reads SynIC MSRs.  If it sees VTL1's values (which securekernel
// programmed during init), KVM's per-VTL MSR banking is broken.
//
// Source: securekernel ShvlpInitializeSynic programs:
//   SINT0 = 0x200F0, SINT1 = 0x20051, STIMER0_CONFIG = 0x10008
// ---------------------------------------------------------------------------

static void sect24_msr_isolation()
{
    kvSECT(24, "Per-VTL MSR Isolation (SynIC/STIMER banking)");
    printf("  Source: securekernel ShvlpInitializeSynic\n");
    printf("  VTL1 programs: SINT0=0x200F0, SINT1=0x20051, STIMER0=0x10008\n");
    printf("  VTL0 must NOT see these values (per-VTL MSR banking).\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_MSR_ISOLATION iso = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_MSR_ISOLATION, NULL, 0,
                         &iso, sizeof(iso), &br, NULL) || !NT_SUCCESS(iso.Status)) {
        printf("  [SKIP] IOCTL 0x80F failed (Status=0x%08X)\n", iso.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  VTL0 MSR reads:\n");
    printf("    SINT0  (0x40000090): 0x%016llX\n", iso.Vtl0Sint0);
    printf("    SINT1  (0x40000091): 0x%016llX\n", iso.Vtl0Sint1);
    printf("    STIMER0(0x400000B0): 0x%016llX\n", iso.Vtl0Stimer0Config);
    printf("    SCONTROL(0x40000080): 0x%016llX\n", iso.Vtl0Scontrol);
    printf("    SIMP   (0x40000082): 0x%016llX\n", iso.Vtl0Simp);
    printf("    SIEFP  (0x40000083): 0x%016llX\n", iso.Vtl0Siefp);
    printf("\n");

    if (iso.Sint0MatchesVtl1)
        kvFAIL("SINT0 leaks VTL1 value (0x200F0)",
               "KVM is not banking MSR 0x40000090 per VTL. VTL0 sees VTL1's SINT0.");
    else
        kvPASS("SINT0 isolated (VTL0 does not see VTL1's 0x200F0)");

    if (iso.Sint1MatchesVtl1)
        kvFAIL("SINT1 leaks VTL1 value (0x20051)",
               "KVM is not banking MSR 0x40000091 per VTL.");
    else
        kvPASS("SINT1 isolated (VTL0 does not see VTL1's 0x20051)");

    if (iso.Stimer0MatchesVtl1)
        kvFAIL("STIMER0_CONFIG leaks VTL1 value (0x10008)",
               "KVM is not banking MSR 0x400000B0 per VTL.");
    else
        kvPASS("STIMER0_CONFIG isolated (VTL0 does not see VTL1's 0x10008)");

    if (iso.Vtl0Sint0 == 0xFFFFFFFFFFFFFFFFull)
        kvWARN("SINT0 GP-faulted", "MSR 0x40000090 not implemented by KVM");
}

// ---------------------------------------------------------------------------
// SECTION 25 -- HvCallSetVpRegisters Round-Trip
//
// Reads VP registers that securekernel wrote via HvCallSetVpRegisters.
// Non-zero values confirm the write path worked.
//
// Source: securekernel ShvlpQueryVsmCapabilities (0xD0006),
//         ShvlpInitializeVsmCodeArea (0xD0002)
// ---------------------------------------------------------------------------

static void sect25_setvpreg()
{
    kvSECT(25, "HvCallSetVpRegisters Round-Trip Validation");
    printf("  Reads VP registers written by securekernel during VTL1 init.\n");
    printf("  Source: securekernel ShvlpQueryVsmCapabilities (0xD0006)\n");
    printf("          ShvlpInitializeVsmCodeArea (0xD0002)\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_SETVPREG vp = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_SETVPREG, NULL, 0,
                         &vp, sizeof(vp), &br, NULL) || !NT_SUCCESS(vp.Status)) {
        printf("  [SKIP] IOCTL 0x810 failed (Status=0x%08X)\n", vp.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  VsmVpSecureVtlConfig (0xD0006): 0x%016llX\n", vp.VtlConfigValue);
    printf("  VsmCodePageOffsets   (0xD0002): 0x%016llX\n", vp.CodePageOffsets);
    printf("  HvStatus from read            : 0x%016llX\n", vp.HvStatusRead);
    printf("  Consistent reads              : %s\n", vp.ConsistentReads ? "YES" : "NO");
    printf("\n");

    if (vp.HvStatusRead == 0xFFFFFFFFFFFFFFFFull)
        kvFAIL("HvCallGetVpRegisters failed",
               "Hypercall returned error status. KVM 0x50 handler broken.");
    else if (vp.SecureVtlConfigNonZero)
        kvPASS("VsmVpSecureVtlConfig non-zero (securekernel's SetVpRegisters worked)");
    else
        kvWARN("VsmVpSecureVtlConfig = 0",
               "Securekernel may not have written this register yet, or KVM 0x51 handler "
               "is not persisting the value.");

    if (vp.ConsistentReads)
        kvPASS("VsmCodePageOffsets reads are consistent");
    else
        kvFAIL("VsmCodePageOffsets inconsistent",
               "Two consecutive reads returned different values. KVM VP register store is racy.");
}

// ---------------------------------------------------------------------------
// SECTION 26 -- GPA Protection Granularity
//
// Tests EPT/NPT permission granularity beyond write-protect:
//   - Read via PA mapping (should succeed for VTL0-accessible pages)
//   - Execute from PA-mapped data page (blocked if MBEC/HVCI active)
//
// Extends Section 20 pattern to data pages instead of code pages.
// ---------------------------------------------------------------------------

static void sect26_gpa_granularity()
{
    kvSECT(26, "GPA Protection Granularity (Read + Execute via PA mapping)");
    printf("  Tests EPT/NPT permission bits beyond write-protect.\n");
    printf("  Allocates NonPagedPool page, maps by PA, tests read + exec.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_GPA_GRANULARITY gpa = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_GPA_GRANULARITY, NULL, 0,
                         &gpa, sizeof(gpa), &br, NULL) || !NT_SUCCESS(gpa.Status)) {
        printf("  [SKIP] IOCTL 0x811 failed (Status=0x%08X)\n", gpa.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  Test page PA          : 0x%016llX\n", gpa.TestPagePa);
    printf("  Read via PA mapping   : %s\n", gpa.DataReadOk ? "OK" : "FAILED");
    printf("  Read via pool VA      : %s\n", gpa.PoolReadOk ? "OK" : "FAILED");
    printf("  Exec from PA mapping  : %s\n",
           gpa.DataExecBlocked ? "BLOCKED (EPT X=0)" : "SUCCEEDED");
    printf("\n");

    if (gpa.DataReadOk)
        kvPASS("Data page read via PA mapping succeeded");
    else
        kvFAIL("Data page read via PA mapping failed",
               "Unexpected -- VTL0 should be able to read its own NonPagedPool pages.");

    if (gpa.DataExecBlocked)
        kvPASS("Exec from PA-mapped data page blocked (EPT supervisor-X=0)");
    else
        kvINFO("Exec from PA mapping succeeded",
               "Data page is executable via PA mapping -- normal without MBEC/HVCI on data pool.");
}

// ---------------------------------------------------------------------------
// SECTION 27 -- Concurrent VTL Switch Stress
//
// Spawns one thread per CPU, each calling NtQuerySystemInformation(0xD5)
// in a tight loop.  Tests race conditions in KVM's per-vCPU VTL switch path.
//
// Expected: every 0xD5 result has sentinel bits 0,4,5 set (indicating VTL1
// processed the request).  If any thread sees all-zero bits, the VTL switch
// failed under concurrency.
// ---------------------------------------------------------------------------

struct ConcurrentCtx {
    PNTQSI NtQSI;
    HANDLE goEvent;
    volatile LONG errCount;
    volatile LONG totalCalls;
};

static unsigned __stdcall vtlStressThread(void* arg)
{
    ConcurrentCtx* ctx = (ConcurrentCtx*)arg;
    WaitForSingleObject(ctx->goEvent, INFINITE);

    for (int i = 0; i < 100; i++) {
        ULONG secspec = 0, retLen = 0;
        NTSTATUS st = ctx->NtQSI((SYSTEM_INFORMATION_CLASS)0xD5,
                                  &secspec, sizeof(secspec), &retLen);
        InterlockedIncrement(&ctx->totalCalls);

        if (NT_SUCCESS(st)) {
            // Sentinel bits 0, 4, 5 must all be set
            if ((secspec & 0x31) != 0x31) {
                InterlockedIncrement(&ctx->errCount);
            }
        }
    }
    return 0;
}

static void sect27_concurrent_vtl(PNTQSI NtQSI)
{
    kvSECT(27, "Concurrent VTL Switch Stress (multi-VP race test)");
    printf("  Spawns one thread per CPU, each calling NtQSI(0xD5) x 100.\n");
    printf("  Tests KVM per-vCPU VTL switch path under concurrency.\n\n");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD nCPU = si.dwNumberOfProcessors;
    if (nCPU > 64) nCPU = 64;

    printf("  CPU count: %u\n", nCPU);

    ConcurrentCtx ctx = {};
    ctx.NtQSI = NtQSI;
    ctx.goEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.errCount = 0;
    ctx.totalCalls = 0;

    HANDLE threads[64] = {};
    for (DWORD i = 0; i < nCPU; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, vtlStressThread, &ctx, 0, NULL);
    }

    // Synchronized start
    SetEvent(ctx.goEvent);

    // Wait with 30-second timeout
    WaitForMultipleObjects(nCPU, threads, TRUE, 30000);

    for (DWORD i = 0; i < nCPU; i++)
        CloseHandle(threads[i]);
    CloseHandle(ctx.goEvent);

    printf("  Total calls: %ld\n", ctx.totalCalls);
    printf("  Errors (sentinel bits missing): %ld\n", ctx.errCount);

    if (ctx.totalCalls == 0)
        kvWARN("No VTL switch calls completed", "All threads timed out or 0xD5 failed");
    else if (ctx.errCount == 0)
        kvPASS("All concurrent VTL switches returned valid sentinel bits");
    else
        kvFAIL("Concurrent VTL switch corruption detected",
               "Some 0xD5 calls returned missing sentinel bits under concurrency. "
               "KVM VTL switch path has a race condition.");
}

// ---------------------------------------------------------------------------
// SECTION 28 -- FPU/XSAVE State Isolation
//
// Tests that XMM register state is preserved across VTL switches.
// The driver loads known patterns into XMM0-3 via FXRSTOR, triggers
// a VTL switch via hypercall, then saves and compares with FXSAVE.
//
// If XMM state is corrupted, the hypervisor is not properly saving/
// restoring FPU state during VTL transitions.
// ---------------------------------------------------------------------------

static void sect28_xsave_isolation()
{
    kvSECT(28, "FPU/XSAVE State Isolation Across VTL Switch");
    printf("  Uses FXSAVE/FXRSTOR to verify XMM0-3 preserved across VTL switch.\n");
    printf("  Source: hypervisor VTL switch save/restore path.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_XSAVE_ISOLATION xs = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_XSAVE_ISOLATION, NULL, 0,
                         &xs, sizeof(xs), &br, NULL) || !NT_SUCCESS(xs.Status)) {
        printf("  [SKIP] IOCTL 0x812 failed (Status=0x%08X)\n", xs.Status);
        if (xs.Status == (NTSTATUS)0xC000000D)
            printf("         KeSaveExtendedProcessorState failed -- SSE not available\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  XMM0 before: 0x%016llX\n", xs.Xmm0Before);
    printf("  XMM0 after : 0x%016llX\n", xs.Xmm0After);
    printf("  All XMM0-3 preserved: %s\n", xs.XmmPreserved ? "YES" : "NO");
    if (xs.CorruptedRegister >= 0)
        printf("  First corrupted register: XMM%d\n", xs.CorruptedRegister);
    printf("\n");

    if (xs.XmmPreserved)
        kvPASS("XMM0-3 preserved across VTL switch (FXSAVE/FXRSTOR confirmed)");
    else
        kvFAIL("XMM state corrupted across VTL switch",
               "KVM hypervisor is not properly saving/restoring FPU/SSE state "
               "during VTL transitions. This will cause random FP corruption in "
               "VTL0 userspace and kernel.");
}

// ---------------------------------------------------------------------------
// SECTION 29 -- Reenlightenment / TSC Emulation MSRs
//
// Tests MSRs critical for live migration of VSM guests:
//   0x40000106 -- HV_X64_MSR_REENLIGHTENMENT_CONTROL
//   0x40000107 -- HV_X64_MSR_TSC_EMULATION_CONTROL
//   0x40000108 -- HV_X64_MSR_TSC_EMULATION_STATUS
//
// If these GP-fault, KVM has not implemented them.  Without TSC emulation,
// live migration of a VSM guest will break guest timekeeping.
// ---------------------------------------------------------------------------

static void sect29_reenlighten()
{
    kvSECT(29, "Reenlightenment / TSC Emulation MSRs");
    printf("  Critical for live migration of VSM guests.\n");
    printf("  Source: hvax64 MSR dispatch for 0x40000106-0x40000108.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_REENLIGHTEN re = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_REENLIGHTEN, NULL, 0,
                         &re, sizeof(re), &br, NULL) || !NT_SUCCESS(re.Status)) {
        printf("  [SKIP] IOCTL 0x813 failed (Status=0x%08X)\n", re.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  Reenlightenment Control (0x40000106): 0x%016llX %s\n",
           re.ReenlightenCtrl, re.ReenlightenGpFault ? "(GP-FAULT)" : "");
    printf("  TSC Emulation Control   (0x40000107): 0x%016llX %s\n",
           re.TscEmulCtrl, re.TscEmulCtrlGpFault ? "(GP-FAULT)" : "");
    printf("  TSC Emulation Status    (0x40000108): 0x%016llX %s\n",
           re.TscEmulStatus, re.TscEmulStatusGpFault ? "(GP-FAULT)" : "");
    printf("\n");

    if (!re.ReenlightenGpFault)
        kvPASS("Reenlightenment Control MSR readable");
    else
        kvWARN("Reenlightenment Control GP-faulted",
               "KVM does not implement MSR 0x40000106. Live migration of VSM guests "
               "may fail to re-sync TSC after migration.");

    if (!re.TscEmulCtrlGpFault)
        kvPASS("TSC Emulation Control MSR readable");
    else
        kvWARN("TSC Emulation Control GP-faulted",
               "KVM does not implement MSR 0x40000107.");

    if (!re.TscEmulStatusGpFault)
        kvPASS("TSC Emulation Status MSR readable");
    else
        kvWARN("TSC Emulation Status GP-faulted",
               "KVM does not implement MSR 0x40000108.");
}

// ---------------------------------------------------------------------------
// SECTION 30 -- Crash MSR Probe (READ-ONLY)
//
// Reads crash notification MSRs without writing.
// 0x40000100-0x40000104: CrashP0 through P4 (data registers)
// 0x40000105: CrashCtl (control register -- DO NOT WRITE)
// ---------------------------------------------------------------------------

static void sect30_crash_msrs()
{
    kvSECT(30, "Crash MSR Probe (READ-ONLY, no writes)");
    printf("  WARNING: This test ONLY READS crash MSRs. No writes.\n");
    printf("  Writing CrashCtl with CrashNotify triggers hypervisor crash notification.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_CRASH_MSRS cm = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_CRASH_MSRS, NULL, 0,
                         &cm, sizeof(cm), &br, NULL) || !NT_SUCCESS(cm.Status)) {
        printf("  [SKIP] IOCTL 0x814 failed (Status=0x%08X)\n", cm.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  CrashCtl (0x40000105): 0x%016llX %s\n",
           cm.CrashCtl, cm.CrashCtlGpFaulted ? "(GP-FAULT)" : "");
    printf("  CrashP0  (0x40000100): 0x%016llX\n", cm.CrashP0);
    printf("  CrashP1  (0x40000101): 0x%016llX\n", cm.CrashP1);
    printf("  CrashP2  (0x40000102): 0x%016llX\n", cm.CrashP2);
    printf("  CrashP3  (0x40000103): 0x%016llX\n", cm.CrashP3);
    printf("  CrashP4  (0x40000104): 0x%016llX\n", cm.CrashP4);
    printf("\n");

    if (!cm.CrashCtlGpFaulted)
        kvPASS("CrashCtl MSR readable (0x40000105)");
    else
        kvWARN("CrashCtl GP-faulted",
               "KVM does not implement MSR 0x40000105. Windows uses this for crash "
               "notification on BSOD -- guest crash reports may not reach the hypervisor.");

    if (!cm.CrashDataGpFaulted)
        kvPASS("Crash data registers P0-P4 readable");
    else
        kvWARN("Some crash data registers GP-faulted",
               "KVM does not implement all MSRs 0x40000100-0x40000104.");
}

// ---------------------------------------------------------------------------
// SECTION 31 -- CR4 SMEP Intercept Verification
//
// HIGH RISK TEST.  Tests that VTL1 installs a CR4 write intercept
// to prevent VTL0 from clearing SMEP (bit 20).
//
// Safety: if SMEP is cleared, driver immediately restores original CR4.
// Skipped if SMEP not set in CR4 (no VTL1 protection installed).
// ---------------------------------------------------------------------------

static void sect31_cr4_intercept()
{
    kvSECT(31, "CR4 SMEP Intercept (HIGH RISK)");
    printf("  Tests VTL1 CR4 write intercept for SMEP protection.\n");
    printf("  Source: securekernel SkmiProtectCr4 / ShvlpSetCr4InterceptMask.\n");
    printf("  If VTL1 intercept is missing, SMEP clearing could succeed.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_CR4_INTERCEPT cr = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_CR4_INTERCEPT, NULL, 0,
                         &cr, sizeof(cr), &br, NULL)) {
        printf("  [SKIP] IOCTL 0x815 failed\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    if (cr.Status == (NTSTATUS)0xC00000BB) {
        printf("  [SKIP] SMEP not set in CR4 -- VTL1 protection not installed\n");
        kvINFO("CR4 intercept", "SMEP not set -- test not applicable");
        return;
    }

    printf("  Original CR4: 0x%016llX\n", cr.OrigCr4);
    printf("  Post-write CR4: 0x%016llX\n", cr.PostWriteCr4);
    printf("  SMEP preserved: %s\n", cr.SmepPreserved ? "YES" : "NO");
    printf("  Exception raised: %s\n", cr.ExceptionRaised ? "YES" : "NO");
    printf("\n");

    if (cr.SmepPreserved && cr.ExceptionRaised)
        kvPASS("CR4 write intercepted by VTL1 -- SMEP clearing blocked with exception");
    else if (cr.SmepPreserved && !cr.ExceptionRaised)
        kvPASS("CR4 write silently reverted by VTL1 -- SMEP preserved");
    else
        kvFAIL("SMEP was cleared by VTL0!",
               "VTL1 did NOT intercept the CR4 write. KVM is not enforcing "
               "CR4 intercepts set by securekernel via HvCallSetVpRegisters "
               "(VsmVpSecureVtlConfig). The driver restored CR4 as a safety measure.");
}

// ---------------------------------------------------------------------------
// SECTION 32 -- SynIC Signal / PostMessage Dispatch
//
// Tests that KVM's SynIC hypercall dispatch handles invalid requests
// gracefully (returns error status, does not crash).
//
// Source: hvax64 HvCallSignalEvent / HvCallPostMessage dispatch.
// ---------------------------------------------------------------------------

static void sect32_synic_signal()
{
    kvSECT(32, "SynIC HvCallSignalEvent / HvCallPostMessage Dispatch");
    printf("  Issues SynIC hypercalls with invalid connection IDs.\n");
    printf("  Expected: error status returned, no crash.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_SYNIC_SIGNAL syn = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_SYNIC_SIGNAL, NULL, 0,
                         &syn, sizeof(syn), &br, NULL) || !NT_SUCCESS(syn.Status)) {
        printf("  [SKIP] IOCTL 0x816 failed (Status=0x%08X)\n", syn.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  HvCallSignalEvent (0x005D): HV_STATUS = 0x%04llX\n",
           syn.SignalEventStatus & 0xFFFF);
    printf("  HvCallPostMessage (0x005C): HV_STATUS = 0x%04llX\n",
           syn.PostMessageStatus & 0xFFFF);
    printf("\n");

    // Status 0 = success (unexpected for invalid connection ID)
    // Status != 0 = error (expected: 0x12 HV_STATUS_INVALID_CONNECTION_ID or similar)
    if ((syn.SignalEventStatus & 0xFFFF) != 0)
        kvPASS("HvCallSignalEvent returned error for invalid connection (expected)");
    else
        kvWARN("HvCallSignalEvent returned success",
               "Unexpected -- connection ID 0 should not be valid.");

    if ((syn.PostMessageStatus & 0xFFFF) != 0)
        kvPASS("HvCallPostMessage returned error for invalid connection (expected)");
    else
        kvWARN("HvCallPostMessage returned success",
               "Unexpected -- connection ID 0 should not be valid.");
}

// ---------------------------------------------------------------------------
// SECTION 33 -- TLB Flush Hypercalls
//
// Tests HvCallFlushVirtualAddressSpace (0x0002) and
// HvCallFlushVirtualAddressList (0x0003).
//
// Stale TLB entries after VTL switch = security vulnerability.
// Source: hvax64 TLB flush dispatch.
// ---------------------------------------------------------------------------

static void sect33_flush()
{
    kvSECT(33, "TLB Flush Hypercalls (HvCallFlush*)");
    printf("  Tests HvCallFlushVirtualAddressSpace (0x0002) and\n");
    printf("  HvCallFlushVirtualAddressList (0x0003).\n");
    printf("  Stale TLB after VTL switch = security vulnerability.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_FLUSH fl = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_FLUSH, NULL, 0,
                         &fl, sizeof(fl), &br, NULL) || !NT_SUCCESS(fl.Status)) {
        printf("  [SKIP] IOCTL 0x817 failed (Status=0x%08X)\n", fl.Status);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    printf("  HvCallFlushVirtualAddressSpace: HV_STATUS = 0x%04llX\n",
           fl.FlushSpaceStatus & 0xFFFF);
    printf("  HvCallFlushVirtualAddressList : HV_STATUS = 0x%04llX\n",
           fl.FlushListStatus & 0xFFFF);
    printf("\n");

    if ((fl.FlushSpaceStatus & 0xFFFF) == 0)
        kvPASS("HvCallFlushVirtualAddressSpace succeeded");
    else
        kvFAIL("HvCallFlushVirtualAddressSpace failed",
               "KVM returned error for TLB flush. This must succeed -- stale TLB "
               "after VTL switch allows VTL0 to access re-protected pages.");

    if ((fl.FlushListStatus & 0xFFFF) == 0)
        kvPASS("HvCallFlushVirtualAddressList succeeded");
    else
        kvWARN("HvCallFlushVirtualAddressList failed",
               "KVM returned error for per-VA TLB flush. May need rep hypercall support.");
}

// ---------------------------------------------------------------------------
// SECTION 34 -- VTL Control Page
//
// The VTL control page is SEPARATE from the VP assist page (MSR 0x40000073).
// It is set via VP register 0x000D0010 (HvRegisterVsmVpVtlControl).
//
// Layout (verified from hvax64 disassembly):
//   +0x00  UINT32  VtlEntryReason   (0 = VtlCall, 1 = Interrupt delivery)
//
// VtlReturnAction is NOT stored in any page -- it is passed via ECX register
// during the VtlReturn hypercall (securekernel: mov ecx, 1; call ShvlpVtlReturn).
//
// Source: hvax64.exe.asm lines 863074-863075, securekernel.exe.asm line 322566.
// ---------------------------------------------------------------------------

static void sect34_vtl_control()
{
    kvSECT(34, "VTL Control Page (VP register 0x000D0010)");
    printf("  Reads VP register 0x000D0010 to locate the VTL control page.\n");
    printf("  VtlEntryReason at offset +0x00 (DWORD): 0=VtlCall, 1=Interrupt.\n");
    printf("  VtlReturnAction is passed via ECX, not stored in any page.\n\n");

    HANDLE h = kvOpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [SKIP] VsmTest.sys not loaded\n");
        return;
    }

    VSMT_VTL_CONTROL vc = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_VTL_ENTRY_REASON, NULL, 0,
                         &vc, sizeof(vc), &br, NULL)) {
        printf("  [SKIP] IOCTL 0x818 failed\n");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    if (vc.Status == (NTSTATUS)0xC000009A) {
        printf("  [SKIP] Could not allocate contiguous memory\n");
        return;
    }

    printf("  HvCallGetVpRegisters(0xD0010) status: 0x%llX\n", vc.HvStatusGetReg);

    if (vc.Status == (NTSTATUS)0xC0000225) {
        printf("  [SKIP] VTL control register not available or page PA is zero\n");
        kvINFO("VTL control page", "Register 0xD0010 returned zero or hypercall failed");
        return;
    }

    printf("  VTL Control Reg   : 0x%016llX\n", vc.VtlControlRegValue);
    printf("  VTL Control PA    : 0x%016llX\n", vc.VtlControlPagePa);
    printf("  VTL Entry Reason  : %u\n", vc.VtlEntryReason);
    printf("  Control Accessible: %s\n", vc.VtlControlAccessible ? "YES" : "NO");
    printf("\n");

    const char* reasonStr = "Unknown";
    if (vc.VtlEntryReason == 0) reasonStr = "VtlCall";
    else if (vc.VtlEntryReason == 1) reasonStr = "Interrupt delivery";
    printf("  Decoded entry reason: %s\n\n", reasonStr);

    if ((vc.HvStatusGetReg & 0xFFFF) == 0)
        kvPASS("HvCallGetVpRegisters(0xD0010) succeeded");
    else
        kvFAIL("HvCallGetVpRegisters(0xD0010) returned error",
               "KVM may not implement the VsmVpVtlControl VP register.");

    if (vc.VtlControlPagePa != 0)
        kvPASS("VTL control page PA is non-zero");
    else
        kvWARN("VTL control page PA is zero",
               "SecureKernel may not have configured the VTL control page yet.");

    if (vc.VtlControlAccessible)
        kvPASS("VTL control page is readable from VTL0");
    else
        kvWARN("VTL control page read faulted",
               "Page may be VTL1-protected (expected if KVM enforces strict VTL isolation).");

    if (vc.VtlControlAccessible && vc.VtlEntryReason <= 1)
        kvPASS("VtlEntryReason is a valid code (0 or 1)");
    else if (vc.VtlControlAccessible)
        kvWARN("VtlEntryReason out of expected range",
               "Expected 0 (VtlCall) or 1 (Interrupt) -- KVM may use different encoding.");
}

// ---------------------------------------------------------------------------
// Run all KVM VSM sections
// ---------------------------------------------------------------------------

void RunKvmVsmTests(void* pNtQSI)
{
    PNTQSI NtQSI = (PNTQSI)pNtQSI;

    printf("\n");
    printf("########################################################\n");
    printf(" KVM VSM Implementation Verification Tests\n");
    printf(" Sections 23-34\n");
    printf("########################################################\n");
    printf(" Focus: VTL switch correctness, MSR banking, FPU isolation,\n");
    printf("        TLB flush, CR4 intercept, SynIC, assist page fields.\n");
    printf("########################################################\n");

    sect23_vtl_latency(NtQSI);
    sect24_msr_isolation();
    sect25_setvpreg();
    sect26_gpa_granularity();
    sect27_concurrent_vtl(NtQSI);
    sect28_xsave_isolation();
    sect29_reenlighten();
    sect30_crash_msrs();
    sect31_cr4_intercept();
    sect32_synic_signal();
    sect33_flush();
    sect34_vtl_control();

    printf("\n  Sections 23-34 summary: %d PASS  %d FAIL  %d WARN\n",
           kvsm_pass, kvsm_fail, kvsm_warn);
}
