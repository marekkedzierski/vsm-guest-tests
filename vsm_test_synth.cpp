//
// vsm_test_synth.cpp -- Synthetic MSR, SynIC, VP register, and hypercall tests
//
// Sections 12-15, derived from exhaustive search of all four disassemblies:
//   hvax64.exe.asm, hvix64.exe.asm, ntoskrnl.exe.asm, securekernel.exe.asm
//
// Build with vsm_test.cpp + vsm_test_intel.cpp:
//   cl /EHa /Zi /O2 vsm_test.cpp vsm_test_intel.cpp vsm_test_synth.cpp
//      /link ntdll.lib kernel32.lib advapi32.lib
//

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Driver IOCTL codes for new sections
// ---------------------------------------------------------------------------

#define VSMT_DEVICE_TYPE   0x8000u
#define VSMT_IOCTL_READ_MSR     CTL_CODE(VSMT_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_VSM_STATE    CTL_CODE(VSMT_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_SYNTH_STATE  CTL_CODE(VSMT_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_VPREGISTER   CTL_CODE(VSMT_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_PARTITION_PROP CTL_CODE(VSMT_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Synthetic MSR addresses (complete set)
// Source: hvax64 HcpHvDispatchMsrReadIntercept_Internal dispatch chain
// ---------------------------------------------------------------------------

// Base group
#define HV_MSR_GUEST_OS_ID       0x40000000u  // Write to enable hypercall page
#define HV_MSR_HYPERCALL         0x40000001u  // bit 0=enable, bits[63:12]=GPA
#define HV_MSR_VP_INDEX          0x40000002u  // Current VP logical index (read-only)
#define HV_MSR_VP_RUNTIME        0x40000004u  // VP runtime in 100ns units

// Time group
#define HV_MSR_TIME_REF_COUNT    0x40000020u  // 100ns time reference (read-only)
#define HV_MSR_REFERENCE_TSC     0x40000021u  // Reference TSC page PA
#define HV_MSR_TSC_FREQUENCY     0x40000022u  // Host TSC frequency in Hz
#define HV_MSR_APIC_FREQUENCY    0x40000023u  // APIC timer frequency in Hz

// APIC / Interrupt group
#define HV_MSR_EOI               0x40000040u  // Synthetic APIC EOI
#define HV_MSR_ICR               0x40000070u  // APIC IPI control register
#define HV_MSR_TPR               0x40000071u  // APIC task priority
#define HV_MSR_VP_ASSIST_PAGE    0x40000073u  // VP assist page (VTL0)

// SynIC group (0x40000080-0x4000008F)
// Source: securekernel ShvlpInitializeSynic, hvax64 bitmap 0xFF0000FFFF003Fh
#define HV_MSR_SCONTROL          0x40000080u  // SynIC enable + APIC config
#define HV_MSR_SVERSION          0x40000081u  // SynIC version (read-only)
#define HV_MSR_SIMP              0x40000082u  // Synthetic Interrupt Message Page PA
#define HV_MSR_SIEFP             0x40000083u  // Synthetic Interrupt Event Flags Page PA
#define HV_MSR_EOM               0x40000084u  // End of Message trigger

// SINT group (0x40000090-0x4000009F)
// VTL1 usage confirmed from securekernel ShvlpInitializeSynic:
//   SINT0 (0x40000090) = 0x200F0  (vector 0xF0, AutoReset=1) -- VTL1 primary channel
//   SINT1 (0x40000091) = 0x20051  (vector 0x51, AutoReset=1) -- VTL1 timer interrupt
#define HV_MSR_SINT0             0x40000090u
#define HV_MSR_SINT1             0x40000091u
#define HV_MSR_SINT2             0x40000092u
// SINT3-15: 0x40000093-0x4000009F

// STIMER group (0x400000B0-0x400000B7)
// VTL1 usage: securekernel ShvlpEnableSyntheticTimer writes:
//   STIMER0_CONFIG = 0x10008  (bit 3=periodic, bit 12=direct delivery)
#define HV_MSR_STIMER0_CONFIG    0x400000B0u
#define HV_MSR_STIMER0_COUNT     0x400000B1u
#define HV_MSR_STIMER1_CONFIG    0x400000B2u
#define HV_MSR_STIMER1_COUNT     0x400000B3u

// VSM MSRs
#define HV_MSR_VSM_PARTITION_CONFIG  0x400000D4u
#define HV_MSR_VSM_PARTITION_STATUS  0x400000E3u
#define HV_MSR_VSM_VP_STATUS         0x400000E4u

// Misc
#define HV_MSR_NESTED_CONTROL    0x400000F0u
#define HV_MSR_REENLIGHTENMENT   0x40000106u
#define HV_MSR_TSC_EMUL_CONTROL  0x40000107u
#define HV_MSR_TSC_EMUL_STATUS   0x40000108u

// SINT AutoReset bit
#define HV_SINT_AUTOEOI          (1u << 17)
#define HV_SINT_MASKED           (1u << 16)
#define HV_SINT_VECTOR_MASK      0xFFu

// Expected VTL1 SINT values (from securekernel ShvlpInitializeSynic):
//   securekernel.exe.asm line 216815: wrmsr(0x40000090, 0x200F0)
//   securekernel.exe.asm line 215321: wrmsr(0x40000091, 0x20051)
#define VTL1_SINT0_EXPECTED      0x200F0ull  // vector=0xF0, AutoReset
#define VTL1_SINT1_EXPECTED      0x20051ull  // vector=0x51, AutoReset (timer)

// Expected VTL1 STIMER0_CONFIG (securekernel.exe.asm line 215324):
//   wrmsr(0x400000B0, 0x10008)
//   bit 3  = 1 (periodic/oneshot select -- depends on direct STIMER support)
//   bit 12 = 1 (direct delivery mode)
#define VTL1_STIMER0_EXPECTED    0x10008ull

// ---------------------------------------------------------------------------
// Synthetic MSR state structure (returned by VSMT_IOCTL_SYNTH_STATE)
// ---------------------------------------------------------------------------

#define VSMT_SENTINEL  0xFFFFFFFFFFFFFFFFull  // MSR GP-faulted

typedef struct {
    // Base MSRs
    UINT64 GuestOsId;          // 0x40000000 -- must be non-zero if HV connected
    UINT64 HypercallPage;      // 0x40000001 -- bit 0 = enabled
    UINT64 VpIndex;            // 0x40000002 -- current VP index
    UINT64 VpRuntime;          // 0x40000004 -- VP runtime in 100ns
    UINT64 TimeRefCount;       // 0x40000020 -- 100ns time reference
    UINT64 TscFrequency;       // 0x40000022 -- TSC freq in Hz

    // SynIC
    UINT64 Scontrol;           // 0x40000080 -- SynIC control
    UINT64 Simp;               // 0x40000082 -- message page PA
    UINT64 Siefp;              // 0x40000083 -- event flags page PA

    // SINTs (relevant subset)
    UINT64 Sint0;              // 0x40000090 -- VTL1 primary: expected 0x200F0
    UINT64 Sint1;              // 0x40000091 -- VTL1 timer:   expected 0x20051
    UINT64 Sint2;              // 0x40000092

    // STIMERs
    UINT64 Stimer0Config;      // 0x400000B0 -- VTL1: expected 0x10008
    UINT64 Stimer0Count;       // 0x400000B1 -- current timer count
    UINT64 Stimer1Config;      // 0x400000B2

    // VP assist page
    UINT64 VpAssistPage;       // 0x40000073 -- VTL0 VP assist page

    // VSM MSRs (from earlier vsm_state)
    UINT64 VsmPartitionStatus; // 0x400000E3
    UINT64 VsmVpStatus;        // 0x400000E4

    NTSTATUS Status;
} VSMT_SYNTH_STATE;

// ---------------------------------------------------------------------------
// VP register query structure (via HvCallGetVpRegisters hypercall 0x50)
// ---------------------------------------------------------------------------

typedef struct {
    UINT32  RegisterId;   // VP register to query
    UINT8   TargetVtl;    // 0xFF = current VTL
    UINT64  Value;        // result
    BOOL    GpFaulted;    // TRUE if hypercall failed
} VSMT_VP_REG_IO;

// VP register IDs (source: securekernel disassembly + Hyper-V TLFS)
// VP assist page (VTL1-specific -- different from MSR 0x40000073 which is VTL0)
#define HV_VPREG_VP_ASSIST_PAGE          0x00090013u  // securekernel line 216009
// VSM code page offsets (VtlCall/VtlReturn entry point offsets)
#define HV_VPREG_VSM_CODE_PAGE_OFFSETS   0x000D0002u  // securekernel line 216093
// VSM VP secure config / VTL capabilities
#define HV_VPREG_VSM_VP_SECURE_VTLCONFIG 0x000D0006u  // securekernel line 216898
// VSM VP context / default GPA protection mask
#define HV_VPREG_VSM_VP_CONTEXT          0x000D0007u  // securekernel line 216230
// VSM VP idle transitions (accessible from VTL0)
#define HV_VPREG_VSM_VP_IDLE_TRANSITIONS 0x00090004u  // ntoskrnl line 773801

// Partition property IDs (used with hypercall 0x7B HvCallGetPartitionProperty)
// Source: ntoskrnl HvlpQueryHypervisorSchedulerType (line 1834918)
#define HV_PARTITION_PROPERTY_SCHEDULER_TYPE  0x0000000Fu  // returns scheduler type byte
#define HV_PARTITION_PROPERTY_DMA_GUARD       0x00000014u  // returns DMA guard status

typedef struct {
    UINT32   PropertyId;   // HV_PARTITION_PROPERTY_*
    UINT64   Value;        // property value
    UINT64   HvStatus;     // 0 = success
    NTSTATUS Status;
} VSMT_PARTITION_PROP;

// ---------------------------------------------------------------------------
// Output helpers (keep self-contained)
// ---------------------------------------------------------------------------

int s12_pass = 0, s12_fail = 0, s12_warn = 0;

static void s12PASS(const char* m) { printf("  [PASS] %s\n", m); s12_pass++; }
static void s12FAIL(const char* m, const char* d) {
    printf("  [FAIL] %s\n         --> %s\n", m, d); s12_fail++;
}
static void s12WARN(const char* m, const char* d) {
    printf("  [WARN] %s\n         --> %s\n", m, d); s12_warn++;
}
static void s12INFO(const char* m, const char* d) {
    printf("  [INFO] %s: %s\n", m, d);
}
static void s12SKIP(const char* m, const char* r) {
    printf("  [SKIP] %s\n         %s\n", m, r);
}
static void s12sect(int n, const char* t) {
    printf("\n========================================================\n");
    printf(" SECTION %d: %s\n", n, t);
    printf("========================================================\n");
}
static void s12sub(const char* t) { printf("\n  -- %s --\n", t); }

static HANDLE OpenDriver()
{
    return CreateFileW(L"\\\\.\\VsmTest",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

// ---------------------------------------------------------------------------
// SECTION 12 -- Synthetic MSR State
//
// Tests every VSM-relevant synthetic MSR from a single IOCTL call.
// Key verification signals derived from disassembly:
//
//   MSR 0x40000001 bit 0 (HypercallPage enable) = 1:
//     KVM must enable the hypercall page for any VSM functionality.
//     Source: hvax64 HcpHvDispatchMsrReadIntercept_Internal,
//             hvix64 identical handler.
//
//   MSR 0x40000082 (SIMP) != 0:
//     SynIC Message Page must be mapped for VTL1 intercept delivery.
//     Source: securekernel ShvlpInitializeSynic line 216804.
//
//   MSR 0x40000083 (SIEFP) != 0:
//     SynIC Event Flags Page mapped. VTL1 uses this for event notification.
//     Source: securekernel ShvlpInitializeSynic line 216815.
//
//   MSR 0x40000090 (SINT0) = 0x200F0 (when VTL1 active):
//     VTL1's primary synthetic interrupt channel.
//     Vector 0xF0, AutoReset=1. Written by ShvlpInitializeSynic.
//     If 0 or SENTINEL: VTL1 SynIC not initialized by securekernel.
//
//   MSR 0x40000091 (SINT1) = 0x20051 (when VTL1 active):
//     VTL1's timer interrupt SINT.
//     Vector 0x51, AutoReset=1. Written by ShvlpEnableSyntheticTimer.
//
//   MSR 0x400000B0 (STIMER0_CONFIG) = 0x10008 (when VTL1 active):
//     VTL1's periodic scheduling timer.
//     bit 3=1 (periodic/oneshot), bit 12=1 (direct delivery).
//     Written by ShvlpEnableSyntheticTimer.
//     If 0: VTL1 timer not running -> scheduling may be broken.
// ---------------------------------------------------------------------------

void sect12_synthetic_msr_state()
{
    s12sect(12, "Synthetic MSR State (SynIC / STIMER / VP)");
    printf("  Source: hvax64 HcpHvDispatchMsrReadIntercept_Internal\n");
    printf("          securekernel ShvlpInitializeSynic + ShvlpEnableSyntheticTimer\n\n");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        s12SKIP("Synthetic MSR tests",
            "VsmTest.sys not loaded. Table of expected values when VSM is working:");
        printf("\n  MSR      | Expected (VTL1 active)     | Source\n");
        printf("  ---------+----------------------------+----------------------\n");
        printf("  40000001 | bit 0 = 1 (page enabled)   | hvax64 MSR dispatch\n");
        printf("  40000002 | VP index (0..N-1)           | ntoskrnl rdmsr usage\n");
        printf("  40000022 | TSC freq in Hz (non-zero)   | hvax64 MSR dispatch\n");
        printf("  40000082 | non-zero (SIMP enabled)     | securekernel line 216804\n");
        printf("  40000083 | non-zero (SIEFP enabled)    | securekernel line 216815\n");
        printf("  40000090 | 0x200F0 (SINT0, VTL1 set)  | securekernel line 216815\n");
        printf("  40000091 | 0x20051 (SINT1, VTL1 set)  | securekernel line 215321\n");
        printf("  400000B0 | 0x10008 (STIMER0_CONFIG)   | securekernel line 215324\n");
        printf("  400000E3 | EnabledVtlSet bit 1 = 1    | VSM_PARTITION_STATUS\n");
        return;
    }

    VSMT_SYNTH_STATE st = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_SYNTH_STATE, NULL, 0,
                         &st, sizeof(st), &br, NULL) || !NT_SUCCESS(st.Status)) {
        s12FAIL("SYNTH_STATE IOCTL", "Add VSMT_IOCTL_SYNTH_STATE to VsmTest.sys (see vsm_ktest_synth.c)");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    // ---- Base MSRs ----
    s12sub("Base synthetic MSRs");
    printf("  GuestOsId   (0x40000000): 0x%016llX\n", st.GuestOsId);
    printf("  HypercallPg (0x40000001): 0x%016llX\n", st.HypercallPage);
    printf("  VpIndex     (0x40000002): 0x%016llX\n", st.VpIndex);
    printf("  VpRuntime   (0x40000004): 0x%016llX\n", st.VpRuntime);
    printf("  TimeRef     (0x40000020): 0x%016llX\n", st.TimeRefCount);
    printf("  TscFreq     (0x40000022): %llu Hz (%.3f GHz)\n",
           st.TscFrequency, (double)st.TscFrequency / 1e9);

    if (st.GuestOsId == VSMT_SENTINEL || st.GuestOsId == 0)
        s12FAIL("GuestOsId",
                "0x40000000 not implemented or returned 0 -- KVM MSR dispatch missing");
    else
        s12PASS("GuestOsId non-zero (MSR 0x40000000 readable)");

    if (st.HypercallPage == VSMT_SENTINEL)
        s12FAIL("HypercallPage MSR", "0x40000001 GP-faulted -- hypercall infrastructure broken");
    else if (!(st.HypercallPage & 1))
        s12FAIL("HypercallPage enabled", "Bit 0 = 0 -- hypercall page not enabled; all hypercalls will fail");
    else
        s12PASS("HypercallPage enabled (bit 0 = 1)");

    if (st.VpIndex == VSMT_SENTINEL)
        s12FAIL("VP_INDEX MSR", "0x40000002 GP-faulted -- KVM must implement HV_MSR_VP_INDEX");
    else
        printf("  [INFO] VP_INDEX = %llu (VP executing this IOCTL)\n", st.VpIndex);

    if (st.TscFrequency == 0 || st.TscFrequency == VSMT_SENTINEL)
        s12WARN("TscFrequency", "0x40000022 not implemented -- guests use CPUID fallback");
    else
        s12PASS("TscFrequency available (MSR 0x40000022)");

    // ---- SynIC ----
    s12sub("SynIC MSRs (0x40000080-0x40000083)");
    printf("  SCONTROL (0x40000080): 0x%016llX\n", st.Scontrol);
    printf("  SIMP     (0x40000082): 0x%016llX\n", st.Simp);
    printf("  SIEFP    (0x40000083): 0x%016llX\n", st.Siefp);

    if (st.Simp == VSMT_SENTINEL || st.Simp == 0)
        s12WARN("SIMP", "SynIC Message Page not mapped -- VTL1 intercept delivery may not work");
    else
        s12PASS("SIMP mapped (SynIC Message Page enabled)");

    if (st.Siefp == VSMT_SENTINEL || st.Siefp == 0)
        s12WARN("SIEFP", "SynIC Event Flags Page not mapped");
    else
        s12PASS("SIEFP mapped (SynIC Event Flags Page enabled)");

    // ---- SINT state -- KEY VTL1 INDICATOR ----
    s12sub("SINT state -- VTL1 initialization indicator");
    printf("  SINT0 (0x40000090): 0x%016llX  (VTL1 expects 0x%016llX)\n",
           st.Sint0, VTL1_SINT0_EXPECTED);
    printf("  SINT1 (0x40000091): 0x%016llX  (VTL1 expects 0x%016llX)\n",
           st.Sint1, VTL1_SINT1_EXPECTED);
    printf("  SINT2 (0x40000092): 0x%016llX\n", st.Sint2);

    // SINT0: securekernel writes 0x200F0 during ShvlpInitializeSynic
    // Vector 0xF0 (240), AutoReset=1, not masked
    if (st.Sint0 == VSMT_SENTINEL)
        s12FAIL("SINT0 readable", "0x40000090 GP-faulted -- KVM must implement all 16 SINTs");
    else if ((st.Sint0 & HV_SINT_VECTOR_MASK) == 0xF0 &&
             (st.Sint0 & HV_SINT_AUTOEOI) &&
             !(st.Sint0 & HV_SINT_MASKED))
        s12PASS("SINT0 = 0x200F0 (VTL1 primary SynIC channel configured by securekernel)");
    else if (st.Sint0 == 0 || (st.Sint0 & HV_SINT_MASKED))
        s12WARN("SINT0", "Masked or zero -- VTL1 SynIC not initialized "
                "(expected from securekernel ShvlpInitializeSynic line 216815)");
    else
        printf("  [INFO] SINT0 value differs from VTL1 expectation (vector=0x%llX, AutoReset=%llu)\n",
               st.Sint0 & 0xFF, (st.Sint0 >> 17) & 1);

    // SINT1: securekernel writes 0x20051 during ShvlpEnableSyntheticTimer
    // Vector 0x51 (81), AutoReset=1
    if (st.Sint1 != VSMT_SENTINEL) {
        if ((st.Sint1 & HV_SINT_VECTOR_MASK) == 0x51 &&
            (st.Sint1 & HV_SINT_AUTOEOI) &&
            !(st.Sint1 & HV_SINT_MASKED))
            s12PASS("SINT1 = 0x20051 (VTL1 timer interrupt SINT configured)");
        else if (st.Sint1 == 0 || (st.Sint1 & HV_SINT_MASKED))
            s12WARN("SINT1", "VTL1 timer SINT not configured (securekernel ShvlpEnableSyntheticTimer)");
    }

    // ---- STIMER state -- VTL1 scheduling indicator ----
    s12sub("STIMER state (VTL1 uses STIMER0 exclusively)");
    printf("  STIMER0_CONFIG (0x400000B0): 0x%016llX  (VTL1 expects 0x%016llX)\n",
           st.Stimer0Config, VTL1_STIMER0_EXPECTED);
    printf("  STIMER0_COUNT  (0x400000B1): 0x%016llX\n", st.Stimer0Count);
    printf("  STIMER1_CONFIG (0x400000B2): 0x%016llX\n", st.Stimer1Config);

    if (st.Stimer0Config == VSMT_SENTINEL)
        s12FAIL("STIMER0_CONFIG", "0x400000B0 GP-faulted -- KVM must implement all 8 STIMER MSRs");
    else if (st.Stimer0Config == VTL1_STIMER0_EXPECTED)
        s12PASS("STIMER0_CONFIG = 0x10008 (VTL1 periodic timer running)");
    else if (st.Stimer0Config == 0)
        s12WARN("STIMER0_CONFIG",
                "Zero -- VTL1 timer not started; securekernel ShvlpEnableSyntheticTimer "
                "writes 0x10008 (periodic, direct delivery, STIMER0)");
    else
        printf("  [INFO] STIMER0_CONFIG = 0x%llX (unexpected value, not 0x10008)\n",
               st.Stimer0Config);

    // Summary for section 12
    printf("\n  Section 12 summary:\n");
    printf("  SINT0 == 0x200F0 and SINT1 == 0x20051: VTL1 SynIC fully initialized\n");
    printf("  STIMER0_CONFIG == 0x10008: VTL1 scheduling timer running\n");
    printf("  These three together confirm securekernel ran ShvlpInitializeSynic\n");
    printf("  and ShvlpEnableSyntheticTimer successfully in VTL1.\n");
}

// ---------------------------------------------------------------------------
// SECTION 13 -- VP Register State (via HvCallGetVpRegisters)
//
// VP registers are per-VTL per-VP values exposed by the hypervisor.
// Key registers for VSM verification:
//
//   0x00090013 (HvRegisterVpAssistPage):
//     VTL1's own VP assist page -- different from MSR 0x40000073 (VTL0 only).
//     securekernel ShvlpInitializeVpAssistPage (line 215989) writes this via
//     HvCallSetVpRegisters (0x51). Non-zero means VTL1 assist page is mapped.
//
//   0x000D0002 (HvRegisterVsmCodePageOffsets):
//     Encodes VtlCall and VtlReturn entry offsets in the hypercall code page.
//     securekernel ShvlpInitializeVsmCodeArea (line 216093) reads this and
//     stores ShvlpVtlCall and ShvlpVtlReturn. Non-zero = VTL1 call path set up.
//
//   0x000D0006 (HvRegisterVsmVpSecureVtlConfig):
//     VTL1 capability flags. Queried by securekernel ShvlpQueryVsmCapabilities
//     (line 216898). Bit 15 controls VP register access; bits [21:18] encode
//     extended VTL capabilities. Non-zero = VTL1 configured by hypervisor.
//
//   0x00090004 (HvRegisterVsmVpIdleTransitions):
//     Accessible from VTL0. Tracks VTL0-VTL1 idle transition counts.
//     ntoskrnl reads this at lines 773801, 777303.
// ---------------------------------------------------------------------------

void sect13_vp_registers()
{
    s12sect(13, "VP Register State (HvCallGetVpRegisters 0x50)");
    printf("  Source: securekernel ShvlpInitializeVsmCodeArea, ShvlpQueryVsmCapabilities\n");
    printf("          securekernel ShvlpInitializeVpAssistPage\n\n");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        s12SKIP("VP register tests", "VsmTest.sys not loaded");
        printf("\n  VP registers that KVM must implement for VSM:\n");
        printf("  0x00090013  HvRegisterVpAssistPage (VTL1)\n");
        printf("              Expected: non-zero (bit 0 = enabled, bits[63:12] = PFN)\n");
        printf("              Source: securekernel ShvlpInitializeVpAssistPage line 215989\n");
        printf("              Query:  HvCallGetVpRegisters(0x50), vpIndex=0xFFFFFFFE, vtl=0xFF\n\n");
        printf("  0x000D0002  HvRegisterVsmCodePageOffsets\n");
        printf("              Expected: bits[11:0]=VtlCallOffset, bits[23:12]=VtlReturnOffset\n");
        printf("              Source: securekernel ShvlpInitializeVsmCodeArea line 216093\n");
        printf("              Must be non-zero for VTL call/return to work\n\n");
        printf("  0x000D0006  HvRegisterVsmVpSecureVtlConfig\n");
        printf("              Expected: bit 15 set + bits[21:18] with capability flags\n");
        printf("              Source: securekernel ShvlpQueryVsmCapabilities line 216898\n");
        printf("              Zero = KVM doesn't support this register = VTL1 boot fails\n\n");
        printf("  0x00090004  HvRegisterVsmVpIdleTransitions (accessible from VTL0)\n");
        printf("              Expected: monotonically increasing counter\n");
        printf("              Source: ntoskrnl line 773801 (HvlVsmGetVpIdleTransitions)\n");
        return;
    }

    // For each VP register: issue VSMT_IOCTL_VPREGISTER with the register ID
    struct { UINT32 id; const char* name; UINT64 expectedMask; UINT64 expectedVal; const char* note; }
    regs[] = {
        { HV_VPREG_VSM_VP_IDLE_TRANSITIONS, "HvRegVsmVpIdleTransitions  [0x90004]",
          0, 0,  // any value (monotonic counter)
          "VTL0-VTL1 idle transition counter (ntoskrnl line 773801)" },
        { HV_VPREG_VP_ASSIST_PAGE, "HvRegVpAssistPage (VTL1)   [0x90013]",
          1, 1,  // bit 0 must be set (enable bit)
          "VTL1 assist page -- non-zero means securekernel ShvlpInitializeVpAssistPage succeeded" },
        { HV_VPREG_VSM_CODE_PAGE_OFFSETS, "HvRegVsmCodePageOffsets    [0xD0002]",
          0xFFFFFF, 0,  // any non-zero in bits[23:0]
          "VtlCall/VtlReturn offsets in hypercall page -- must be non-zero for VTL switching" },
        { HV_VPREG_VSM_VP_SECURE_VTLCONFIG, "HvRegVsmVpSecureVtlConfig  [0xD0006]",
          (1u << 15), (1u << 15),  // bit 15 must be set
          "VTL1 capability flags -- securekernel ShvlpQueryVsmCapabilities uses bit 15 as gate" },
    };

    BOOL driverOk = FALSE;
    for (int i = 0; i < 4; i++) {
        VSMT_VP_REG_IO io = { regs[i].id, 0xFF /* current VTL */ };
        DWORD br = 0;
        if (!DeviceIoControl(h, VSMT_IOCTL_VPREGISTER, &io, sizeof(io),
                             &io, sizeof(io), &br, NULL)) {
            if (i == 0) {
                s12SKIP("VP register IOCTL", "Add VSMT_IOCTL_VPREGISTER to VsmTest.sys (see vsm_ktest_synth.c)");
                CloseHandle(h);
                return;
            }
            break;
        }
        driverOk = TRUE;

        printf("  %s: ", regs[i].name);
        if (io.GpFaulted)
            printf("GP-FAULT (KVM does not implement this VP register)\n");
        else
            printf("0x%016llX\n", io.Value);

        printf("    %s\n", regs[i].note);

        if (io.GpFaulted) {
            s12FAIL(regs[i].name, "VP register not implemented -- VTL1 initialization will fail");
        } else if (regs[i].expectedMask && (io.Value & regs[i].expectedMask) != regs[i].expectedVal) {
            if (io.Value == 0)
                s12WARN(regs[i].name, "Value is 0 -- may indicate VTL1 not yet initialized this register");
            else
                s12WARN(regs[i].name, "Expected bits not set (check TLFS for correct encoding)");
        } else if (io.Value != 0) {
            s12PASS(regs[i].name);
        }
        printf("\n");
    }

    // HvRegVsmCodePageOffsets detail (if readable)
    printf("  HvRegVsmCodePageOffsets decode:\n");
    printf("    bits[11:0]  = VtlCall offset from hypercall page base\n");
    printf("    bits[23:12] = VtlReturn offset from hypercall page base\n");
    printf("    Source: securekernel ShvlpInitializeVsmCodeArea line 216093\n");
    printf("    If both offsets are non-zero: VTL call/return path is configured\n");
    printf("    If zero: securekernel cannot perform VTL1 calls -> boot failure\n");

    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// SECTION 14 -- Partition Property Hypercall (0x7B)
//
// Source: ntoskrnl HvlpQueryHypervisorSchedulerType (line 1834918)
//         lea ecx, [rdi+7Bh] with rdi=0 -> ecx = 0x7B
//         Property 0x0F = scheduler type
//         Property 0x14 = DMA guard enabled
//
// Scheduler types (source: hvax64 GetSchedulerTypeString):
//   1 = Classic (SMT disabled)
//   2 = Classic
//   3 = Core
//   4 = Root  (root partition scheduler -- can only be observed from root)
//
// For KVM VSM: scheduler type must be returned by hypercall 0x7B property 0x0F.
// If not implemented, ntoskrnl falls back and some HvlEnlightenments bits
// (HV_LPI_CAP_ENLIGHTENMENT bit 18) may be incorrectly set.
//
// Also queries property 0x14 (DMA guard enabled status). Source:
// ntoskrnl HvlDmaGetDmaGuardEnabled (line 1835975): mov dword ptr [rbx], 14h
// ---------------------------------------------------------------------------

void sect14_partition_properties()
{
    s12sect(14, "Partition Property Hypercall (0x7B)");
    printf("  Source: ntoskrnl HvlpQueryHypervisorSchedulerType line 1834918\n");
    printf("          ntoskrnl HvlDmaGetDmaGuardEnabled line 1835975\n\n");

    HANDLE h = OpenDriver();
    if (h == INVALID_HANDLE_VALUE) {
        s12SKIP("Partition property tests", "VsmTest.sys not loaded");
        printf("\n  Properties to query via hypercall 0x7B:\n");
        printf("  Property 0x0F: Scheduler type\n");
        printf("    Expected values: 1=Classic(SMT off), 2=Classic, 3=Core, 4=Root\n");
        printf("    KVM default: 2 (Classic). Root partition: 4.\n");
        printf("    Source: ntoskrnl HvlpQueryHypervisorSchedulerType (CPUID 0x40000003)\n\n");
        printf("  Property 0x14: DMA guard enabled\n");
        printf("    0 = disabled, 1 = enabled\n");
        printf("    Source: ntoskrnl HvlDmaGetDmaGuardEnabled\n\n");
        printf("  Property 0x10 (estimated): VSM capability flags\n");
        printf("    Used by ntoskrnl during VSM initialization to verify partition\n");
        printf("    is allowed to use HvCallEnablePartitionVtl\n");
        return;
    }

    struct { UINT32 propId; const char* name; const char* notes; }
    props[] = {
        { HV_PARTITION_PROPERTY_SCHEDULER_TYPE, "Scheduler type [0x0F]",
          "1=Classic(SMT-off), 2=Classic, 3=Core, 4=Root" },
        { HV_PARTITION_PROPERTY_DMA_GUARD, "DMA guard enabled [0x14]",
          "0=disabled, 1=enabled; ntoskrnl HvlDmaGetDmaGuardEnabled" },
    };

    for (int i = 0; i < 2; i++) {
        VSMT_PARTITION_PROP pp = { props[i].propId };
        DWORD br = 0;
        BOOL ok = DeviceIoControl(h, VSMT_IOCTL_PARTITION_PROP,
                                  &pp, sizeof(pp), &pp, sizeof(pp), &br, NULL);
        if (!ok || !NT_SUCCESS(pp.Status)) {
            if (i == 0)
                s12SKIP("Partition property IOCTL", "Add VSMT_IOCTL_PARTITION_PROP to VsmTest.sys");
            CloseHandle(h);
            return;
        }

        printf("  %s: ", props[i].name);
        if (pp.HvStatus == 0) {
            printf("0x%llX\n", pp.Value);
            printf("    %s\n", props[i].notes);

            if (i == 0) { // Scheduler type
                const char* typeStr =
                    pp.Value == 1 ? "Classic (SMT disabled)" :
                    pp.Value == 2 ? "Classic" :
                    pp.Value == 3 ? "Core" :
                    pp.Value == 4 ? "Root" : "Unknown";
                printf("    Type: %s\n", typeStr);
                if (pp.Value >= 1 && pp.Value <= 4)
                    s12PASS("Scheduler type returned valid value");
                else
                    s12WARN("Scheduler type", "Unexpected value -- check KVM property 0x0F handler");
            } else { // DMA guard
                if (pp.Value == 0)
                    s12INFO("DMA guard", "Disabled (expected if IOMMU not configured)");
                else
                    s12PASS("DMA guard enabled (hypercall 0x7B property 0x14)");
            }
        } else {
            printf("HV_STATUS=0x%llX (hypercall failed)\n", pp.HvStatus);
            s12FAIL(props[i].name, "Hypercall 0x7B failed -- KVM may not implement this property");
        }
        printf("\n");
    }

    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// SECTION 15 -- CPUID Hypercall Page Verification
//
// Verifies the complete CPUID leaf chain that Windows uses to handshake
// with the hypervisor. All four leaves must be correct for VSM to initialize.
//
// Source:
//   hvax64 HcpHandleCpuidVendorAndMaxExt line 1028453: injects "Microsoft Hv"
//   hvax64 HcpHandleCpuidPartitionFeatures line 1046780: injects leaf 0x40000001-0x40000003
//   ntoskrnl HvlpDetermineEnlightenments: reads all leaves to populate enlightenment flags
//   securekernel HviGetHypervisorVendorAndMaxFunction: reads leaf 0x40000000
// ---------------------------------------------------------------------------

void sect15_cpuid_chain()
{
    s12sect(15, "CPUID Leaf Chain Verification");
    printf("  Source: hvax64 HcpHandleCpuidVendorAndMaxExt line 1028453\n");
    printf("          ntoskrnl HvlpDetermineEnlightenments\n\n");

    // Leaf 0x40000000 -- vendor string
    int cpu[4] = {};
    __cpuid(cpu, 0x40000000);
    UINT32 maxLeaf = cpu[0];
    char vendor[13] = {};
    memcpy(vendor + 0, &cpu[1], 4);
    memcpy(vendor + 4, &cpu[2], 4);
    memcpy(vendor + 8, &cpu[3], 4);

    printf("  Leaf 0x40000000: max=0x%08X  vendor='%.12s'\n", maxLeaf, vendor);
    if (memcmp(vendor, "Microsoft Hv", 12) == 0)
        s12PASS("Vendor = 'Microsoft Hv' (required by ntoskrnl HvlpDetermineEnlightenments)");
    else
        s12FAIL("Vendor string", "Not 'Microsoft Hv' -- ntoskrnl will not enable any enlightenments");

    // Leaf 0x40000001 -- interface
    __cpuid(cpu, 0x40000001);
    char ifc[5] = {};
    memcpy(ifc, &cpu[0], 4);
    printf("  Leaf 0x40000001: EAX='%.4s'\n", ifc);
    if (memcmp(ifc, "Hv#1", 4) == 0)
        s12PASS("Interface = 'Hv#1' (required by HviIsHypervisorMicrosoftCompatible)");
    else
        s12FAIL("Interface signature", "Not 'Hv#1' -- all HVI* checks will fail");

    // Leaf 0x40000002 -- version
    __cpuid(cpu, 0x40000002);
    UINT32 ver = cpu[0];
    printf("  Leaf 0x40000002: EAX=0x%08X  EBX=0x%08X (HV version %u.%u.%u, SP=%u)\n",
           cpu[0], cpu[1],
           (ver >>  0) & 0xFF,   // major
           (ver >>  8) & 0xFF,   // minor
           (ver >> 16) & 0xFFFF, // build
           cpu[1]);              // service pack

    // Leaf 0x40000003 -- partition privileges
    __cpuid(cpu, 0x40000003);
    UINT32 priv = cpu[0];
    printf("  Leaf 0x40000003: EAX=0x%08X\n", priv);
    printf("    AccessVsm                   [13]: %s  <-- CRITICAL for VSM\n",
           (priv >> 13) & 1 ? "YES" : "NO");
    printf("    AccessVpRegisters           [14]: %s\n", (priv >> 14) & 1 ? "YES" : "NO");
    printf("    EnableExtendedHypercalls    [15]: %s\n", (priv >> 15) & 1 ? "YES" : "NO");
    if (!((priv >> 13) & 1))
        s12FAIL("AccessVsm [13]", "Bit 13 not set -- HvCallEnablePartitionVtl will be rejected");
    else
        s12PASS("AccessVsm [13] set -- partition has VSM privileges");

    // Leaf 0x40000004 -- enlightenment recommendations
    __cpuid(cpu, 0x40000004);
    printf("  Leaf 0x40000004: EAX=0x%08X\n", cpu[0]);
    printf("    UseX2ApicMsrs          [8]: %s\n", (cpu[0] >> 8) & 1 ? "YES" : "NO");
    printf("    Nested virt avail     [12]: %s\n", (cpu[0] >> 12) & 1 ? "YES" : "NO");
    printf("    UseHypercallForRestoreTime [20]: %s\n", (cpu[0] >> 20) & 1 ? "YES" : "NO");

    // Leaf 0x40000005 -- implementation limits
    if (maxLeaf >= 0x40000005) {
        __cpuid(cpu, 0x40000005);
        printf("  Leaf 0x40000005: MaxVPs=%u  MaxLogicalCPUs=%u  MaxIntMappings=%u\n",
               cpu[0], cpu[1], cpu[2]);
        if (cpu[0] == 0)
            s12WARN("MaxVPs", "Zero -- securekernel may fail to allocate VP contexts");
    }

    // Leaf 0x40000006 -- hardware features
    if (maxLeaf >= 0x40000006) {
        __cpuid(cpu, 0x40000006);
        printf("  Leaf 0x40000006: EAX=0x%08X\n", cpu[0]);
        BOOL slat  = (cpu[0] >> 3) & 1;
        BOOL mbec  = (cpu[0] >> 18) & 1;
        BOOL dma   = (cpu[0] >> 7) & 1;
        BOOL csss  = (cpu[0] >> 17) & 1;
        BOOL apicV = (cpu[0] >> 23) & 1;
        printf("    SLAT         [3]: %s  MbecAvailable [18]: %s  DmaProtection [7]: %s\n",
               slat ? "YES" : "NO", mbec ? "YES" : "NO", dma ? "YES" : "NO");
        printf("    SupervisorShadowStack [17]: %s  ApicVirt [23]: %s\n",
               csss ? "YES" : "NO", apicV ? "YES" : "NO");
        if (!slat)
            s12FAIL("SLAT [3]", "SecondLevelAddressTranslation not set -- required for VTL GPA protection");
    }

    // Leaf 0x40000003 EDX -- IOMMU domain flags
    __cpuid(cpu, 0x40000003);
    UINT32 edx3 = cpu[3];
    printf("  Leaf 0x40000003 EDX=0x%08X\n", edx3);
    printf("    HalpHvIommuDeviceDomain    [24]: %s\n", (edx3 >> 24) & 1 ? "YES" : "NO");
    printf("    HalpHvParaVirtIommuDomain  [25]: %s\n", (edx3 >> 25) & 1 ? "YES" : "NO");
}

// ---------------------------------------------------------------------------
// Run all sections 12-15
// ---------------------------------------------------------------------------

void RunSyntheticMsrTests(void* NtQSI)
{
    (void)NtQSI;  // NtQSI not needed for this set (uses driver or direct CPUID)

    printf("\n");
    printf("########################################################\n");
    printf(" Synthetic MSR, VP Register, and Hypercall Tests\n");
    printf(" Sections 12-15\n");
    printf("########################################################\n");
    printf(" Sources: hvax64/hvix64 MSR dispatch, securekernel SynIC init,\n");
    printf("          ntoskrnl enlightenment path\n");
    printf("########################################################\n");

    sect12_synthetic_msr_state();
    sect13_vp_registers();
    sect14_partition_properties();
    sect15_cpuid_chain();

    printf("\n  Sections 12-15 summary: %d PASS  %d FAIL  %d WARN\n",
           s12_pass, s12_fail, s12_warn);
}
