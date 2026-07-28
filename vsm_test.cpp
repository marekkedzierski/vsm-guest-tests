//
// vsm_test.cpp -- Guest-side VSM/VBS feature verification
//
// Run inside a Windows VM backed by KVM VSM to verify each feature works.
// Each test is annotated with the KVM component it exercises so failures
// point directly at what needs to be implemented or fixed.
//
// Build (x64, elevated prompt):
//   cl /EHa /Zi /O2 vsm_test.cpp /link ntdll.lib kernel32.lib advapi32.lib tbs.lib
//
// Usage:
//   vsm_test.exe              -- all sections
//   vsm_test.exe 1            -- single section by number
//
// Section map:
//   1  VTL Infrastructure (CPUID)
//   2  VTL Operational State (NtQuerySystemInformation)
//   3  MBEC / Mode-Based Execute Control
//   4  Credential Guard
//   5  VBS Enclave / IUM
//   6  GPA Memory Protection (HVCI empirical)
//   7  DMA Protection (IOMMU / VTL1 domain model)
//   8  VTL1 Speculation Control (0xD5)
//   9  Synthetic MSRs (requires VsmTest.sys -- see vsm_ktest.c)
//  10  Intel APICv / Posted Interrupts per VTL    (vsm_test_intel.cpp)
//  11  VTL Switch Correctness                     (vsm_test_intel.cpp)
//  12  Synthetic MSR State (SynIC / STIMER / VP)  (vsm_test_synth.cpp)
//  13  VP Register State (HvCallGetVpRegisters)   (vsm_test_synth.cpp)
//  14  Partition Property Hypercall (0x7B)         (vsm_test_synth.cpp)
//  15  CPUID Leaf Chain Verification               (vsm_test_synth.cpp)
//  16  SharedUserData Hyper-V Flag                 (vsm_test_isolation.cpp)
//  17  MSR Liveness (TIME_REF_COUNT monotonicity)  (vsm_test_isolation.cpp)
//  18  Reference TSC Page Content                  (vsm_test_isolation.cpp)
//  19  VTL Isolation: Physical Mapping Bypass      (vsm_test_isolation.cpp)
//  20  MBEC: Supervisor Execute Control            (vsm_test_isolation.cpp)
//  21  KVM MSR pass-through (SPEC_CTRL / PRED_CMD) (vsm_test_isolation.cpp)
//  22  Multi-VP VP_INDEX Uniqueness                (vsm_test_isolation.cpp)
//  23  VTL Switch Latency (user+kernel)            (vsm_test_kvmvsm.cpp)
//  24  Per-VTL MSR Isolation (SynIC banking)       (vsm_test_kvmvsm.cpp)
//  25  HvCallSetVpRegisters Round-Trip             (vsm_test_kvmvsm.cpp)
//  26  GPA Protection Granularity                  (vsm_test_kvmvsm.cpp)
//  27  Concurrent VTL Switch Stress                (vsm_test_kvmvsm.cpp)
//  28  FPU/XSAVE State Isolation                   (vsm_test_kvmvsm.cpp)
//  29  Reenlightenment / TSC Emulation MSRs        (vsm_test_kvmvsm.cpp)
//  30  Crash MSR Probe (read-only)                 (vsm_test_kvmvsm.cpp)
//  31  CR4 SMEP Intercept (HIGH RISK)              (vsm_test_kvmvsm.cpp)
//  32  SynIC Signal / PostMessage Dispatch         (vsm_test_kvmvsm.cpp)
//  33  TLB Flush Hypercalls                        (vsm_test_kvmvsm.cpp)
//  34  VP Assist Page VTL Entry Fields             (vsm_test_kvmvsm.cpp)
//

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <tbs.h>

// ---------------------------------------------------------------------------
// CPUID leaf constants
// ---------------------------------------------------------------------------

#define HV_CPUID_VENDOR_AND_MAX     0x40000000u
#define HV_CPUID_INTERFACE          0x40000001u
#define HV_CPUID_VERSION            0x40000002u
#define HV_CPUID_FEATURES           0x40000003u  // partition privilege flags
#define HV_CPUID_ENLIGHTENMENT_INFO 0x40000004u
#define HV_CPUID_IMPLEMENT_LIMITS   0x40000005u
#define HV_CPUID_HW_FEATURES        0x40000006u

#define AMD_CPUID_SVM_FEATURES      0x8000000Au

// ---------------------------------------------------------------------------
// CPUID 0x40000003 EAX -- partition privilege flags
// ---------------------------------------------------------------------------

#define HV_PRIV_AccessVsm                   (1u << 13)
#define HV_PRIV_AccessVpRegisters           (1u << 14)
#define HV_PRIV_EnableExtendedHypercalls    (1u << 15)
#define HV_PRIV_StartVirtualProcessor       (1u << 16)
#define HV_PRIV_IsolateSecureVmReservations (1u << 17)

// ---------------------------------------------------------------------------
// CPUID 0x40000006 EAX -- hardware features (VSM-relevant subset)
// ---------------------------------------------------------------------------

#define HV_HW_SLAT              (1u <<  3)  // Second-level address translation (EPT/NPT)
#define HV_HW_DmaRemapping      (1u <<  4)  // Intel VT-d / DMA remapping
#define HV_HW_HvManagedIommu    (1u <<  5)  // HV-managed IOMMU (HalpHvIommu=1 in ntoskrnl)
#define HV_HW_DmaProtection     (1u <<  7)  // IOMMU active (securekernel SDEV gate)
#define HV_HW_SupervisorShadow  (1u << 17)  // VTL1 CET shadow stack support
#define HV_HW_MbecAvailable     (1u << 18)  // Mode-Based Execute Control
#define HV_HW_GpaSpaceReclaim   (1u << 19)

// ---------------------------------------------------------------------------
// AMD SVM (CPUID 0x8000000A EDX)
// ---------------------------------------------------------------------------

#define AMD_SVM_AVIC   (1u << 13)   // Advanced Virtual Interrupt Controller
#define AMD_SVM_GMET   (1u << 23)   // Guest Mode Execute Trap (AMD MBEC equivalent)

// ---------------------------------------------------------------------------
// NtQuerySystemInformation classes used
// ---------------------------------------------------------------------------

#define QSI_EnlightenmentInfo       0x5Bu
#define QSI_CodeIntegrity           0x67u
#define QSI_HvDetail                0x9Fu
#define QSI_DeviceGuard             0xA5u
#define QSI_Hsti                    0xA6u
#define QSI_VsmProtection           0xA9u
#define QSI_KvaShadow               0xC4u
#define QSI_SpeculationControl      0xC9u
#define QSI_SecureSpeculationCtrl   0xD5u
#define QSI_AcpiFirmwareTable       0x4Cu

// ---------------------------------------------------------------------------
// Synthetic MSR addresses
// ---------------------------------------------------------------------------

#define HV_MSR_GUEST_OS_ID          0x40000000u
#define HV_MSR_HYPERCALL            0x40000001u
#define HV_MSR_VP_INDEX             0x40000002u
#define HV_MSR_VP_ASSIST_PAGE       0x40000073u
#define HV_MSR_CRASH_CTL            0x40000105u
#define HV_MSR_VSM_PARTITION_CONFIG 0x400000D4u  // written by securekernel to set VTL policy
#define HV_MSR_VSM_PARTITION_STATUS 0x400000E3u  // EnabledVtlSet, MbecEnabled, DmaProtectionActive
#define HV_MSR_VSM_VP_STATUS        0x400000E4u  // ActiveVtl, ActiveMbecEnabled, VP EnabledVtlSet

// HV_X64_MSR_VSM_PARTITION_STATUS layout
typedef union {
    UINT64 raw;
    struct {
        UINT64 EnabledVtlSet      : 16;  // bitmask of enabled VTLs (bit 0=VTL0, bit 1=VTL1, ...)
        UINT64 MbecEnabled        :  1;  // bit 16
        UINT64 DmaProtectionActive:  1;  // bit 17
        UINT64 Reserved           : 46;
    };
} HV_VSM_PARTITION_STATUS;

// HV_X64_MSR_VSM_VP_STATUS layout
typedef union {
    UINT64 raw;
    struct {
        UINT64 ActiveVtl       :  4;   // current VTL this VP is executing in
        UINT64 ActiveMbec      :  1;   // MBEC active for current thread
        UINT64 Reserved0       : 11;
        UINT64 EnabledVtlSet   : 16;   // VTLs enabled for this VP
        UINT64 Reserved1       : 32;
    };
} HV_VSM_VP_STATUS;

// ---------------------------------------------------------------------------
// Structures for NtQuerySystemInformation
// ---------------------------------------------------------------------------

typedef NTSTATUS (WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#pragma pack(push,1)
typedef struct {
    BYTE  HvlHypervisorConnected;
    BYTE  IsRootPartition;      // (HvlpRootFlags >> 3) & 1
    BYTE  IsVmBusPresent;       // (HvlpFlags >> 12) & 1
    BYTE  SchedulerType;
    DWORD Reserved;
    UINT64 HvlEnlightenments;
} ENLIGHTENMENTS_INFO;
#pragma pack(pop)

typedef struct {
    BYTE  Flags0;         // SecureKernelRunning, HVCI, IUM, ...
    BYTE  Flags1;         // Trustlet, KMCI supplemental, CET-SS, ...
    BYTE  Flags2;         // NPF bit 19
    BYTE  Reserved[13];
} DEVICE_GUARD_INFO;

typedef struct {
    BYTE  DmaProtectionAvailable;   // ACPI IVRS/DMAR table present
    BYTE  DmaProtectionInUse;       // HV asserts DMA enforcement active
    BYTE  HardwareMbecAvailable;    // VMX EPT VPID CAP bit 54 or AMD GMET
    BYTE  ApicVirtAvailable;        // CPUID 0x40000006 bit 23
} VSM_PROTECTION_INFO;

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

#define COL 56

static int g_pass = 0, g_fail = 0, g_warn = 0;

static void PASS(const char* msg)
{
    printf("  [PASS] %s\n", msg);
    g_pass++;
}
static void FAIL(const char* msg, const char* detail)
{
    printf("  [FAIL] %s\n         --> %s\n", msg, detail);
    g_fail++;
}
static void WARN(const char* msg, const char* detail)
{
    printf("  [WARN] %s\n         --> %s\n", msg, detail);
    g_warn++;
}
static void INFO(const char* msg, const char* detail)
{
    printf("  [INFO] %s: %s\n", msg, detail);
}
static void SKIP(const char* msg, const char* reason)
{
    printf("  [SKIP] %s\n         %s\n", msg, reason);
}
static void section(int n, const char* title)
{
    printf("\n");
    printf("========================================================\n");
    printf(" SECTION %d: %s\n", n, title);
    printf("========================================================\n");
}
static void subsect(const char* title)
{
    printf("\n  -- %s --\n", title);
}
static void checkbit(const char* name, ULONG val, int bit, bool required)
{
    bool set = (val >> bit) & 1;
    printf("  %-*s : %s", COL, name, set ? "YES" : "NO");
    if (required && !set) { printf("  <-- REQUIRED"); g_fail++; }
    printf("\n");
}
static BOOL probe_acpi(PNtQuerySystemInformation NtQSI, DWORD id)
{
    // Mimics HvlpProcessIommu: 20-byte probe, table present = STATUS_BUFFER_TOO_SMALL
    // + ReturnLength > struct size.  See querysystem.cpp ProbeAcpiTable().
    #pragma pack(push,1)
    struct { ULONG Prov, Action, TableId, BufLen, Pad; }
        sfi = { 0x41435049u, 1u, id, 0u, 0u };
    #pragma pack(pop)
    ULONG retLen = 0;
    NTSTATUS st = NtQSI((SYSTEM_INFORMATION_CLASS)QSI_AcpiFirmwareTable,
                        &sfi, sizeof(sfi), &retLen);
    return (st == (NTSTATUS)0xC0000023u && retLen > sizeof(sfi));
}

// ---------------------------------------------------------------------------
// Section 1 -- VTL Infrastructure (CPUID)
//
// KVM requirements tested here:
//   - CPUID 0x40000001 EAX interface signature == "Hv#1"
//   - CPUID 0x40000003 EAX bit 13 (AccessVsm)
//   - CPUID 0x40000006 EAX bits 3, 18 (SLAT, MBEC)
//   - AMD: CPUID 0x8000000A EDX bit 23 (GMET)
// ---------------------------------------------------------------------------

static void sect1_vtl_cpuid()
{
    section(1, "VTL Infrastructure (CPUID)");

    // Hypervisor present bit
    int cpu[4] = {};
    __cpuid(cpu, 1);
    if (!((cpu[2] >> 31) & 1)) {
        FAIL("Hypervisor present (CPUID.1:ECX[31])",
             "No hypervisor detected -- KVM not running or CPUID filtering misconfigured");
        return;
    }
    PASS("Hypervisor present (CPUID.1:ECX[31])");

    // Max leaf and vendor
    __cpuid(cpu, HV_CPUID_VENDOR_AND_MAX);
    UINT32 maxLeaf = cpu[0];
    char vendor[13] = {};
    memcpy(vendor + 0, &cpu[1], 4);
    memcpy(vendor + 4, &cpu[2], 4);
    memcpy(vendor + 8, &cpu[3], 4);
    printf("  Max HV leaf  : 0x%08X\n", maxLeaf);
    printf("  HV vendor    : %.12s\n", vendor);

    if (maxLeaf < HV_CPUID_HW_FEATURES) {
        FAIL("Max HV leaf >= 0x40000006",
             "KVM must expose at least 0x40000006 for VSM CPUID checks");
        return;
    }
    PASS("Max HV leaf >= 0x40000006");

    // Interface signature -- Windows checks for "Hv#1" exactly
    __cpuid(cpu, HV_CPUID_INTERFACE);
    char ifc[5] = {};
    memcpy(ifc, &cpu[0], 4);
    printf("  HV interface : %.4s\n", ifc);
    if (memcmp(ifc, "Hv#1", 4) == 0)
        PASS("Interface signature == 'Hv#1'");
    else
        FAIL("Interface signature", "Expected 'Hv#1' -- HviIsHypervisorMicrosoftCompatible() will fail");

    subsect("CPUID 0x40000003 EAX -- Partition Privilege Flags");
    __cpuid(cpu, HV_CPUID_FEATURES);
    UINT32 eax3 = cpu[0], edx3 = cpu[3];
    printf("  Raw EAX=0x%08X  EDX=0x%08X\n", eax3, edx3);

    // AccessVsm is the gate for all VSM functionality
    checkbit("AccessVsm                    [13] (VSM master gate)", eax3, 13, true);
    checkbit("AccessVpRegisters            [14]", eax3, 14, true);
    checkbit("EnableExtendedHypercalls     [15]", eax3, 15, false);
    checkbit("StartVirtualProcessor        [16]", eax3, 16, false);
    checkbit("IsolateSecureVmReservations  [17]", eax3, 17, false);

    printf("\n  CPUID 0x40000003 EDX -- HAL IOMMU domain flags:\n");
    printf("  %-*s : %s\n", COL, "HalpHvIommuDeviceDomain    [24]",
           (edx3 >> 24) & 1 ? "YES" : "NO");
    printf("  %-*s : %s\n", COL, "HalpHvParaVirtIommuDomain  [25]",
           (edx3 >> 25) & 1 ? "YES" : "NO");

    subsect("CPUID 0x40000006 EAX -- Hardware Features");
    __cpuid(cpu, HV_CPUID_HW_FEATURES);
    UINT32 hw = cpu[0];
    printf("  Raw EAX=0x%08X\n", hw);

    checkbit("SecondLevelAddressTranslation [3] (EPT/NPT present)", hw, 3, true);
    checkbit("DmaRemapping / VT-d           [4]",                   hw, 4, false);
    checkbit("HV-managed IOMMU (HalpHvIommu)[5]",                  hw, 5, false);
    checkbit("DmaProtection active (SK gate) [7]",                  hw, 7, false);
    checkbit("SupervisorShadowStack (VTL1)  [17]",                  hw, 17, false);
    checkbit("MbecAvailable                 [18]",                  hw, 18, false);
    checkbit("GpaSpaceReclaim               [19]",                  hw, 19, false);

    if (!((hw >> 3) & 1))
        printf("  --> SLAT required: without it HvCallModifyVtlProtectionMask cannot be implemented\n");
    if (!((hw >> 18) & 1))
        printf("  --> MbecAvailable=0: HVCI will use software-only enforcement (weaker)\n");

    subsect("CPUID 0x8000000A EDX -- AMD SVM features (AMD-only)");
    __cpuid(cpu, 0x80000000);
    if ((UINT32)cpu[0] >= AMD_CPUID_SVM_FEATURES) {
        __cpuid(cpu, AMD_CPUID_SVM_FEATURES);
        UINT32 svmEdx = cpu[3];
        printf("  Raw EDX=0x%08X\n", svmEdx);
        checkbit("AVIC (Advanced Virtual Interrupt Controller) [13]", svmEdx, 13, false);
        checkbit("GMET (Guest Mode Execute Trap / AMD MBEC)    [23]", svmEdx, 23, false);
        if (!((svmEdx >> 23) & 1))
            printf("  --> GMET absent: AMD MBEC requires GMET in KVM VMCB\n");
    } else {
        INFO("AMD SVM", "Leaf 0x8000000A not available (Intel host or CPUID limited)");
    }
}

// ---------------------------------------------------------------------------
// Section 2 -- VTL Operational State
//
// KVM requirements tested here:
//   - HvCallEnablePartitionVtl + HvCallEnableVpVtl: VTL1 must be active
//   - VslGetNestedPageProtectionFlags: NPF bits must reach ntoskrnl correctly
//   - SkeQuerySpeculationFeaturesInformation: IUM service 258 dispatch
// ---------------------------------------------------------------------------

static void sect2_vtl_operational(PNtQuerySystemInformation NtQSI)
{
    section(2, "VTL Operational State (NtQuerySystemInformation)");
    ULONG retLen;
    NTSTATUS st;

    subsect("0x5B HvlQueryEnlightenmentInfo");
    ENLIGHTENMENTS_INFO enl = {};
    st = NtQSI((SYSTEM_INFORMATION_CLASS)QSI_EnlightenmentInfo,
               &enl, sizeof(enl), &retLen);
    if (NT_SUCCESS(st)) {
        printf("  HvlHypervisorConnected : %s\n", enl.HvlHypervisorConnected ? "YES" : "NO");
        printf("  IsRootPartition        : %s\n",  enl.IsRootPartition        ? "YES" : "NO");
        printf("  IsVmBusPresent         : %s\n",  enl.IsVmBusPresent         ? "YES" : "NO");
        printf("  SchedulerType          : %u\n",  enl.SchedulerType);
        printf("  HvlEnlightenments      : 0x%016llX\n", enl.HvlEnlightenments);

        if (enl.HvlHypervisorConnected) PASS("HvlHypervisorConnected");
        else FAIL("HvlHypervisorConnected", "Hypervisor not connected to kernel -- KVM enlightenment handshake failed");
    } else {
        FAIL("0x5B query", "NtQuerySystemInformation failed");
    }

    subsect("0xA5 SystemDeviceGuardInformation (VslGetNestedPageProtectionFlags)");
    // Source: ExpQuerySystemInformation case 165 -> VslGetNestedPageProtectionFlags (securekernel)
    DEVICE_GUARD_INFO dg = {};
    st = NtQSI((SYSTEM_INFORMATION_CLASS)QSI_DeviceGuard, &dg, sizeof(dg), &retLen);
    if (NT_SUCCESS(st)) {
        printf("  Raw Flags0=0x%02X  Flags1=0x%02X  Flags2=0x%02X\n",
               dg.Flags0, dg.Flags1, dg.Flags2);
        bool skRunning  = (dg.Flags0 & 0x01) != 0;  // VslIsSecureKernelRunning
        bool hvciKernel = (dg.Flags0 & 0x02) != 0;  // NPF bit 1
        bool hvciUser   = (dg.Flags0 & 0x04) != 0;  // NPF bit 5
        bool hvciAudit  = (dg.Flags0 & 0x08) != 0;  // NPF bit 4
        bool firmPP     = (dg.Flags0 & 0x10) != 0;  // ExpFirmwarePageProtectionSupported
        bool iumActive  = (dg.Flags0 & 0x20) != 0;  // VslpEnterIumSecureMode succeeded
        bool trustlet   = (dg.Flags1 & 0x01) != 0;  // VslIsTrustletRunning
        bool kmciSuppl  = (dg.Flags1 & 0x02) != 0;  // NPF bit 9
        bool kss        = (dg.Flags1 & 0x04) != 0;  // NPF bit 11 (CET-SS for kernel)
        bool kssStrict  = (dg.Flags1 & 0x08) != 0;  // NPF bit 12

        printf("  SecureKernelRunning   [0].0 VslIsSecureKernelRunning : %s\n", skRunning  ? "YES" : "NO");
        printf("  HVCI kernel enforce   [0].1 NPF bit 1                : %s\n", hvciKernel ? "YES" : "NO");
        printf("  HVCI user mode        [0].2 NPF bit 5                : %s\n", hvciUser   ? "YES" : "NO");
        printf("  HVCI audit mode       [0].3 NPF bit 4                : %s\n", hvciAudit  ? "YES" : "NO");
        printf("  Firmware page prot    [0].4 ExpFirmwarePP            : %s\n", firmPP     ? "YES" : "NO");
        printf("  IUM active            [0].5 VslpEnterIumSecureMode   : %s\n", iumActive  ? "YES" : "NO");
        printf("  Trustlet running      [1].0 VslIsTrustletRunning     : %s\n", trustlet   ? "YES" : "NO");
        printf("  KMCI supplemental     [1].1 NPF bit 9                : %s\n", kmciSuppl  ? "YES" : "NO");
        printf("  Kernel shadow stacks  [1].2 NPF bit 11               : %s\n", kss        ? "YES" : "NO");
        printf("  KSS strict mode       [1].3 NPF bit 12               : %s\n", kssStrict  ? "YES" : "NO");

        if (skRunning)  PASS("SecureKernel running (VTL1 up, HvCallEnablePartitionVtl worked)");
        else            FAIL("SecureKernel running",
                             "VTL1 not active -- HvCallEnablePartitionVtl or HvCallEnableVpVtl not implemented");
        if (hvciKernel) PASS("HVCI kernel enforcement (HvCallModifyVtlProtectionMask active)");
        else            WARN("HVCI kernel enforcement",
                             "Not active -- VTL1 NPT protection not enforcing kernel execute control");
        if (iumActive)  PASS("IUM mode (VTL1 trustlet support -- Credential Guard possible)");
        else            FAIL("IUM active",
                             "VslpEnterIumSecureMode failed -- LSAISO / VBS enclave creation will fail");
    } else {
        FAIL("0xA5 query", "NtQuerySystemInformation failed");
    }

    subsect("0x67 SystemCodeIntegrityInformation (HVCI / IUM via code integrity options)");
    SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci) };
    st = NtQSI((SYSTEM_INFORMATION_CLASS)QSI_CodeIntegrity, &ci, sizeof(ci), &retLen);
    if (NT_SUCCESS(st)) {
        bool hvciKmci = (ci.CodeIntegrityOptions & 0x400) != 0;
        bool ium      = (ci.CodeIntegrityOptions & 0x800) != 0;
        printf("  Raw CodeIntegrityOptions : 0x%08X\n", ci.CodeIntegrityOptions);
        printf("  HVCI_KMCI_ENABLED  [10]  : %s\n", hvciKmci ? "YES" : "NO");
        printf("  HVCI_IUM_ENABLED   [11]  : %s\n", ium      ? "YES" : "NO");
        if (hvciKmci) PASS("HVCI_KMCI_ENABLED -- kernel code integrity enforcement active");
        else          FAIL("HVCI_KMCI_ENABLED", "HVCI not active");
        if (ium)      PASS("HVCI_IUM_ENABLED -- securekernel confirmed running in IUM/VTL1");
        else          FAIL("HVCI_IUM_ENABLED", "IUM mode not entered");
    }

    subsect("0xA9 SystemVsmProtectionInformation (HvlQueryVsmProtectionInfo)");
    VSM_PROTECTION_INFO vsm = {};
    st = NtQSI((SYSTEM_INFORMATION_CLASS)QSI_VsmProtection, &vsm, sizeof(vsm), &retLen);
    if (NT_SUCCESS(st)) {
        printf("  DmaProtectionAvailable [0] : %s  (ACPI IVRS/DMAR table present)\n", vsm.DmaProtectionAvailable ? "YES" : "NO");
        printf("  DmaProtectionInUse     [1] : %s  (CPUID 0x40000006[7]; HV asserts active)\n", vsm.DmaProtectionInUse     ? "YES" : "NO");
        printf("  HardwareMbecAvailable  [2] : %s  (VMX EPT VPID CAP bit 54 or AMD GMET)\n", vsm.HardwareMbecAvailable  ? "YES" : "NO");
        printf("  ApicVirtAvailable      [3] : %s  (CPUID 0x40000006[23])\n", vsm.ApicVirtAvailable      ? "YES" : "NO");

        if (vsm.HardwareMbecAvailable) PASS("MBEC hardware available (0xA9[2])");
        else                           WARN("MBEC hardware", "Not available -- check KVM VMCS/VMCB MBEC enable path");
    }
}

// ---------------------------------------------------------------------------
// Section 3 -- MBEC (Mode-Based Execute Control)
//
// KVM requirements tested here:
//   - CPUID 0x40000006[18]: MbecAvailable must be set
//   - AMD: CPUID 0x8000000A[23]: GMET must be set and enabled in VMCB
//   - Intel: EPT must have separate user/supervisor execute bits
//   - 0xA9[2]: HardwareMbecAvailable = VMX_EPT_VPID_CAP bit 54 or AMD GMET
//   - 0xA5: HVCI + kernel shadow stacks enabled by securekernel using MBEC
// ---------------------------------------------------------------------------

static void sect3_mbec(PNtQuerySystemInformation NtQSI)
{
    section(3, "MBEC (Mode-Based Execute Control)");
    ULONG retLen;

    // 1. CPUID advertisement
    int cpu[4] = {};
    __cpuid(cpu, HV_CPUID_VENDOR_AND_MAX);
    bool mbecCpuid = false;
    if ((UINT32)cpu[0] >= HV_CPUID_HW_FEATURES) {
        __cpuid(cpu, HV_CPUID_HW_FEATURES);
        mbecCpuid = ((cpu[0] >> 18) & 1) != 0;
    }
    printf("  CPUID 0x40000006[18] MbecAvailable : %s\n", mbecCpuid ? "YES" : "NO");
    if (!mbecCpuid)
        FAIL("MbecAvailable CPUID bit", "KVM must set bit 18 in CPUID 0x40000006 EAX when MBEC is supported");

    // 2. AMD GMET
    __cpuid(cpu, 0x80000000);
    bool gmet = false;
    if ((UINT32)cpu[0] >= AMD_CPUID_SVM_FEATURES) {
        __cpuid(cpu, AMD_CPUID_SVM_FEATURES);
        gmet = ((cpu[3] >> 23) & 1) != 0;
    }
    printf("  CPUID 0x8000000A[23] GMET (AMD)    : %s\n", gmet ? "YES" : "NO");
    if (!gmet)
        INFO("GMET", "Not advertised (Intel host, or AMD KVM not setting GMET in CPUID)");

    // 3. 0xA9[2] hardware MBEC reflected in kernel
    VSM_PROTECTION_INFO vsm = {};
    NtQSI((SYSTEM_INFORMATION_CLASS)QSI_VsmProtection, &vsm, sizeof(vsm), &retLen);
    printf("  0xA9[2] HardwareMbecAvailable      : %s\n", vsm.HardwareMbecAvailable ? "YES" : "NO");
    if (mbecCpuid && !vsm.HardwareMbecAvailable)
        WARN("MBEC CPUID/0xA9 mismatch",
             "CPUID claims MBEC but 0xA9[2]=0 -- KVM may not be setting VMX_EPT_VPID_CAP bit 54 "
             "or AMD GMET bit in the reported capabilities");

    // 4. HVCI + kernel shadow stacks (MBEC consequence)
    DEVICE_GUARD_INFO dg = {};
    NtQSI((SYSTEM_INFORMATION_CLASS)QSI_DeviceGuard, &dg, sizeof(dg), &retLen);
    bool hvciKernel = (dg.Flags0 & 0x02) != 0;
    bool kss        = (dg.Flags1 & 0x04) != 0;
    printf("  HVCI kernel enforcement active     : %s\n", hvciKernel ? "YES" : "NO");
    printf("  Kernel CET shadow stacks active    : %s\n", kss        ? "YES" : "NO");

    // 5. CET from kernel's perspective (0xDD)
    ULONG cetFlags = 0;
    NtQSI((SYSTEM_INFORMATION_CLASS)0xDD, &cetFlags, sizeof(cetFlags), &retLen);
    printf("  0xDD CET hardware support   [0]    : %s\n", (cetFlags >> 0) & 1 ? "YES" : "NO");
    printf("  0xDD CET user mode          [1]    : %s\n", (cetFlags >> 1) & 1 ? "YES" : "NO");
    printf("  0xDD CET kernel enabled     [8]    : %s\n", (cetFlags >> 8) & 1 ? "YES" : "NO");

    // Summary
    if (mbecCpuid && vsm.HardwareMbecAvailable && hvciKernel)
        PASS("MBEC: advertised + hardware confirmed + HVCI active -- full MBEC enforcement chain OK");
    else if (!mbecCpuid)
        FAIL("MBEC chain", "CPUID bit 18 not set -- securekernel won't enable MBEC");
    else if (!vsm.HardwareMbecAvailable)
        WARN("MBEC chain", "Hardware MBEC not reflected in 0xA9[2]");
    else
        WARN("MBEC chain", "MBEC advertised but HVCI not yet active");
}

// ---------------------------------------------------------------------------
// Section 4 -- Credential Guard
//
// KVM requirements tested here:
//   - Full VTL1 operational (VtlRunning, IumActive from sect2)
//   - LsaIso.exe running as IUM trustlet (ShvlAttachDeviceDomain path for
//     credential material isolation)
//   - lsass.exe is PPL (Protected Process Light)
// ---------------------------------------------------------------------------

static void sect4_credential_guard()
{
    section(4, "Credential Guard");

    // Registry configuration
    subsect("Registry configuration");
    auto regDword = [](HKEY root, const wchar_t* path, const wchar_t* val) -> DWORD {
        HKEY h; DWORD v = 0, sz = sizeof(v);
        if (RegOpenKeyExW(root, path, 0, KEY_READ, &h) == ERROR_SUCCESS) {
            RegQueryValueExW(h, val, NULL, NULL, (LPBYTE)&v, &sz);
            RegCloseKey(h);
        }
        return v;
    };

    DWORD lsaFlags  = regDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags");
    DWORD cgEnabled = regDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard", L"Enabled");
    DWORD cgRunning = regDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard", L"Running");
    DWORD vbsOn     = regDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity");

    const char* lsaStr = lsaFlags == 1 ? "enabled + UEFI lock" :
                         lsaFlags == 2 ? "enabled, no UEFI lock" : "disabled";
    printf("  VBS enabled   (DeviceGuard\\EnableVBS)     : %s\n", vbsOn     ? "YES" : "NO");
    printf("  CG configured (Scenarios\\CG\\Enabled)      : %s\n", cgEnabled ? "YES" : "NO");
    printf("  CG running    (Scenarios\\CG\\Running)      : %s\n", cgRunning ? "YES" : "NO");
    printf("  LsaCfgFlags                               : 0x%X (%s)\n", lsaFlags, lsaStr);

    if (!vbsOn)   WARN("VBS enabled", "Not configured -- Credential Guard requires VBS");
    if (!cgEnabled) WARN("CG configured", "Not enabled in policy");
    if (cgRunning) PASS("Credential Guard: OS reports CG running");
    else           FAIL("Credential Guard running", "Running=0 -- VTL1 not providing credential isolation");

    // Process detection
    subsect("LsaIso.exe (IUM trustlet) and lsass PPL");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD lsassPid = 0, lsaisoPid = 0;
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(pe) };
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe")  == 0) lsassPid  = pe.th32ProcessID;
            if (_wcsicmp(pe.szExeFile, L"LsaIso.exe") == 0) lsaisoPid = pe.th32ProcessID;
        }
        CloseHandle(snap);
    }
    printf("  lsass.exe  PID : %u\n", lsassPid);
    printf("  LsaIso.exe PID : %u\n", lsaisoPid);

    if (lsaisoPid) PASS("LsaIso.exe is running as an IUM trustlet in VTL1");
    else           FAIL("LsaIso.exe", "Not running -- VTL1 IUM mode not working or CG not active");

    // Empirical: try to open lsass with full access -- PPL must block it
    if (lsassPid) {
        HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
        if (!hLsass) {
            if (GetLastError() == ERROR_ACCESS_DENIED)
                PASS("lsass PPL: OpenProcess(PROCESS_ALL_ACCESS) denied (PPL active)");
            else
                INFO("lsass open", "Denied (non-standard error)");
        } else {
            CloseHandle(hLsass);
            FAIL("lsass PPL", "lsass opened with PROCESS_ALL_ACCESS -- Credential Guard NOT protecting credential store");
        }
    }
}

// ---------------------------------------------------------------------------
// Section 5 -- VBS Enclave / IUM
//
// KVM requirements tested here:
//   - The full VTL entry path: CreateEnclave(VBS) ->
//     NtCreateEnclave -> VslCreateEnclave -> securekernel IUM service
//   - This exercises HvCallEnableVpVtl, VTL context switch, and IUM mode
// ---------------------------------------------------------------------------

#ifndef ENCLAVE_TYPE_VBS
#  define ENCLAVE_TYPE_VBS       0x00000010u
#endif
#ifndef ENCLAVE_VBS_FLAG_DEBUG
#  define ENCLAVE_VBS_FLAG_DEBUG 0x00000001u
#endif

// ENCLAVE_CREATE_INFO_VBS is defined by the Windows SDK (winenclaveapi.h)
typedef LPVOID(WINAPI* PCreateEnclave)(HANDLE, LPVOID, SIZE_T, SIZE_T, DWORD, LPCVOID, DWORD, LPDWORD);
typedef BOOL  (WINAPI* PDeleteEnclave)(LPVOID);
typedef BOOL  (WINAPI* PIsEnclaveFeaturePresent)(DWORD);

static void sect5_ium_enclave()
{
    section(5, "VBS Enclave / IUM (VTL1 entry path)");

    HMODULE hK32   = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto pCreate = (PCreateEnclave)           GetProcAddress(hK32,   "CreateEnclave");
    auto pDelete = (PDeleteEnclave)           GetProcAddress(hK32,   "DeleteEnclave");
    auto pCheck  = (PIsEnclaveFeaturePresent) GetProcAddress(hNtdll, "RtlIsEnclaveFeaturePresent");

    if (!pCreate) { SKIP("VBS enclave", "CreateEnclave unavailable (OS < 1709)"); return; }

    // Pre-check: RtlIsEnclaveFeaturePresent
    if (pCheck) {
        BOOL vbsOk = pCheck(ENCLAVE_TYPE_VBS);
        printf("  RtlIsEnclaveFeaturePresent(VBS) : %s\n", vbsOk ? "YES" : "NO");
        if (!vbsOk)
            WARN("VBS enclave feature", "RtlIsEnclaveFeaturePresent=FALSE -- VTL1 IUM not active");
    }

    // CreateEnclave(VBS) exercises the full VTL entry path:
    //   usermode -> NtCreateEnclave -> kernel -> VslCreateEnclave
    //   -> securekernel IUM service (VTL switch) -> SkmmCreateExposedSecureSection
    //   -> ShvlAttachDeviceDomain (hypercall 0xB2)
    ENCLAVE_CREATE_INFO_VBS info = { ENCLAVE_VBS_FLAG_DEBUG };
    DWORD enclErr = 0;
    LPVOID base = pCreate(GetCurrentProcess(), NULL, 0x10000, 0,
                          ENCLAVE_TYPE_VBS, &info, sizeof(info), &enclErr);
    if (base) {
        PASS("VBS enclave created -- full VTL1 entry path works (VTL switch, IUM service, hypercall 0xB2)");
        printf("        Enclave base VA: %p\n", base);
        pDelete(base);
    } else {
        DWORD err = GetLastError();
        switch (err) {
        case ERROR_NOT_SUPPORTED:
            FAIL("VBS enclave", "ERROR_NOT_SUPPORTED -- VTL1 not running OR HvCallEnablePartitionVtl/IUM not implemented in KVM");
            break;
        case ERROR_EAS_NOT_SUPPORTED:
            FAIL("VBS enclave", "Feature disabled by policy -- check VBS/IUM policy");
            break;
        case ERROR_ACCESS_DENIED:
            // VTL1 IS running but rejected the enclave for policy/signing reasons -- still useful
            PASS("VTL1 running (enclave rejected for policy/signing, NOT for missing VTL1)");
            INFO("Enclave denied", "Signing or measurement mismatch -- expected in test environments");
            break;
        case ERROR_INVALID_PARAMETER:
            WARN("VBS enclave", "INVALID_PARAMETER -- check ENCLAVE_CREATE_INFO_VBS structure or size");
            break;
        default:
            printf("  [FAIL] VBS enclave: LastError=0x%08X  EnclaveError=0x%08X\n", err, enclErr);
            g_fail++;
        }
    }
}

// ---------------------------------------------------------------------------
// Section 6 -- GPA Memory Protection (HvCallModifyVtlProtectionMask)
//
// KVM requirements tested here:
//   - HvCallModifyVtlProtectionMask: VTL1 must be able to set per-VTL NPT/EPT
//     permissions (e.g., mark kernel .text pages as read-only from VTL0)
//   - SkmiProtectPageRange (securekernel): SLAT modifications must succeed
// ---------------------------------------------------------------------------

static void sect6_gpa_protection(PNtQuerySystemInformation NtQSI)
{
    section(6, "GPA Memory Protection (HvCallModifyVtlProtectionMask / NPT-EPT)");

    // Infer from HVCI: if HVCI is active, VTL1 has called HvCallModifyVtlProtectionMask
    // to mark kernel code pages as read-only from VTL0's perspective.
    SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci) };
    ULONG retLen;
    NtQSI((SYSTEM_INFORMATION_CLASS)QSI_CodeIntegrity, &ci, sizeof(ci), &retLen);
    bool hvci = (ci.CodeIntegrityOptions & 0x400) != 0;

    printf("  HVCI active (implies VTL1 NPT write-protect on .text pages) : %s\n",
           hvci ? "YES" : "NO");
    if (hvci)
        PASS("GPA protection: HVCI implies HvCallModifyVtlProtectionMask operational");
    else
        FAIL("GPA protection", "HVCI not active -- VTL1 NPT/EPT modification not enforced");

    // Empirical test A: try to make a system DLL's .text section writable via VirtualProtect.
    // With HVCI: VirtualProtect to PAGE_EXECUTE_READWRITE should fail (or if it succeeds,
    // any actual write attempt should AV because VTL1 has locked the page in the SLAT).
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
        BYTE* textPage = (BYTE*)hNtdll + nt->OptionalHeader.BaseOfCode;

        DWORD oldProt = 0;
        BOOL vpOk = VirtualProtect(textPage, 1, PAGE_EXECUTE_READWRITE, &oldProt);
        if (!vpOk) {
            PASS("ntdll .text: VirtualProtect(RWX) blocked by HVCI/policy");
        } else {
            // VirtualProtect succeeded at the PTE level -- try the actual write
            BYTE orig = *textPage;
            BOOL wrote = FALSE;
            __try { *textPage = orig; wrote = TRUE; }
            __except (EXCEPTION_EXECUTE_HANDLER) { /* SLAT blocked it */ }
            VirtualProtect(textPage, 1, oldProt, &oldProt);
            if (!wrote)
                PASS("ntdll .text: write blocked by VTL1 SLAT despite VirtualProtect succeeding");
            else
                FAIL("ntdll .text writable",
                     "VTL1 SLAT NOT blocking writes to code pages -- HvCallModifyVtlProtectionMask not enforcing");
        }
    }

    // Empirical test B: RWX allocation blocked by HVCI / ProhibitDynamicCode
    LPVOID rwx = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rwx) {
        PASS("RWX VirtualAlloc blocked by HVCI/UMCI policy");
    } else {
        VirtualFree(rwx, 0, MEM_RELEASE);
        INFO("RWX alloc", "Succeeded for this process (expected if not under UMCI -- kernel pages still SLAT-protected)");
    }

    // KVA shadow / KPTI state for completeness
    ULONG kva = 0;
    NtQSI((SYSTEM_INFORMATION_CLASS)QSI_KvaShadow, &kva, sizeof(kva), &retLen);
    printf("  KVA Shadow / KPTI active [0]       : %s\n", kva & 1 ? "YES" : "NO");
    printf("  KVA Shadow + PCID        [2]       : %s\n", (kva >> 2) & 1 ? "YES" : "NO");
    printf("  Raw KVA DWORD            : 0x%08X\n", kva);
}

// ---------------------------------------------------------------------------
// Section 7 -- DMA Protection (IOMMU / VTL1 domain model)
//
// KVM requirements tested here:
//   - ACPI SDEV/IVRS/DMAR table emulation via NtQuerySystemInformation(0x4C)
//   - CPUID 0x40000006[7]: DmaProtection active assertion
//   - VTL1 per-device IOMMU domain model:
//       SkhalDmaInitializeDevice -> ShvlAttachDeviceDomain (hypercall 0xB2)
//       pages granted via ShvlMapDeviceGpaPages (hypercall 0xB3)
// ---------------------------------------------------------------------------

static void sect7_dma_protection(PNtQuerySystemInformation NtQSI)
{
    section(7, "DMA Protection (IOMMU / VTL1 domain model)");
    ULONG retLen;

    // 0xA9 DMA bytes
    VSM_PROTECTION_INFO vsm = {};
    NtQSI((SYSTEM_INFORMATION_CLASS)QSI_VsmProtection, &vsm, sizeof(vsm), &retLen);
    printf("  0xA9[0] DmaProtectionAvailable : %s  (ACPI IVRS/DMAR present)\n",
           vsm.DmaProtectionAvailable ? "YES" : "NO");
    printf("  0xA9[1] DmaProtectionInUse     : %s  (HV CPUID 0x40000006[7] assertion)\n",
           vsm.DmaProtectionInUse ? "YES" : "NO");

    // ACPI table probes
    struct { DWORD sig; const char* name; const char* desc; } tbls[] = {
        { 0x56454453u, "SDEV", "Secure Devices (securekernel DMA policy; fatal if IOMMU absent)" },
        { 0x53525649u, "IVRS", "AMD I/O Virtualization Reporting Structure (AMD-Vi)" },
        { 0x52414D44u, "DMAR", "Intel DMA Remapping / VT-d" },
        { 0x4746434Du, "MCFG", "PCIe MMCFG (SkhalpPciMcfgInit in securekernel)" },
    };
    printf("\n  ACPI table probes (NtQuerySystemInformation 0x4C):\n");
    BOOL present[4] = {};
    for (int i = 0; i < 4; i++) {
        present[i] = probe_acpi(NtQSI, tbls[i].sig);
        printf("    %-4s : %-8s  %s\n",
               tbls[i].name, present[i] ? "PRESENT" : "absent",
               present[i] ? tbls[i].desc : "");
    }

    // VTL1 DMA model inference (same logic as querysystem PrintDmaProtectionDetail)
    DEVICE_GUARD_INFO dg = {};
    NtQSI((SYSTEM_INFORMATION_CLASS)QSI_DeviceGuard, &dg, sizeof(dg), &retLen);
    bool skRunning = (dg.Flags0 & 0x01) != 0;

    int cpu[4] = {};
    __cpuid(cpu, HV_CPUID_VENDOR_AND_MAX);
    bool iommuGate = false;
    if ((UINT32)cpu[0] >= HV_CPUID_HW_FEATURES) {
        __cpuid(cpu, HV_CPUID_HW_FEATURES);
        iommuGate = ((cpu[0] >> 7) & 1) != 0;
    }

    printf("\n  VTL1 DMA model:\n");
    printf("    SecureKernel running (0xA5[0].0)   : %s\n", skRunning ? "YES" : "NO");
    printf("    IOMMU gate CPUID 0x40000006[7]     : %s\n", iommuGate ? "YES" : "NO");
    printf("    ACPI SDEV present                  : %s\n", present[0] ? "YES" : "NO");

    if (skRunning && iommuGate) {
        PASS("VTL1 per-device IOMMU domain model ACTIVE");
        printf("         All DMA devices placed in VTL1-owned domains (0 pages mapped).\n");
        printf("         Pages granted only via ShvlMapDeviceGpaPages (KVM hypercall 0xB3).\n");
        if (present[0])
            printf("         SDEV present -- SkhalInitSystem populated per-device DMA policy.\n");
    } else if (present[0] && !iommuGate) {
        FAIL("DMA: SDEV present but IOMMU gate=0",
             "KVM must set CPUID 0x40000006[7]=1 when IOMMU enforcement is active; "
             "securekernel BugChecks on next VTL1 boot if SDEV present without IOMMU");
    } else if (!skRunning) {
        INFO("DMA model", "HAL-level DMA guard only (VTL1 not running)");
    }
}

// ---------------------------------------------------------------------------
// Section 8 -- VTL1 Speculation Control (0xD5)
//
// KVM requirements tested here:
//   - IUM service 258 dispatch: VslGetSecureSpeculationControlInformation
//     must route to SkeQuerySpeculationFeaturesInformation in securekernel
//   - Bit 0, 4, 5: hardcoded sentinels (always-1, pipeline integrity check)
//   - Bits 1-3: VTL1 KPTI state (SkiKvaShadow / SkiKvaShadowMode)
//   - Bits 6-11, 14-15: SkiSpeculationFeatures-derived (IBRS/STIBP/eIBRS/SSBD)
//   - Bits 12-13: per-CPU gs:0xAB0 boundary enforcement (IBPB on exit/entry)
//
// NOTE: ntoskrnl applies a NON-LINEAR bit remap between SK output and user-mode
// DWORD. SK bit numbers != output bit numbers. All mappings confirmed from
// securekernel + ntoskrnl disassembly. See VSM_VTL_Speculation_Fields.txt.
// ---------------------------------------------------------------------------

static void sect8_vtl1_speculation(PNtQuerySystemInformation NtQSI)
{
    section(8, "VTL1 Speculation Control (0xD5 -- SkeQuerySpeculationFeaturesInformation)");

    printf("  Source: SkeQuerySpeculationFeaturesInformation (securekernel.exe)\n");
    printf("  Path:   KeQuerySecureSpeculationInformation -> IUM service 258\n");
    printf("          -> VslGetSecureSpeculationControlInformation\n\n");

    ULONG secspec = 0, retLen;
    NTSTATUS st = NtQSI((SYSTEM_INFORMATION_CLASS)QSI_SecureSpeculationCtrl,
                        &secspec, sizeof(secspec), &retLen);
    if (!NT_SUCCESS(st)) {
        FAIL("0xD5 query", "Failed -- VTL1 not running or IUM service 258 not implemented");
        printf("         NTSTATUS: 0x%08X\n", st);
        return;
    }
    printf("  Raw DWORD: 0x%08X\n\n", secspec);

    // Bit 0: hardcoded sentinel (always 1 in SkeQuerySpeculationFeaturesInformation)
    // If this is 0, securekernel did not actually provide the data.
    if ((secspec & 1) == 0)
        FAIL("Bit[0] sentinel (always-1 in SK)", "=0 means securekernel NOT providing data; KVM VTL1 path broken");
    else
        PASS("Bit[0] sentinel = 1 (securekernel provided real data)");

    // Output bits after ntoskrnl non-linear remap from SK bits.
    // SK bit → output bit mapping confirmed from securekernel + ntoskrnl disassembly.
    // See VSM_VTL_Speculation_Fields.txt for full documentation.

    // Sentinels (bits 0, 4, 5): always 1 when query succeeds
    printf("  sentinel always-1              [0] SK0:  hardcoded         : %s\n",
           (secspec >> 0) & 1 ? "YES" : "NO");

    // KPTI state (bits 1-3)
    printf("  VTL1 KPTI active               [1] SK1:  SkiKvaShadow!=0  : %s\n",
           (secspec >> 1) & 1 ? "YES" : "NO");
    printf("  VTL1 KPTI no-PCID              [2] SK2:  SkiKvaShadowMode==2 : %s\n",
           (secspec >> 2) & 1 ? "YES" : "NO");
    printf("  VTL1 KPTI + PCID               [3] SK3:  SkiKvaShadowMode==1 : %s\n",
           (secspec >> 3) & 1 ? "YES" : "NO");

    // Sentinels (bits 4, 5)
    printf("  sentinel always-1              [4] SK17: or edx,20000h    : %s\n",
           (secspec >> 4) & 1 ? "YES" : "NO");
    printf("  sentinel always-1              [5] SK16: or ecx,200h+shl7 : %s\n",
           (secspec >> 5) & 1 ? "YES" : "NO");

    // SkiSpeculationFeatures-derived bits (bits 6-11, 14-15)
    printf("  !SF[16]&&!SF[17] (fallback IBRS)[6] SK8:  SkiSpecFeatures  : %s\n",
           (secspec >> 6) & 1 ? "YES" : "NO");
    printf("  SF[4] STIBP present            [7] SK9:  SkiSpecFeatures  : %s\n",
           (secspec >> 7) & 1 ? "YES" : "NO");
    printf("  SF[0] IBRS present             [8] SK10: SkiSpecFeatures  : %s\n",
           (secspec >> 8) & 1 ? "YES" : "NO");
    printf("  SF[6] eIBRS / IBRS_ALL         [9] SK13: SkiSpecFeatures  : %s\n",
           (secspec >> 9) & 1 ? "YES" : "NO");
    printf("  SF[7] SSBD available          [10] SK14: SkiSpecFeatures  : %s\n",
           (secspec >> 10) & 1 ? "YES" : "NO");
    printf("  NOT SF[8] (CPU needs SSBD)    [11] SK15: !SkiSpecFeatures[8] : %s\n",
           (secspec >> 11) & 1 ? "YES" : "NO");

    // Per-CPU gs:0xAB0 boundary enforcement (bits 12-13)
    printf("  gs:0xAB0[1] IBPB on VTL exit  [12] SK11: boundary enforce : %s\n",
           (secspec >> 12) & 1 ? "YES" : "NO");
    printf("  gs:0xAB0[2] IBPB on VTL entry [13] SK12: boundary enforce : %s\n",
           (secspec >> 13) & 1 ? "YES" : "NO");

    // Combined capability bits (bits 14-15)
    printf("  SF[9]||SF[13] (eIBRS/BHB ret) [14] SK18: SkiSpecFeatures  : %s\n",
           (secspec >> 14) & 1 ? "YES" : "NO");
    printf("  SF[12] IBPB suppressed        [15] SK19: SkiSpecFeatures  : %s\n",
           (secspec >> 15) & 1 ? "YES" : "NO");

    // Sentinel integrity check
    if (((secspec >> 0) & 1) && ((secspec >> 4) & 1) && ((secspec >> 5) & 1))
        PASS("All 3 sentinels set (bits 0,4,5) -- query pipeline intact");
    else if ((secspec >> 0) & 1)
        WARN("Sentinel check", "Bit 0 set but bits 4 or 5 missing -- partial SK response or remap error");

    // KPTI assessment
    if ((secspec & 1) && ((secspec >> 1) & 1))
        PASS("VTL1 running KPTI (securekernel has its own KVA shadow, separate from VTL0)");
    if ((secspec & 1) && !((secspec >> 1) & 1))
        INFO("VTL1 KPTI", "VTL1 not running KPTI (CPU not Meltdown-vulnerable, or KPTI disabled in SK)");

    // Boundary enforcement assessment
    if ((secspec >> 13) & 1)
        PASS("VTL1 IBPB on entry active (gs:0xAB0[2]) -- VTL0 branch poisoning blocked");
    else if ((secspec & 1) && !((secspec >> 13) & 1) && !((secspec >> 15) & 1))
        WARN("VTL1 IBPB entry", "Not active and IBPB not suppressed -- potential Spectre v2 attack surface");

    if ((secspec >> 12) & 1)
        PASS("VTL1 IBPB on exit active (gs:0xAB0[1]) -- VTL1 branch training doesn't leak to VTL0");
}

// ---------------------------------------------------------------------------
// Section 9 -- Synthetic MSRs (requires VsmTest.sys companion driver)
//
// KVM requirements tested here:
//   - HV_X64_MSR_VSM_PARTITION_STATUS (0x400000E3): EnabledVtlSet must have
//     bit 1 set when VTL1 is running, MbecEnabled when MBEC is on
//   - HV_X64_MSR_VSM_VP_STATUS (0x400000E4): ActiveVtl, EnabledVtlSet per VP
//   - HV_X64_MSR_VSM_PARTITION_CONFIG (0x400000D4): written by securekernel
//     to configure VTL policy; KVM must handle write+read correctly
// ---------------------------------------------------------------------------

#define VSMT_DEVICE  L"\\\\.\\VsmTest"
#define VSMT_IOCTL_VSM_STATE  CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    UINT64   PartitionStatus;  // 0x400000E3
    UINT64   VpStatus;         // 0x400000E4
    UINT64   PartitionConfig;  // 0x400000D4
    UINT64   GuestOsId;        // 0x40000000
    UINT64   HypercallPage;    // 0x40000001
    UINT64   VpIndex;          // 0x40000002
    NTSTATUS QueryStatus;
} VSMT_VSM_STATE;

static void sect9_synthetic_msrs()
{
    section(9, "Synthetic MSRs (requires VsmTest.sys)");

    HANDLE h = CreateFileW(VSMT_DEVICE,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        SKIP("Synthetic MSR tests", "VsmTest.sys not loaded (see vsm_ktest.c)");
        printf("\n  MSRs that KVM must implement for VSM:\n");
        printf("  0x400000E3  HV_X64_MSR_VSM_PARTITION_STATUS\n");
        printf("    bits[15:0]  EnabledVtlSet  -- bit 1 must be set when VTL1 running\n");
        printf("    bit 16      MbecEnabled    -- set when MBEC active for partition\n");
        printf("    bit 17      DmaProtActive  -- set when DMA protection enforced\n");
        printf("  0x400000E4  HV_X64_MSR_VSM_VP_STATUS\n");
        printf("    bits[3:0]   ActiveVtl      -- current VTL (should be 0 in VTL0)\n");
        printf("    bit 4       ActiveMbec     -- MBEC for current thread\n");
        printf("    bits[19:8]  EnabledVtlSet  -- VTLs enabled for this VP\n");
        printf("  0x400000D4  HV_X64_MSR_VSM_PARTITION_CONFIG\n");
        printf("    Written by securekernel to set VTL1 policy (DefaultVtlProtectionMask,\n");
        printf("    ZeroMemoryOnReset, DenyLowerVtlStartup, InterceptAcceptance, etc.)\n");
        printf("    KVM must allow write+read and apply the written policy.\n");
        return;
    }

    VSMT_VSM_STATE state = {};
    DWORD br = 0;
    if (!DeviceIoControl(h, VSMT_IOCTL_VSM_STATE, NULL, 0,
                         &state, sizeof(state), &br, NULL)) {
        FAIL("VsmTest.sys IOCTL", "DeviceIoControl failed");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    if (!NT_SUCCESS(state.QueryStatus)) {
        printf("  Driver QueryStatus: 0x%08X\n", state.QueryStatus);
        FAIL("MSR read", "Driver failed to read VSM MSRs -- KVM may not implement them (GP fault on rdmsr)");
        return;
    }

    // Parse and display partition status
    HV_VSM_PARTITION_STATUS ps; ps.raw = state.PartitionStatus;
    HV_VSM_VP_STATUS        vs; vs.raw = state.VpStatus;

    printf("  HV_X64_MSR_VSM_PARTITION_STATUS (0x400000E3): 0x%016llX\n",
           state.PartitionStatus);
    printf("    EnabledVtlSet  : 0x%04llX", ps.EnabledVtlSet);
    if (ps.EnabledVtlSet & 1) printf(" [VTL0]");
    if (ps.EnabledVtlSet & 2) printf(" [VTL1]");
    if (ps.EnabledVtlSet & 4) printf(" [VTL2]");
    printf("\n");
    printf("    MbecEnabled    : %s\n", ps.MbecEnabled ? "YES" : "NO");
    printf("    DmaProtActive  : %s\n", ps.DmaProtectionActive ? "YES" : "NO");

    printf("  HV_X64_MSR_VSM_VP_STATUS (0x400000E4): 0x%016llX\n",
           state.VpStatus);
    printf("    ActiveVtl      : %llu  (should be 0 when running in VTL0)\n", vs.ActiveVtl);
    printf("    ActiveMbec     : %s\n", vs.ActiveMbec ? "YES" : "NO");
    printf("    VP EnabledVtls : 0x%04llX\n", vs.EnabledVtlSet);

    printf("  HV_X64_MSR_VSM_PARTITION_CONFIG (0x400000D4): 0x%016llX\n",
           state.PartitionConfig);
    printf("  HV_X64_MSR_GUEST_OS_ID          (0x40000000): 0x%016llX\n", state.GuestOsId);
    printf("  HV_X64_MSR_HYPERCALL            (0x40000001): 0x%016llX\n", state.HypercallPage);
    printf("  HV_X64_MSR_VP_INDEX             (0x40000002): 0x%016llX\n", state.VpIndex);

    // Validate
    if (state.PartitionStatus == 0xFFFFFFFFFFFFFFFFull)
        FAIL("VSM_PARTITION_STATUS", "GP-faulted on rdmsr -- KVM does not implement 0x400000E3");
    else if (ps.EnabledVtlSet & 2)
        PASS("VSM_PARTITION_STATUS: VTL1 in EnabledVtlSet (bit 1)");
    else
        FAIL("VSM_PARTITION_STATUS: VTL1 not in EnabledVtlSet",
             "KVM HvCallEnablePartitionVtl must set this bit");

    if (state.VpStatus == 0xFFFFFFFFFFFFFFFFull)
        FAIL("VSM_VP_STATUS", "GP-faulted on rdmsr -- KVM does not implement 0x400000E4");
    else if (vs.ActiveVtl == 0)
        PASS("VSM_VP_STATUS: ActiveVtl=0 (correct when running in VTL0)");
    else
        WARN("VSM_VP_STATUS: ActiveVtl!=0", "Unexpected VTL for a VTL0 read");

    if (!(state.HypercallPage & 1))
        WARN("HypercallPage", "Enable bit (bit 0) not set -- hypercall page not active");
    else
        PASS("Hypercall page enabled (bit 0)");
}

// ---------------------------------------------------------------------------
// External section runners (vsm_test_intel.cpp, vsm_test_synth.cpp,
// vsm_test_isolation.cpp)
// ---------------------------------------------------------------------------

extern void RunIntelVsmTests(void* NtQSI);
extern void RunSyntheticMsrTests(void* NtQSI);
extern void RunIsolationTests(void* pNtQSI);
extern void RunKvmVsmTests(void* pNtQSI);

// External counters from vsm_test_synth.cpp, vsm_test_isolation.cpp, vsm_test_kvmvsm.cpp
extern int s12_pass, s12_fail, s12_warn;
extern int iso_pass, iso_fail, iso_warn;
extern int kvsm_pass, kvsm_fail, kvsm_warn;

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    printf("VSM Guest-Side Feature Verification\n");
    printf("Each test maps to a specific KVM VSM implementation requirement.\n");
    printf("====================================================================\n\n");

    BOOL elevated = FALSE;
    { HANDLE tok; TOKEN_ELEVATION e; DWORD sz;
      if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
          if (GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &sz))
              elevated = e.TokenIsElevated;
          CloseHandle(tok);
      } }
    printf("Running as: %s\n", elevated ? "Elevated (admin)" : "Standard user");
    printf("Elevation recommended for Section 4 (CG) and Section 9 (MSR driver).\n");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQSI = (PNtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");

    int filter = argc > 1 ? atoi(argv[1]) : 0;  // 0 = all sections
    if (!filter || filter == 1) sect1_vtl_cpuid();
    if (!filter || filter == 2) sect2_vtl_operational(NtQSI);
    if (!filter || filter == 3) sect3_mbec(NtQSI);
    if (!filter || filter == 4) sect4_credential_guard();
    if (!filter || filter == 5) sect5_ium_enclave();
    if (!filter || filter == 6) sect6_gpa_protection(NtQSI);
    if (!filter || filter == 7) sect7_dma_protection(NtQSI);
    if (!filter || filter == 8) sect8_vtl1_speculation(NtQSI);
    if (!filter || filter == 9) sect9_synthetic_msrs();

    // Intel-specific addendum sections (3, 7, 10, 11)
    if (!filter || filter == 10 || filter == 11)
        RunIntelVsmTests(NtQSI);

    // Synthetic MSR, VP register, partition property, CPUID chain (12-15)
    if (!filter || (filter >= 12 && filter <= 15))
        RunSyntheticMsrTests(NtQSI);

    // Isolation, liveness, MBEC empirical, speculation cross-check (16-22)
    if (!filter || (filter >= 16 && filter <= 22))
        RunIsolationTests(NtQSI);

    // KVM VSM implementation verification (23-34)
    if (!filter || (filter >= 23 && filter <= 34))
        RunKvmVsmTests(NtQSI);

    // Combine counters from all modules
    int total_pass = g_pass + s12_pass + iso_pass + kvsm_pass;
    int total_fail = g_fail + s12_fail + iso_fail + kvsm_fail;
    int total_warn = g_warn + s12_warn + iso_warn + kvsm_warn;

    printf("\n====================================================================\n");
    printf("Results: %d PASS  %d FAIL  %d WARN\n", total_pass, total_fail, total_warn);
    printf("====================================================================\n");
    return total_fail > 0 ? 1 : 0;
}
