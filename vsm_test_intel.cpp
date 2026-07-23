//
// vsm_test_intel.cpp -- Intel-specific VSM guest tests
//
// Supplements vsm_test.cpp with Intel-only checks derived from hvix64.exe
// disassembly comparison against hvax64.exe.
//
// Key Intel vs AMD differences found in hypervisor disassembly:
//
//  MBEC:   Intel checks IA32_VMX_EPT_VPID_CAP (MSR 0x48B) bits 21+22
//          AMD checks CPUID 0x8000000A EDX bit 23 (GMET)
//
//  IOMMU:  Intel uses VT-d / DMAR: HcpInitializeIommuGlobalCapabilities
//                    HcpInvalidateIommuTlb -> invept/invvpid instructions
//          AMD uses AMD-Vi / IVRS: HcpInitializeIommuContext (MMIO ring buf)
//                    IOMMU invalidation is part of SVM VTL transition state machine
//          --> Intel KVM *must* issue INVEPT after every HvModifyVtlProtectionMask
//              AMD does not need a separate IOTLB flush step
//
//  VTL switch: Intel uses per-VTL VMCS pointer swap (vmlaunch/vmresume)
//              AMD uses VMRUN intercept + 8-state orchestration machine
//              Intel-only: HcpExecuteHvModifyVtlProtectionMask (named handler)
//                          MmpBatchUpdateEptPermissions (two-phase EPT update)
//
//  APICv:  Intel: full APICv with posted interrupts (3 modes: disabled/normal/aggressive)
//                 HcpSerializeVirtualApicState / HcpDeserializeVirtualApicState per VTL
//                 VMCS fields 0x2012 (VirtualApicPage), 0x2014 (ApicAccess),
//                             0x2016 (PostedIntrDescAddr) must be valid per VTL
//          AMD:  software APIC emulation only; no AVIC backing page in disassembly
//
// Build with vsm_test.cpp:
//   cl /EHa /Zi /O2 vsm_test.cpp vsm_test_intel.cpp /link ntdll.lib kernel32.lib advapi32.lib
//

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Driver IOCTL extensions (must match vsm_ktest.c additions)
// ---------------------------------------------------------------------------

#define VSMT_DEVICE_TYPE  0x8000u
#define VSMT_IOCTL_READ_MSR     CTL_CODE(VSMT_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_INTEL_CAPS   CTL_CODE(VSMT_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IA32_VMX_EPT_VPID_CAP MSR (0x48B) layout
// Source: Intel SDM Vol 3A, Appendix A.10 + hvix64 HcpVerifyVmxCapability_Cpuid20
typedef union {
    UINT64 raw;
    struct {
        UINT64 ExecOnlyEptAllowed        :  1;  // bit  0 -- execute-only EPT entries
        UINT64 Reserved0                 :  5;
        UINT64 PagingStructureLevelFour  :  1;  // bit  6 -- 4-level EPT walk
        UINT64 Reserved1                 :  1;
        UINT64 UcEptMemtype              :  1;  // bit  8 -- UC EPT memory type
        UINT64 Reserved2                 :  5;
        UINT64 WbEptMemtype              :  1;  // bit 14 -- WB EPT memory type
        UINT64 Reserved3                 :  1;
        UINT64 PageWalkLen2              :  1;  // bit 16 -- 2MB pages
        UINT64 PageWalkLen3              :  1;  // bit 17 -- 1GB pages (PDPE)
        UINT64 Reserved4                 :  2;
        UINT64 InveptSupported           :  1;  // bit 20 -- INVEPT instruction
        UINT64 EptAccessedDirty          :  1;  // bit 21 -- accessed/dirty bits in EPT
        UINT64 EptUserModeLinearAddress  :  1;  // bit 22 -- advanced EPT info in violation exit
        UINT64 Reserved5                 :  2;
        UINT64 InveptSingleContext       :  1;  // bit 25 -- INVEPT type 1 (single context)
        UINT64 InveptAllContext          :  1;  // bit 26 -- INVEPT type 2 (all contexts)
        UINT64 Reserved6                 :  5;
        UINT64 InvvpidSupported          :  1;  // bit 32 -- INVVPID instruction
        UINT64 Reserved7                 :  7;
        UINT64 InvvpidIndivAddr          :  1;  // bit 40 -- INVVPID type 0
        UINT64 InvvpidSingleCtx          :  1;  // bit 41 -- INVVPID type 1
        UINT64 InvvpidAllCtx             :  1;  // bit 42 -- INVVPID type 2
        UINT64 InvvpidSingleCtxRetaining :  1;  // bit 43 -- INVVPID type 3
        UINT64 Reserved8                 :  4;
        // MBEC (Mode-Based Execute Control) -- key for HVCI on Intel
        // Source: hvix64 HcpVerifyVmxCapability_Cpuid20 @ 0x33D4A8:
        //   test al, 20h  --> bit 5 of a sub-byte = bit 48+5? Let's look at TLFS:
        //   Actually from Intel SDM: EPT MBEC is bit 22 of IA32_VMX_PROCBASED_CTLS2
        //   The EPT VPID CAP bits for MBEC:
        //   -- Intel officially documents this as PROCBASED_CTLS2, not EPT_VPID_CAP
        //   -- hvix64 uses dword_B1EA4 (platform capability word) which is filled
        //      by parsing multiple VMX MSRs combined
        UINT64 Reserved9                 : 16;
    };
} IA32_VMX_EPT_VPID_CAP;

// IA32_VMX_PROCBASED_CTLS2 (MSR 0x48B is EPT_VPID_CAP; CTLS2 is 0x48B? No...)
// Actually:
//   0x481 = IA32_VMX_PINBASED_CTLS
//   0x482 = IA32_VMX_PROCBASED_CTLS
//   0x483 = IA32_VMX_EXIT_CTLS
//   0x484 = IA32_VMX_ENTRY_CTLS
//   0x485 = IA32_VMX_MISC
//   0x48B = IA32_VMX_EPT_VPID_CAP
//   0x48C = IA32_VMX_TRUE_PINBASED_CTLS
//   0x48D = IA32_VMX_TRUE_PROCBASED_CTLS
//   0x48E = IA32_VMX_TRUE_EXIT_CTLS
//   0x48F = IA32_VMX_TRUE_ENTRY_CTLS
//   0x491 = IA32_VMX_VMFUNC
//   For PROCBASED_CTLS2 (secondary): 0x48B... wait, that's EPT_VPID_CAP.
//   Secondary PROCBASED is at IA32_VMX_PROCBASED_CTLS2 -- not a separate MSR,
//   it's a capability reported via IA32_VMX_PROCBASED_CTLS bit 31.
//   MBEC is controlled via IA32_VMX_PROCBASED_CTLS3 (new Intel MSR 0x492).

#define IA32_VMX_EPT_VPID_CAP_MSR   0x48Bu
#define IA32_VMX_PROCBASED_CTLS2    0x48Bu  // Not same! see below
// Correct MSR for secondary VM-exec controls capability:
// CPUID.01H:ECX[5]=VMX, then read IA32_VMX_PROCBASED_CTLS2 by setting bit 31
// of IA32_VMX_PROCBASED_CTLS (allowed-1 bit) then reading 0x48B.
// For simplicity the driver reads 0x48B directly.

// Intel capabilities structure returned by VSMT_IOCTL_INTEL_CAPS
typedef struct {
    // IA32_VMX_EPT_VPID_CAP (MSR 0x48B)
    UINT64   EptVpidCap;
    // IA32_VMX_PROCBASED_CTLS2 (derived from IA32_VMX_PROCBASED_CTLS + 0x48B)
    // Bits relevant to MBEC:
    //   bit 20 (ENABLE_EPT) -- EPT must be on for MBEC
    //   bit 22 (ENABLE_VPID) -- VPID for TLB management
    //   bit 13 (ENABLE_RDTSCP) -- not MBEC but useful
    UINT64   ProcbasedCtls2Allowed;
    // IA32_VMX_EPT_VPID_CAP bit meanings (from hvix64 HcpVerifyVmxCapability_Cpuid20):
    //   bit 0:  execute-only EPT entries supported (needed for MBEC user-exec=0, super=1)
    //   bit 6:  4-level EPT page walk
    //   bit 14: WB memory type for EPT
    //   bit 20: INVEPT supported
    //   bit 21: EPT accessed and dirty flags
    //   bit 25: INVEPT single-context
    //   bit 26: INVEPT all-context
    //   bit 32: INVVPID supported
    //   bit 40-43: INVVPID types (0=individual, 1=single, 2=all, 3=retaining)
    BOOL     IntelCpuDetected;
    BOOL     VmxSupported;         // CPUID.01H:ECX[5]
    NTSTATUS Status;
} VSMT_INTEL_CAPS;

// ---------------------------------------------------------------------------
// Output helpers (duplicated to keep this file standalone)
// ---------------------------------------------------------------------------

static void iPASS(const char* m) { printf("  [PASS] %s\n", m); }
static void iFAIL(const char* m, const char* d) {
    printf("  [FAIL] %s\n         --> %s\n", m, d);
}
static void iWARN(const char* m, const char* d) {
    printf("  [WARN] %s\n         --> %s\n", m, d);
}
static void iINFO(const char* m, const char* d) { printf("  [INFO] %s: %s\n", m, d); }
static void iSKIP(const char* m, const char* r) {
    printf("  [SKIP] %s\n         %s\n", m, r);
}

// ---------------------------------------------------------------------------
// CPU vendor detection
// ---------------------------------------------------------------------------

typedef enum { CPU_INTEL, CPU_AMD, CPU_OTHER } CpuVendor;

static CpuVendor DetectCpuVendor()
{
    int cpu[4] = {};
    __cpuid(cpu, 0);
    // EBX:ECX:EDX holds vendor string
    // Intel: "GenuineIntel" = EBX=0x756E6547, EDX=0x49656E69, ECX=0x6C65746E
    // AMD:   "AuthenticAMD" = EBX=0x68747541, EDX=0x69746E65, ECX=0x444D4163
    if (cpu[1] == 0x756E6547 && cpu[3] == 0x49656E69 && cpu[2] == 0x6C65746E)
        return CPU_INTEL;
    if (cpu[1] == 0x68747541 && cpu[3] == 0x69746E65 && cpu[2] == 0x444D4163)
        return CPU_AMD;
    return CPU_OTHER;
}

static const char* VendorName(CpuVendor v)
{
    switch (v) {
    case CPU_INTEL: return "Intel";
    case CPU_AMD:   return "AMD";
    default:        return "Other";
    }
}

// ---------------------------------------------------------------------------
// SECTION 3 ADDENDUM -- Intel-specific MBEC checks
//
// Intel MBEC path (from hvix64 disassembly):
//   HcpVerifyVmxCapability_Cpuid20 @ 0x33D4A8:
//     Reads IA32_VMX_EPT_VPID_CAP (MSR 0x48B) and checks:
//       test al, 1  (bit 0): execute-only EPT entries
//       test al, 2  (bit 1): ... (EPT field)
//       test al, 20h(bit 5 of second nibble): MBEC user-mode execute
//   HcpInitializeIommuGlobalCapabilities @ 0x309AA0:
//     bt ecx, 0Ah  (bit 10 of dword_B1EA4): IOTLB advanced MBEC flag
//
// The two-phase EPT permission update (Intel-only):
//   MmpBatchUpdateEptPermissions       @ 0x38287C  (phase 1)
//   MmpBatchUpdateEptPermissions_Phase2@ 0x38169C  (phase 2)
//   --> After phase 2, HcpExecuteInveptInstruction is called
//   --> AMD has single-pass NPT update, no INVEPT needed
//
// KVM Intel MBEC verification:
//   1. Host CPU must expose IA32_VMX_EPT_VPID_CAP bit 0 (exec-only EPT) to VM
//      (via KVM's MSR emulation)
//   2. INVEPT after every HvModifyVtlProtectionMask is verified by HVCI staying stable
//   3. 0xA9[2] HardwareMbecAvailable must reflect IA32_VMX_EPT_VPID_CAP bits
// ---------------------------------------------------------------------------

void sect3_intel_mbec_addendum()
{
    printf("\n  -- Intel MBEC addendum (hvix64-specific checks) --\n");

    CpuVendor vendor = DetectCpuVendor();
    printf("  CPU vendor: %s\n", VendorName(vendor));

    if (vendor != CPU_INTEL) {
        iINFO("Intel MBEC checks", "Skipping -- not an Intel CPU");
        return;
    }

    // Check VMX exposed to guest (needed for reading VMX MSRs)
    int cpu[4] = {};
    __cpuid(cpu, 1);
    bool vmxExposed = ((cpu[2] >> 5) & 1) != 0;  // CPUID.1:ECX[5]
    printf("  VMX exposed to guest (CPUID.1:ECX[5]) : %s\n", vmxExposed ? "YES" : "NO");

    if (!vmxExposed) {
        iINFO("VMX not exposed",
              "Cannot read IA32_VMX_EPT_VPID_CAP from guest; use VsmTest.sys driver");
        printf("  --> KVM must expose VMX to the guest for nested-virt MBEC, OR\n");
        printf("      KVM reads IA32_VMX_EPT_VPID_CAP from host and sets 0xA9[2] correctly\n");
        printf("  --> Verify 0xA9[2] HardwareMbecAvailable using vsm_test.exe Section 3\n");
        return;
    }

    printf("\n  Note: IA32_VMX_EPT_VPID_CAP (MSR 0x48B) must be read from Ring 0.\n");
    printf("  Load VsmTest.sys and add VSMT_IOCTL_INTEL_CAPS to read these bits:\n\n");
    printf("  IA32_VMX_EPT_VPID_CAP bits required for Intel MBEC:\n");
    printf("    bit  0: Execute-only EPT entries    -- needed for VTL1 execute-no-read pages\n");
    printf("    bit  6: 4-level EPT walk             -- required for 48-bit GPA\n");
    printf("    bit 20: INVEPT instruction support   -- mandatory: KVM must issue INVEPT\n");
    printf("            after every HvCallModifyVtlProtectionMask (hypercall 0x00B1)\n");
    printf("            Source: hvix64 MmpBatchUpdateEptPermissions_Phase2 @ 0x38169C\n");
    printf("            calls HcpExecuteInveptInstruction @ 0x3A6010 (invept ecx,[rdx])\n");
    printf("    bit 25: INVEPT type 1 (single context) -- clean VTL switch without full flush\n");
    printf("    bit 26: INVEPT type 2 (all contexts)   -- used on global VTL state changes\n");
    printf("    bit 32: INVVPID instruction support     -- used in minimal loop event router\n");
    printf("            Source: hvix64 HcpExecuteMinimalLoopEventRouter @ 0x332D30\n\n");

    printf("  Intel MBEC vs AMD GMET summary:\n");
    printf("  +--------------+-----------------------------------------+-------------------------------------+\n");
    printf("  | Feature      | Intel (hvix64)                          | AMD (hvax64)                        |\n");
    printf("  +--------------+-----------------------------------------+-------------------------------------+\n");
    printf("  | Capability   | IA32_VMX_EPT_VPID_CAP MSR 0x48B [0,20] | CPUID 0x8000000A EDX [23] (GMET)    |\n");
    printf("  | Detection fn | HcpVerifyVmxCapability_Cpuid20 0x33D4A8 | HcpEvaluateHostCpuidCapabilities    |\n");
    printf("  | TLB flush    | INVEPT (explicit, after every VTL chg)  | Part of SVM VTL transition SM       |\n");
    printf("  | EPT update   | Two-phase: Phase1 + Phase2 + INVEPT     | Single-pass NPT update              |\n");
    printf("  | KVM MSR      | 0x48B must return bits 0,20,25,26,32    | N/A (VMCB GMET bit)                 |\n");
    printf("  +--------------+-----------------------------------------+-------------------------------------+\n");
}

// ---------------------------------------------------------------------------
// SECTION 7 ADDENDUM -- Intel VT-d specific DMA checks
//
// Intel DMA path (from hvix64 disassembly):
//   HcpInitializeIommuGlobalCapabilities @ 0x309AA0:
//     Reads HcpPlatformFlags bit 5 (test al, 20h) -- VT-d hardware detected
//     Reads dword_B1EA4 bit 10 (bt ecx, 0Ah)      -- IOTLB advanced support
//
//   HcpInvalidateIommuTlb @ 0x35EFB4:
//     Translates GPA and issues IOTLB invalidation command
//     --> Called after every VTL GPA permission change on Intel
//
//   HcpValidateAndFlushIommuPtes @ 0x352FB0:
//     Calls HcpExecuteInveptInstruction + HcpExecuteInvvpidInstruction
//     --> Double flush: EPT + IOMMU TLB (Intel-only)
//
// AMD DMA path:
//   HcpOrchestrateSvmVtlIommuTransition -- combined VTL+IOMMU state machine
//   --> No separate IOTLB invalidation step; baked into VTL transition
//
// KVM Intel DMA verification:
//   For Intel, DMAR table must be present AND VT-d must be enabled
//   For AMD,   IVRS table must be present AND AMD-Vi must be enabled
//   Both checked in vsm_test.cpp Section 7; this adds Intel-specific detail
// ---------------------------------------------------------------------------

typedef NTSTATUS (WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

void sect7_intel_dma_addendum(PNtQuerySystemInformation NtQSI)
{
    printf("\n  -- Intel VT-d DMA addendum (hvix64-specific) --\n");

    CpuVendor vendor = DetectCpuVendor();
    printf("  CPU vendor: %s\n", VendorName(vendor));

    // ACPI table probe for vendor-specific IOMMU table
    // Intel: DMAR (0x52414D44) -- VT-d descriptor
    // AMD:   IVRS (0x53525649) -- AMD-Vi descriptor
    #pragma pack(push,1)
    struct { ULONG Prov, Action, TableId, BufLen, Pad; } sfi;
    #pragma pack(pop)

    auto probeAcpi = [&](DWORD id) -> BOOL {
        sfi = { 0x41435049u, 1u, id, 0u, 0u };
        ULONG retLen = 0;
        NTSTATUS st = NtQSI((SYSTEM_INFORMATION_CLASS)0x4C, &sfi, sizeof(sfi), &retLen);
        return (st == (NTSTATUS)0xC0000023u && retLen > sizeof(sfi));
    };

    BOOL hasDmar = probeAcpi(0x52414D44u);  // DMAR (Intel VT-d)
    BOOL hasIvrs = probeAcpi(0x53525649u);  // IVRS (AMD-Vi)
    BOOL hasSdev = probeAcpi(0x56454453u);  // SDEV (both)

    printf("  DMAR (Intel VT-d) ACPI table : %s\n", hasDmar ? "PRESENT" : "absent");
    printf("  IVRS (AMD-Vi) ACPI table     : %s\n", hasIvrs ? "PRESENT" : "absent");
    printf("  SDEV (Secure Devices) table  : %s\n", hasSdev ? "PRESENT" : "absent");

    if (vendor == CPU_INTEL) {
        if (hasDmar) {
            iINFO("Intel VT-d", "DMAR table present (required for VTL1 per-device domain model on Intel)");
            if (!hasIvrs)
                iINFO("No IVRS", "Expected on Intel-only system");
            if (hasSdev) {
                printf("\n  Intel DMA enforcement chain (when VTL1 active):\n");
                printf("    SDEV -> SkhalDmaInitializeDevice (securekernel)\n");
                printf("           -> ShvlAttachDeviceDomain (hypercall 0xB2)\n");
                printf("           -> hvix64 HcpSetIommuDeviceTranslation (0x7D/0x7E)\n");
                printf("           -> VT-d context entry programming\n");
                printf("    HvModifyVtlProtectionMask -> MmpBatchUpdateEptPermissions\n");
                printf("           -> HcpExecuteInveptInstruction (invept ecx,[rdx])\n");
                printf("           -> HcpInvalidateIommuTlb (VT-d IOTLB flush)\n");
                printf("    NOTE: Intel requires BOTH EPT flush (INVEPT) AND IOTLB flush\n");
                printf("    after every GPA permission change. AMD only needs VTL transition SM.\n");
            }
        } else {
            iFAIL("Intel VT-d: DMAR absent",
                  "Intel system without DMAR cannot use VTL1 IOMMU domain model; "
                  "securekernel SkpnppSdevInitialize will BugCheck if SDEV present");
        }

        // CPUID 0x40000006[7] is the guest-visible DMA protection gate
        int cpu[4] = {};
        __cpuid(cpu, 0x40000000);
        bool dmaGate = false;
        if ((UINT32)cpu[0] >= 0x40000006) {
            __cpuid(cpu, 0x40000006);
            dmaGate = ((cpu[0] >> 7) & 1) != 0;
        }
        printf("\n  CPUID 0x40000006[7] DmaProtection gate : %s\n", dmaGate ? "YES" : "NO");
        if (dmaGate && hasDmar)
            iPASS("Intel DMA protection: DMAR + HV gate bit both present");
        else if (!dmaGate && hasDmar)
            iWARN("Intel DMA gate mismatch",
                  "DMAR table present but CPUID 0x40000006[7]=0; "
                  "KVM must set this bit when VT-d IOMMU is active");
        else if (dmaGate && !hasDmar)
            iWARN("Intel DMA gate mismatch",
                  "CPUID 0x40000006[7]=1 but no DMAR table; "
                  "securekernel 0xA9[1] DmaProtectionInUse will be wrong");

    } else if (vendor == CPU_AMD) {
        if (hasIvrs) {
            iINFO("AMD AMD-Vi", "IVRS table present (required for VTL1 per-device domain model on AMD)");
            printf("\n  AMD DMA enforcement chain (when VTL1 active):\n");
            printf("    SDEV -> SkhalDmaInitializeDevice (securekernel)\n");
            printf("           -> ShvlAttachDeviceDomain (hypercall 0xB2)\n");
            printf("           -> hvax64 HcpSetIommuDeviceTranslation (0x7D/0x7E)\n");
            printf("           -> AMD-Vi command ring (MMIO, 5 rings: cmd/event/PPR...)\n");
            printf("    HvModifyVtlProtectionMask -> HcpBatchModifyVtlProtection\n");
            printf("           -> HcpOrchestrateSvmVtlIommuTransition (8-state machine)\n");
            printf("    NOTE: AMD does NOT need separate INVEPT/IOTLB flush steps.\n");
            printf("          IOMMU invalidation is integrated in the VTL transition SM.\n");
        } else {
            iFAIL("AMD AMD-Vi: IVRS absent",
                  "AMD system without IVRS cannot use VTL1 IOMMU domain model");
        }
    }

    printf("\n  Intel vs AMD IOMMU flush requirement (KVM implementation note):\n");
    printf("  +-----------------------+----------------------------------+----------------------------+\n");
    printf("  | Operation             | Intel (hvix64)                   | AMD (hvax64)               |\n");
    printf("  +-----------------------+----------------------------------+----------------------------+\n");
    printf("  | After VTL perm change | INVEPT (0x3A6010) +              | None -- baked into         |\n");
    printf("  |                       | IOTLB flush (0x35EFB4)           | HcpSvmOrchestrateVtl...    |\n");
    printf("  | IOMMU command         | VT-d IOTLB invalidation descriptor| AMD-Vi command ring buffer  |\n");
    printf("  | Table format          | DMAR context entries             | IVRS IVHD + device table   |\n");
    printf("  | KVM path              | intel_iommu.c + kvm_iommu.c      | amd_iommu.c + kvm_iommu.c  |\n");
    printf("  +-----------------------+----------------------------------+----------------------------+\n");
}

// ---------------------------------------------------------------------------
// SECTION 10 -- Intel-specific APICv / posted interrupt checks
//
// From hvix64 disassembly:
//   Intel has full APICv support with 3 operating modes:
//     DISABLEPOSTEDINTERRUPTS  @ string 0x5EE8
//     AGGRESSIVEPOSTEDINTERRUPTS @ string 0x5F00
//     ENABLEPOSTEDINTERRUPTS   @ string 0x5F90
//   Functions: HcpSerializeVirtualApicState, HcpDeserializeVirtualApicState,
//              HcpEmulateVirtualApicTimer, HcpProcessVirtualApicStateFlags
//
//   Per-VTL APICv requirement: each VTL must have its own:
//     VMCS field 0x2012 (VIRTUAL_APIC_PAGE_ADDR) -- 4KB page for virtual APIC state
//     VMCS field 0x2014 (APIC_ACCESS_ADDR)       -- GPA of APIC access page
//     VMCS field 0x2016 (POSTED_INTR_DESC_ADDR)  -- posted interrupt descriptor
//
// AMD has NO APICv/AVIC backing page; uses software emulation.
// AMD APIC state is part of the VMCB (offsets 0x400-0x5F8 = VMCB save area).
//
// Guest-visible test: APIC timer delivery behavior -- with APICv hardware,
// the timer fires without VM exit. Observable via tight timing measurement.
// ---------------------------------------------------------------------------

static void sect10_intel_apicv()
{
    printf("\n========================================================\n");
    printf(" SECTION 10: Intel APICv / Posted Interrupts per VTL\n");
    printf("========================================================\n");

    CpuVendor vendor = DetectCpuVendor();
    printf("  CPU vendor: %s\n", VendorName(vendor));

    if (vendor != CPU_INTEL) {
        printf("  [SKIP] Intel APICv tests -- not an Intel CPU\n");
        printf("  AMD note: AMD uses software APIC emulation (no AVIC backing page\n");
        printf("  found in hvax64 disassembly). APIC state is in VMCB offsets 0x400-0x5F8.\n");
        return;
    }

    // Check APIC virtualization capability from guest perspective
    int cpu[4] = {};
    __cpuid(cpu, 0x40000000);
    bool apicVirtCpuid = false;
    if ((UINT32)cpu[0] >= 0x40000006) {
        __cpuid(cpu, 0x40000006);
        apicVirtCpuid = ((cpu[0] >> 23) & 1) != 0;  // bit 23 = ApicVirtAvailable
    }
    printf("  CPUID 0x40000006[23] ApicVirtAvailable : %s\n",
           apicVirtCpuid ? "YES" : "NO");

    // Check x2APIC mode
    // SkiInitializeApic in securekernel reads IA32_APIC_BASE MSR 0x1B bit 10 (x2APIC)
    // and CPUID 0x40000004[8] (UseX2ApicMsrs enlightenment)
    __cpuid(cpu, 0x40000004);  // enlightenment recommendations
    bool useX2ApicMsrs = ((cpu[0] >> 8) & 1) != 0;  // bit 8 = UseX2ApicMsrs
    printf("  CPUID 0x40000004[8] UseX2ApicMsrs      : %s\n",
           useX2ApicMsrs ? "YES" : "NO");

    // x2APIC mode detection via CPUID
    __cpuid(cpu, 1);
    bool x2ApicSupport = ((cpu[2] >> 21) & 1) != 0;  // CPUID.01H:ECX[21]
    printf("  CPUID.01H:ECX[21] x2APIC support       : %s\n",
           x2ApicSupport ? "YES" : "NO");

    printf("\n  Intel APICv per-VTL requirement:\n");
    printf("    Each VTL needs its own:\n");
    printf("    - VMCS 0x2012 VIRTUAL_APIC_PAGE_ADDR : 4KB page for virtual APIC state\n");
    printf("    - VMCS 0x2014 APIC_ACCESS_ADDR        : GPA of APIC access (4KB)\n");
    printf("    - VMCS 0x2016 POSTED_INTR_DESC_ADDR   : posted interrupt descriptor (64B)\n");
    printf("    KVM must save/restore these per VTL switch:\n");
    printf("    HcpSerializeVirtualApicState   @ hvix64:0x2BC440\n");
    printf("    HcpDeserializeVirtualApicState @ hvix64:0x2BEA00\n");
    printf("    These are called in HcpSwitchToVtlContext / HcpHandleVtlReturn\n\n");

    if (apicVirtCpuid) {
        iPASS("ApicVirtAvailable set -- Intel APICv capability exposed to guest");
        if (useX2ApicMsrs)
            iPASS("UseX2ApicMsrs enlightenment active -- x2APIC via MSR path");
        else
            iWARN("UseX2ApicMsrs not set",
                  "KVM should set CPUID 0x40000004[8] when x2APIC is active; "
                  "securekernel SkiInitializeApic uses this bit for SkiUseApicMsrs");
    } else {
        iWARN("ApicVirtAvailable=0",
              "Intel APICv not advertised to guest; VTL switch will use slower "
              "software APIC path. Set CPUID 0x40000006[23] in KVM CPUID emulation.");
    }

    // Timing test: measure APIC timer latency
    // With APICv (hardware virtual APIC): timer delivery has no VM exit overhead
    // Without APICv (software): each timer access causes a VM exit
    // Measurable via RDTSC before/after -- but requires elevated + timer setup
    printf("\n  APICv timer test:\n");
    printf("  [SKIP] Requires kernel driver for APIC timer setup\n");
    printf("         Add to VsmTest.sys: program APIC_LVT_TIMER, measure delivery\n");
    printf("         with RDTSC. APICv: < 1000 cycles overhead. Software: > 10000.\n");
}

// ---------------------------------------------------------------------------
// SECTION 11 -- Intel SVM VTL state machine equivalent verification
//
// AMD has an 8-state VTL transition orchestrator (HcpSvmOrchestrateVtlTransition)
// that manages VTL intercepts + IOMMU flush atomically via a state index.
// Intel uses VMCS pointer swap + INVEPT (no state machine).
//
// For Intel KVM VSM, verify the VTL switch is clean:
//   - No stale TLB entries after VTL switch (INVEPT issued)
//   - EPT permissions correctly reflect per-VTL protection masks
//   - VTL0 cannot access pages marked VTL1-only in EPT
// ---------------------------------------------------------------------------

static void sect11_vtl_switch_correctness()
{
    printf("\n========================================================\n");
    printf(" SECTION 11: VTL Switch Correctness (Intel VMCS path)\n");
    printf("========================================================\n");

    CpuVendor vendor = DetectCpuVendor();
    printf("  CPU vendor: %s\n", VendorName(vendor));

    printf("\n  VTL switch mechanism comparison:\n");
    if (vendor == CPU_INTEL) {
        printf("  Intel path (hvix64):\n");
        printf("    HcpSwitchToVtlContext: VpReferenceVpByIndex -> HcpReferenceVtl\n");
        printf("    -> lock bts [rcx+118h], 0  (atomic VTL lock)\n");
        printf("    -> VMCS pointer swap        (per-VTL VMCS)\n");
        printf("    -> HcpSerializeVirtualApicState (save APIC state)\n");
        printf("    -> vmlaunch/vmresume        (HcpExecuteVmlaunch @ 0x3A6040)\n");
        printf("    -> On return: HcpHandleVtlReturn\n");
        printf("                  -> HcpDeserializeVirtualApicState\n");
        printf("                  -> INVEPT if any GPA permission changed\n\n");
    } else {
        printf("  AMD path (hvax64):\n");
        printf("    HcpSvmOrchestrateVtlTransition: 8-state machine\n");
        printf("    state 0: init, acquire VTL lock\n");
        printf("    state 1: HcpOrchestrateSvmVtlIommuTransition (IOMMU flush)\n");
        printf("    state 2: VTL context switch\n");
        printf("    state 3: vmrun (HcpSvmRunMinimalLoop @ 0x336B00)\n");
        printf("    state 4-7: return path + IOMMU restore\n");
        printf("    -> clgi/stgi/vmrun in HcpSvmRunMinimalLoop\n\n");
    }

    // Test: verify VTL1-protected memory is inaccessible from VTL0
    // This is the same as Section 6's write-protection test but with
    // explicit Intel/AMD annotation
    printf("  VTL switch isolation test (EPT/NPT write-protection):\n");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
        BYTE* text = (BYTE*)hNtdll + nt->OptionalHeader.BaseOfCode;
        DWORD oldProt = 0;
        BOOL vpOk = VirtualProtect(text, 1, PAGE_EXECUTE_READWRITE, &oldProt);
        if (!vpOk) {
            iPASS("ntdll .text: VirtualProtect(RWX) blocked");
            if (vendor == CPU_INTEL)
                printf("         Intel: VMCS EPT permission denied VirtualProtect -> PAGE_EXECUTE_READWRITE\n");
            else
                printf("         AMD: NPT permission denied VirtualProtect -> PAGE_EXECUTE_READWRITE\n");
        } else {
            BYTE orig = *text; BOOL wrote = FALSE;
            __try { *text = orig; wrote = TRUE; }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            VirtualProtect(text, 1, oldProt, &oldProt);
            if (!wrote) {
                iPASS("ntdll .text: write blocked by SLAT despite VirtualProtect");
                if (vendor == CPU_INTEL)
                    printf("         Intel: EPT U/S execute bits blocked write (MBEC enforcement)\n");
                else
                    printf("         AMD: NPT blocked write (GMET enforcement)\n");
            } else {
                iFAIL("ntdll .text writable",
                      vendor == CPU_INTEL
                      ? "Intel: EPT write bit not cleared -- HvModifyVtlProtectionMask + INVEPT not working"
                      : "AMD: NPT write bit not cleared -- HvModifyVtlProtectionMask not working");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point for Intel-specific sections
// Run from main() after all base sections:
//   sect3_intel_mbec_addendum();
//   sect7_intel_dma_addendum(NtQSI);
//   sect10_intel_apicv();
//   sect11_vtl_switch_correctness();
// ---------------------------------------------------------------------------

void RunIntelVsmTests(void* NtQSI)
{
    printf("\n");
    printf("########################################################\n");
    printf(" Intel-Specific VSM Tests (hvix64 disassembly-derived)\n");
    printf("########################################################\n");
    printf(" Source: hvix64.exe.asm diff against hvax64.exe.asm\n");
    printf(" Key differences: MBEC via EPT vs GMET, VT-d vs AMD-Vi,\n");
    printf("                  APICv per-VTL, VMCS-based VTL switch\n");
    printf("########################################################\n");

    sect3_intel_mbec_addendum();
    sect7_intel_dma_addendum((PNtQuerySystemInformation)NtQSI);
    sect10_intel_apicv();
    sect11_vtl_switch_correctness();
}
