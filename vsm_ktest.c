//
// vsm_ktest.c -- VsmTest.sys companion kernel driver for VSM guest tests
//
// Provides Ring 0 access to synthetic MSRs that vsm_test.exe cannot
// read from user mode.  Also serves as the hook point for future
// hypercall-level tests (direct VMCALL).
//
// Build (from an elevated WDK/SDK command prompt):
//   cd vsm_guest_tests
//   msbuild vsm_ktest.vcxproj /p:Configuration=Release /p:Platform=x64
//
// Or manually:
//   cl /kernel /O2 /GS- /Zi vsm_ktest.c /link /DRIVER /NODEFAULTLIB
//      /ENTRY:DriverEntry /SUBSYSTEM:NATIVE ntoskrnl.lib
//      /OUT:VsmTest.sys
//
// Install and load (test-signed or disable DSE):
//   sc create VsmTest type= kernel start= demand binPath= C:\vsm_guest_tests\VsmTest.sys
//   sc start  VsmTest
//   [run vsm_test.exe]
//   sc stop   VsmTest
//   sc delete VsmTest
//
// IMPORTANT: load with test-signing enabled or HVCI disabled, otherwise
// unsigned kernel code will be blocked by the same HVCI you're testing.
// If HVCI is active, sign the driver with a test certificate.
//

#include <ntddk.h>

// ---------------------------------------------------------------------------
// IOCTL codes (must match vsm_test.cpp)
// ---------------------------------------------------------------------------

#define VSMT_DEVICE_TYPE  0x8000u

#define VSMT_IOCTL_READ_MSR       CTL_CODE(VSMT_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_VSM_STATE      CTL_CODE(VSMT_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_WRITE_MSR      CTL_CODE(VSMT_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_HYPERCALL      CTL_CODE(VSMT_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_INTEL_CAPS     CTL_CODE(VSMT_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_SYNTH_STATE    CTL_CODE(VSMT_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_VPREGISTER     CTL_CODE(VSMT_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VSMT_IOCTL_PARTITION_PROP CTL_CODE(VSMT_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---------------------------------------------------------------------------
// Structures (must match vsm_test.cpp)
// ---------------------------------------------------------------------------

typedef struct {
    ULONG  MsrIndex;
    UINT64 Value;
} VSMT_MSR_IO;

typedef struct {
    UINT64   PartitionStatus;  // HV_X64_MSR_VSM_PARTITION_STATUS (0x400000E3)
    UINT64   VpStatus;         // HV_X64_MSR_VSM_VP_STATUS        (0x400000E4)
    UINT64   PartitionConfig;  // HV_X64_MSR_VSM_PARTITION_CONFIG (0x400000D4)
    UINT64   GuestOsId;        // HV_X64_MSR_GUEST_OS_ID          (0x40000000)
    UINT64   HypercallPage;    // HV_X64_MSR_HYPERCALL            (0x40000001)
    UINT64   VpIndex;          // HV_X64_MSR_VP_INDEX             (0x40000002)
    NTSTATUS QueryStatus;
} VSMT_VSM_STATE;

typedef struct {
    UINT64 CallCode;     // Hyper-V call code (input)
    UINT64 Input;        // Single input QWORD (input)
    UINT64 Output;       // Output QWORD (output, filled by driver)
    UINT64 HvStatus;     // Hypervisor status (output)
} VSMT_HYPERCALL_IO;

// ---------------------------------------------------------------------------
// Synthetic MSR addresses
// ---------------------------------------------------------------------------

#define HV_MSR_GUEST_OS_ID          0x40000000u
#define HV_MSR_HYPERCALL            0x40000001u
#define HV_MSR_VP_INDEX             0x40000002u
#define HV_MSR_VSM_PARTITION_CONFIG 0x400000D4u
#define HV_MSR_VSM_PARTITION_STATUS 0x400000E3u
#define HV_MSR_VSM_VP_STATUS        0x400000E4u

// Sentinel value written to output when the MSR GP-faulted
#define VSMT_MSR_FAULT_SENTINEL 0xFFFFFFFFFFFFFFFFull

// ---------------------------------------------------------------------------
// Safe MSR read -- catches #GP via structured exception handling.
// Returns VSMT_MSR_FAULT_SENTINEL if the MSR is not implemented.
// ---------------------------------------------------------------------------

UINT64 SafeReadMsr(ULONG msr)
{
    UINT64 val = VSMT_MSR_FAULT_SENTINEL;
    __try {
        val = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("VsmTest: rdmsr 0x%X -> #GP (KVM does not implement this MSR)\n", msr));
    }
    return val;
}

// ---------------------------------------------------------------------------
// Safe MSR write
// ---------------------------------------------------------------------------

NTSTATUS SafeWriteMsr(ULONG msr, UINT64 value)
{
    __try {
        __writemsr(msr, value);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("VsmTest: wrmsr 0x%X = 0x%llX -> #GP\n", msr, value));
        return STATUS_UNSUCCESSFUL;
    }
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_VSM_STATE
// Reads the full set of VSM synthetic MSRs and returns them in one struct.
// ---------------------------------------------------------------------------

static NTSTATUS HandleVsmState(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_VSM_STATE))
        return STATUS_BUFFER_TOO_SMALL;

    VSMT_VSM_STATE* s = (VSMT_VSM_STATE*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    // Base MSRs (all KVM hypervisor implementations should have these)
    s->GuestOsId     = SafeReadMsr(HV_MSR_GUEST_OS_ID);
    s->HypercallPage = SafeReadMsr(HV_MSR_HYPERCALL);
    s->VpIndex       = SafeReadMsr(HV_MSR_VP_INDEX);

    // VSM-specific MSRs -- these GP-fault if KVM VSM support is incomplete.
    // The sentinel 0xFFFF...FFFF signals "not implemented" to vsm_test.exe.
    s->PartitionStatus = SafeReadMsr(HV_MSR_VSM_PARTITION_STATUS);
    s->VpStatus        = SafeReadMsr(HV_MSR_VSM_VP_STATUS);
    s->PartitionConfig = SafeReadMsr(HV_MSR_VSM_PARTITION_CONFIG);

    KdPrint(("VsmTest: PARTITION_STATUS=0x%llX  VP_STATUS=0x%llX  PARTITION_CONFIG=0x%llX\n",
             s->PartitionStatus, s->VpStatus, s->PartitionConfig));

    s->QueryStatus = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_VSM_STATE);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_READ_MSR
// Single MSR read -- useful for ad-hoc MSR exploration.
// ---------------------------------------------------------------------------

static NTSTATUS HandleReadMsr(PVOID inBuf, ULONG inLen,
                               PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (inLen  < sizeof(VSMT_MSR_IO)) return STATUS_INVALID_PARAMETER;
    if (outLen < sizeof(VSMT_MSR_IO)) return STATUS_BUFFER_TOO_SMALL;

    VSMT_MSR_IO* io = (VSMT_MSR_IO*)inBuf;
    ((VSMT_MSR_IO*)outBuf)->MsrIndex = io->MsrIndex;
    ((VSMT_MSR_IO*)outBuf)->Value    = SafeReadMsr(io->MsrIndex);

    KdPrint(("VsmTest: ReadMsr 0x%X = 0x%llX\n",
             io->MsrIndex, ((VSMT_MSR_IO*)outBuf)->Value));

    *outInfo = sizeof(VSMT_MSR_IO);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_WRITE_MSR
// Single MSR write -- for testing KVM's handling of writes to synthetic MSRs.
// ---------------------------------------------------------------------------

static NTSTATUS HandleWriteMsr(PVOID inBuf, ULONG inLen, PULONG_PTR outInfo)
{
    if (inLen < sizeof(VSMT_MSR_IO)) return STATUS_INVALID_PARAMETER;
    VSMT_MSR_IO* io = (VSMT_MSR_IO*)inBuf;
    *outInfo = 0;
    return SafeWriteMsr(io->MsrIndex, io->Value);
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_INTEL_CAPS  (Intel-only)
//
// Reads IA32_VMX_EPT_VPID_CAP (MSR 0x48B) and reports EPT MBEC capability.
// Source: hvix64 HcpVerifyVmxCapability_Cpuid20 @ 0x33D4A8 checks this MSR
// for bits that control execute-only EPT, INVEPT, and MBEC enforcement.
//
// Bits of interest for KVM VSM MBEC:
//   bit  0: Execute-only EPT entries -- user-mode execute, no read = MBEC asymmetric
//   bit  6: 4-level EPT page walk (required for 48-bit GPA space)
//   bit 20: INVEPT instruction supported -- MANDATORY for VTL GPA permission changes
//   bit 21: EPT accessed/dirty flag support
//   bit 25: INVEPT single-context (type 1)
//   bit 26: INVEPT all-context (type 2)
//   bit 32: INVVPID supported
//   bit 40-43: INVVPID types
// ---------------------------------------------------------------------------

#define VSMT_IOCTL_INTEL_CAPS  CTL_CODE(VSMT_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IA32_VMX_EPT_VPID_CAP_MSR 0x48Bu
#define IA32_FEATURE_CONTROL_MSR  0x03Au

typedef struct {
    UINT64   EptVpidCap;           // IA32_VMX_EPT_VPID_CAP (0x48B)
    UINT64   FeatureControl;       // IA32_FEATURE_CONTROL (0x03A) -- bit 2 = VMX enabled
    BOOLEAN  IntelCpuDetected;
    BOOLEAN  VmxEnabledInBios;     // IA32_FEATURE_CONTROL bit 2
    BOOLEAN  EptExecOnlySupported; // EptVpidCap bit 0
    BOOLEAN  InveptSupported;      // EptVpidCap bit 20
    BOOLEAN  InveptSingleCtx;      // EptVpidCap bit 25
    BOOLEAN  InveptAllCtx;         // EptVpidCap bit 26
    BOOLEAN  InvvpidSupported;     // EptVpidCap bit 32
    NTSTATUS Status;
} VSMT_INTEL_CAPS;

static NTSTATUS HandleIntelCaps(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_INTEL_CAPS)) return STATUS_BUFFER_TOO_SMALL;

    VSMT_INTEL_CAPS* c = (VSMT_INTEL_CAPS*)outBuf;
    RtlZeroMemory(c, sizeof(*c));

    // Check Intel CPU via CPUID
    int cpuInfo[4] = { 0 };
    UINT32 eax, ebx, ecx, edx;
    //
    // Read vendor ID via CPUID leaf 0
    // We use the assembly stub if available; otherwise inline intrinsic.
    // "GenuineIntel" = EBX=0x756E6547, ECX=0x6C65746E, EDX=0x49656E69
    //
    __cpuid(cpuInfo, 0);
    c->IntelCpuDetected = (cpuInfo[1] == 0x756E6547 &&
                           cpuInfo[2] == 0x6C65746E &&
                           cpuInfo[3] == 0x49656E69);

    // IA32_FEATURE_CONTROL MSR: bit 0 = lock, bit 2 = VMX outside SMX enabled
    c->FeatureControl = SafeReadMsr(IA32_FEATURE_CONTROL_MSR);
    if (c->FeatureControl != VSMT_MSR_FAULT_SENTINEL)
        c->VmxEnabledInBios = (c->FeatureControl & (1u << 2)) != 0;

    // IA32_VMX_EPT_VPID_CAP
    c->EptVpidCap = SafeReadMsr(IA32_VMX_EPT_VPID_CAP_MSR);

    if (c->EptVpidCap != VSMT_MSR_FAULT_SENTINEL) {
        c->EptExecOnlySupported = (c->EptVpidCap & (1ull <<  0)) != 0;
        c->InveptSupported      = (c->EptVpidCap & (1ull << 20)) != 0;
        c->InveptSingleCtx      = (c->EptVpidCap & (1ull << 25)) != 0;
        c->InveptAllCtx         = (c->EptVpidCap & (1ull << 26)) != 0;
        c->InvvpidSupported     = (c->EptVpidCap & (1ull << 32)) != 0;
        KdPrint(("VsmTest: EptVpidCap=0x%llX InveptOk=%d\n",
                 c->EptVpidCap, c->InveptSupported));
    } else {
        KdPrint(("VsmTest: IA32_VMX_EPT_VPID_CAP GP-faulted -- AMD or VMX not exposed\n"));
    }

    c->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_INTEL_CAPS);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_HYPERCALL
//
// Issues a simple (non-rep, non-variable) Hyper-V hypercall from kernel mode.
//
// Uses the standard hypercall ABI:
//   rcx = call code + flags
//   rdx = input parameter (GPA of input page, or fast-call input)
//   r8  = output parameter (GPA of output page, or fast-call output)
//
// For fast hypercalls (bit 16 of call code set), input/output are in
// registers rather than memory pages -- use this for simple VSM probes.
//
// WARNING: Issuing arbitrary hypercalls from a test driver can destabilize
// the VM.  Use only known-safe read-only or idempotent calls.
//
// Safe calls for testing:
//   0x0002  HvCallGetPartitionId    -- returns partition ID (read-only)
//   0x007B  HvCallGetDmaGuardStatus -- returns DMA guard enabled flag
//   0x0082  HvCallRegisterDeviceId  -- registration test (careful)
// ---------------------------------------------------------------------------

#pragma warning(disable: 4100)  // unused parameter in stub

static UINT64 VsmtIssueHypercall(UINT64 callCode, UINT64 input)
{
    //
    // Standard x64 hypercall ABI (Hyper-V TLFS section 3.1):
    //   VMCALL with:
    //     RCX = HV_CALL_ATTRIBUTES | callCode
    //     RDX = input
    //     R8  = output (ignored for fast calls)
    //   Return value in RAX = HV_STATUS
    //
    // We use VMCALL via inline assembly (__vmx_vmcall is not available
    // from C; use _mm_clflush as a placeholder for the actual VMCALL
    // or compile with MASM for the real call).
    //
    // In production: replace this with the VMCALL instruction.
    //
    UINT64 status = 0xFFFFFFFFFFFFFFFFull; // placeholder: "not implemented"

    // TODO: replace with actual VMCALL when assembling with MASM:
    //   mov  rax, callCode
    //   mov  rdx, input
    //   vmcall
    //   mov  status, rax

    KdPrint(("VsmTest: hypercall 0x%llX (stub -- implement VMCALL)\n", callCode));
    return status;
}

static NTSTATUS HandleHypercall(PVOID inBuf, ULONG inLen,
                                 PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (inLen  < sizeof(VSMT_HYPERCALL_IO)) return STATUS_INVALID_PARAMETER;
    if (outLen < sizeof(VSMT_HYPERCALL_IO)) return STATUS_BUFFER_TOO_SMALL;

    VSMT_HYPERCALL_IO* io = (VSMT_HYPERCALL_IO*)inBuf;
    VSMT_HYPERCALL_IO* out = (VSMT_HYPERCALL_IO*)outBuf;

    RtlCopyMemory(out, io, sizeof(*io));
    out->HvStatus = VsmtIssueHypercall(io->CallCode, io->Input);

    *outInfo = sizeof(VSMT_HYPERCALL_IO);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_SYNTH_STATE
//
// Reads the full set of VSM-relevant synthetic MSRs in one shot.
// Key VTL1 indicators (from securekernel disassembly):
//   SINT0 (0x40000090) = 0x200F0  -- ShvlpInitializeSynic line 216815
//   SINT1 (0x40000091) = 0x20051  -- ShvlpEnableSyntheticTimer line 215321
//   STIMER0_CONFIG (0x400000B0) = 0x10008 -- ShvlpEnableSyntheticTimer line 215324
// ---------------------------------------------------------------------------

// Must match vsm_test_synth.cpp VSMT_SYNTH_STATE
typedef struct {
    UINT64 GuestOsId;
    UINT64 HypercallPage;
    UINT64 VpIndex;
    UINT64 VpRuntime;
    UINT64 TimeRefCount;
    UINT64 TscFrequency;
    UINT64 Scontrol;
    UINT64 Simp;
    UINT64 Siefp;
    UINT64 Sint0;
    UINT64 Sint1;
    UINT64 Sint2;
    UINT64 Stimer0Config;
    UINT64 Stimer0Count;
    UINT64 Stimer1Config;
    UINT64 VpAssistPage;
    UINT64 VsmPartitionStatus;
    UINT64 VsmVpStatus;
    NTSTATUS Status;
} VSMT_SYNTH_STATE_K;

static NTSTATUS HandleSynthState(PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (outLen < sizeof(VSMT_SYNTH_STATE_K)) return STATUS_BUFFER_TOO_SMALL;
    VSMT_SYNTH_STATE_K* s = (VSMT_SYNTH_STATE_K*)outBuf;
    RtlZeroMemory(s, sizeof(*s));

    s->GuestOsId         = SafeReadMsr(0x40000000u);
    s->HypercallPage     = SafeReadMsr(0x40000001u);
    s->VpIndex           = SafeReadMsr(0x40000002u);
    s->VpRuntime         = SafeReadMsr(0x40000004u);
    s->TimeRefCount      = SafeReadMsr(0x40000020u);
    s->TscFrequency      = SafeReadMsr(0x40000022u);
    s->Scontrol          = SafeReadMsr(0x40000080u);
    s->Simp              = SafeReadMsr(0x40000082u);
    s->Siefp             = SafeReadMsr(0x40000083u);
    s->Sint0             = SafeReadMsr(0x40000090u);  // VTL1 primary (expect 0x200F0)
    s->Sint1             = SafeReadMsr(0x40000091u);  // VTL1 timer  (expect 0x20051)
    s->Sint2             = SafeReadMsr(0x40000092u);
    s->Stimer0Config     = SafeReadMsr(0x400000B0u);  // VTL1 timer config (expect 0x10008)
    s->Stimer0Count      = SafeReadMsr(0x400000B1u);
    s->Stimer1Config     = SafeReadMsr(0x400000B2u);
    s->VpAssistPage      = SafeReadMsr(0x40000073u);
    s->VsmPartitionStatus= SafeReadMsr(0x400000E3u);
    s->VsmVpStatus       = SafeReadMsr(0x400000E4u);

    KdPrint(("VsmTest: SINT0=0x%llX SINT1=0x%llX STIMER0_CFG=0x%llX\n",
             s->Sint0, s->Sint1, s->Stimer0Config));

    s->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_SYNTH_STATE_K);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_VPREGISTER
//
// Reads a single VP register via HvCallGetVpRegisters (hypercall 0x50).
//
// Hypercall 0x50 input page layout (non-fast, memory-based):
//   +0x00 QWORD PartitionId  = 0xFFFFFFFFFFFFFFFF (self)
//   +0x08 DWORD VpIndex      = 0xFFFFFFFE (current VP)
//   +0x0C BYTE  InputVtl     = 0xFF (current VTL)
//   +0x0D BYTE  padding[3]
//   +0x10 UINT64 RegisterId  = the VP register to read
//
// Output page:
//   +0x00 UINT128 RegisterValue (16 bytes)
//
// This implementation uses the simplest path: allocate contiguous pages,
// get their physical address, and call VsmtSlowHypercall.
//
// NOTE: Windows kernel already has a valid hypercall page mapped.
// We use ExAllocatePool2 for the I/O pages and MmGetPhysicalAddress.
//
// Known VP registers (from securekernel + ntoskrnl disassembly):
//   0x00090004  HvRegVsmVpIdleTransitions (VTL0 accessible)
//   0x00090013  HvRegVpAssistPage (VTL1 assist page -- requires VTL1 context)
//   0x000D0002  HvRegVsmCodePageOffsets (VtlCall/VtlReturn offsets)
//   0x000D0006  HvRegVsmVpSecureVtlConfig (VTL1 capability flags)
// ---------------------------------------------------------------------------

// Declared in vsm_vmcall.asm:
extern UINT64 VsmtSlowHypercall(UINT64 callCode, UINT64 inGpa, UINT64 outGpa);

typedef struct {
    UINT32   RegisterId;
    UINT8    TargetVtl;
    UINT64   Value;
    BOOLEAN  GpFaulted;
} VSMT_VP_REG_IO_K;

static NTSTATUS HandleVpRegister(PVOID inBuf, ULONG inLen,
                                  PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (inLen  < sizeof(VSMT_VP_REG_IO_K)) return STATUS_INVALID_PARAMETER;
    if (outLen < sizeof(VSMT_VP_REG_IO_K)) return STATUS_BUFFER_TOO_SMALL;

    VSMT_VP_REG_IO_K* io  = (VSMT_VP_REG_IO_K*)inBuf;
    VSMT_VP_REG_IO_K* out = (VSMT_VP_REG_IO_K*)outBuf;
    RtlCopyMemory(out, io, sizeof(*io));
    out->GpFaulted = FALSE;
    out->Value     = 0;

    // Allocate two contiguous 4KB pages: input and output for the hypercall
    // (hypercall pages must be physically contiguous and 4KB-aligned)
    PHYSICAL_ADDRESS lo = { 0 }, hi = { .QuadPart = 0x7FFFFFFF };  // below 2GB
    PVOID inPage  = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    PVOID outPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage || !outPage) {
        if (inPage)  MmFreeContiguousMemory(inPage);
        if (outPage) MmFreeContiguousMemory(outPage);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Build input page (HvCallGetVpRegisters input format)
    RtlZeroMemory(inPage, 4096);
    RtlZeroMemory(outPage, 4096);

    PUINT64 inp = (PUINT64)inPage;
    inp[0] = 0xFFFFFFFFFFFFFFFFull;  // PartitionId = self
    // VpIndex (DWORD) + InputVtl (BYTE) packed at offset 8
    ((PUINT32)inPage)[2] = 0xFFFFFFFEu; // VpIndex = current VP
    ((PUINT8)inPage)[12] = io->TargetVtl ? io->TargetVtl : 0xFF; // VTL
    // RegisterList starts at offset 16: one entry = one UINT64 register ID
    inp[2] = (UINT64)io->RegisterId;   // offset 16

    // Get GPAs
    PHYSICAL_ADDRESS inPhys  = MmGetPhysicalAddress(inPage);
    PHYSICAL_ADDRESS outPhys = MmGetPhysicalAddress(outPage);

    // HvCallGetVpRegisters = 0x0050
    // Call code: 0x0050 | (RepCount=1 << 32) | fast=0
    // Input count = 1 (one register), rep = 1
    UINT64 callCode = 0x0050ull | (1ull << 17); // fast hypercall bit | call code

    // For rep list hypercall: callCode = 0x0050, input in GPA
    UINT64 hvStatus = VsmtSlowHypercall(0x0050ull, inPhys.QuadPart, outPhys.QuadPart);

    KdPrint(("VsmTest: GetVpRegisters(0x%X) hvStatus=0x%llX\n", io->RegisterId, hvStatus));

    if ((hvStatus & 0xFFFF) == 0) {
        // Success: output page has the register value (128-bit)
        PUINT64 outp = (PUINT64)outPage;
        out->Value = outp[0];  // low 64 bits of the 128-bit VP register value
        out->GpFaulted = FALSE;
    } else {
        out->GpFaulted = TRUE;  // non-zero HV_STATUS = not implemented or no access
    }

    MmFreeContiguousMemory(inPage);
    MmFreeContiguousMemory(outPage);

    *outInfo = sizeof(VSMT_VP_REG_IO_K);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL: VSMT_IOCTL_PARTITION_PROP
//
// Queries a partition property via hypercall 0x7B (HvCallGetPartitionProperty).
// Source: ntoskrnl HvlpQueryHypervisorSchedulerType (line 1834918)
//         lea ecx, [rdi+7Bh] with rdi=0 -> call code 0x7B
//         Property 0x0F = scheduler type
//         Property 0x14 = DMA guard enabled
// ---------------------------------------------------------------------------

typedef struct {
    UINT32   PropertyId;
    UINT64   Value;
    UINT64   HvStatus;
    NTSTATUS Status;
} VSMT_PARTITION_PROP_K;

static NTSTATUS HandlePartitionProp(PVOID inBuf, ULONG inLen,
                                     PVOID outBuf, ULONG outLen, PULONG_PTR outInfo)
{
    if (inLen  < sizeof(VSMT_PARTITION_PROP_K)) return STATUS_INVALID_PARAMETER;
    if (outLen < sizeof(VSMT_PARTITION_PROP_K)) return STATUS_BUFFER_TOO_SMALL;

    VSMT_PARTITION_PROP_K* io  = (VSMT_PARTITION_PROP_K*)inBuf;
    VSMT_PARTITION_PROP_K* out = (VSMT_PARTITION_PROP_K*)outBuf;
    RtlCopyMemory(out, io, sizeof(*io));
    out->Value    = 0;
    out->HvStatus = 0xFFFFFFFFFFFFFFFFull;

    PHYSICAL_ADDRESS lo = { 0 }, hi = { .QuadPart = 0x7FFFFFFF };
    PVOID inPage  = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    PVOID outPage = MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, lo, MmNonCached);
    if (!inPage || !outPage) {
        if (inPage)  MmFreeContiguousMemory(inPage);
        if (outPage) MmFreeContiguousMemory(outPage);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(inPage, 4096);
    RtlZeroMemory(outPage, 4096);

    // HvCallGetPartitionProperty input:
    //   +0x00 UINT64 PartitionId = 0xFFFF...FFFF (self)
    //   +0x08 UINT32 PropertyCode
    PUINT64 inp = (PUINT64)inPage;
    inp[0] = 0xFFFFFFFFFFFFFFFFull;
    ((PUINT32)inPage)[2] = io->PropertyId;

    PHYSICAL_ADDRESS inPhys  = MmGetPhysicalAddress(inPage);
    PHYSICAL_ADDRESS outPhys = MmGetPhysicalAddress(outPage);

    out->HvStatus = VsmtSlowHypercall(0x007Bull, inPhys.QuadPart, outPhys.QuadPart);

    if ((out->HvStatus & 0xFFFF) == 0) {
        PUINT64 outp = (PUINT64)outPage;
        out->Value = outp[0];
    }

    KdPrint(("VsmTest: GetPartitionProperty(0x%X) hvStatus=0x%llX value=0x%llX\n",
             io->PropertyId, out->HvStatus, out->Value));

    MmFreeContiguousMemory(inPage);
    MmFreeContiguousMemory(outPage);

    out->Status = STATUS_SUCCESS;
    *outInfo = sizeof(VSMT_PARTITION_PROP_K);
    return STATUS_SUCCESS;
}

// Forward declaration -- implemented in vsm_ktest_isolation.c
NTSTATUS VsmtIsolationDispatch(ULONG code, PVOID buf, ULONG inLen, ULONG outLen,
                                PULONG_PTR outInfo);

// ---------------------------------------------------------------------------
// IRP dispatch
// ---------------------------------------------------------------------------

static NTSTATUS VsmtDispatchCreate(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS VsmtDispatchClose(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS VsmtDispatchIoctl(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG  code   = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG  inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID  buf    = irp->AssociatedIrp.SystemBuffer; // METHOD_BUFFERED: single shared buf

    NTSTATUS    status  = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR   outInfo = 0;

    switch (code) {
    case VSMT_IOCTL_VSM_STATE:
        status = HandleVsmState(buf, outLen, &outInfo);
        break;
    case VSMT_IOCTL_READ_MSR:
        status = HandleReadMsr(buf, inLen, buf, outLen, &outInfo);
        break;
    case VSMT_IOCTL_WRITE_MSR:
        status = HandleWriteMsr(buf, inLen, &outInfo);
        break;
    case VSMT_IOCTL_HYPERCALL:
        status = HandleHypercall(buf, inLen, buf, outLen, &outInfo);
        break;
    case VSMT_IOCTL_INTEL_CAPS:
        status = HandleIntelCaps(buf, outLen, &outInfo);
        break;
    case VSMT_IOCTL_SYNTH_STATE:
        status = HandleSynthState(buf, outLen, &outInfo);
        break;
    case VSMT_IOCTL_VPREGISTER:
        status = HandleVpRegister(buf, inLen, buf, outLen, &outInfo);
        break;
    case VSMT_IOCTL_PARTITION_PROP:
        status = HandlePartitionProp(buf, inLen, buf, outLen, &outInfo);
        break;
    default:
        // Delegate sections 17-22 IOCTLs to isolation module
        status = VsmtIsolationDispatch(code, buf, inLen, outLen, &outInfo);
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = outInfo;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------------
// Driver unload
// ---------------------------------------------------------------------------

#define DEVICE_NAME  L"\\Device\\VsmTest"
#define SYMLINK_NAME L"\\DosDevices\\VsmTest"

static void VsmtUnload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (drv->DeviceObject)
        IoDeleteDevice(drv->DeviceObject);

    KdPrint(("VsmTest: unloaded\n"));
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    UNREFERENCED_PARAMETER(regPath);

    UNICODE_STRING devName, symlink;
    RtlInitUnicodeString(&devName,  DEVICE_NAME);
    RtlInitUnicodeString(&symlink,  SYMLINK_NAME);

    // Create device
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS st = IoCreateDevice(drv, 0, &devName,
                                 VSMT_DEVICE_TYPE, 0, FALSE, &devObj);
    if (!NT_SUCCESS(st)) {
        KdPrint(("VsmTest: IoCreateDevice failed 0x%X\n", st));
        return st;
    }

    // Create symbolic link for user-mode access
    st = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(devObj);
        KdPrint(("VsmTest: IoCreateSymbolicLink failed 0x%X\n", st));
        return st;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    drv->DriverUnload                         = VsmtUnload;
    drv->MajorFunction[IRP_MJ_CREATE]         = VsmtDispatchCreate;
    drv->MajorFunction[IRP_MJ_CLOSE]          = VsmtDispatchClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VsmtDispatchIoctl;

    KdPrint(("VsmTest: loaded -- VSM MSR test driver\n"));
    KdPrint(("  Reading MSR 0x400000E3 (VSM_PARTITION_STATUS) on next IOCTL\n"));
    KdPrint(("  If KVM does not implement this MSR, rdmsr will #GP and we return sentinel\n"));

    return STATUS_SUCCESS;
}
