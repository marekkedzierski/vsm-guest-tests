; vsm_vmcall.asm -- VMCALL stubs for VSM hypercall testing
;
; Assemble: ml64 /c /Cx vsm_vmcall.asm
; Link into vsm_ktest.obj
;
; Hyper-V fast hypercall ABI (TLFS section 3.1):
;   Input:  RCX = call code | fast-bit (bit 16) | input count in [27:17]
;           RDX = first fast input QWORD
;   Output: RAX = HV_STATUS (0 = success)
;           RDX = first fast output QWORD (when applicable)
;
; Non-fast (memory-based) hypercall ABI:
;   Input:  RCX = call code | rep count in [43:32]
;           RDX = GPA of input parameter page (4KB-aligned)
;           R8  = GPA of output parameter page (4KB-aligned)
;   Output: RAX = HV_STATUS | actual rep count in [43:32]
;
; Both paths: VMCALL instruction triggers VM exit to KVM hypervisor.

.CODE

;
; VsmtFastHypercall(UINT64 callCode, UINT64 inputVal) -> UINT64 hvStatus
;
; Issues a fast hypercall (bit 16 of callCode must be set by caller if needed).
; callCode in RCX, inputVal in RDX -- standard x64 ABI matches VMCALL ABI exactly.
;
PUBLIC VsmtFastHypercall
VsmtFastHypercall PROC
    ; RCX = callCode, RDX = inputVal
    ; RAX = HV_STATUS on return
    vmcall
    ret
VsmtFastHypercall ENDP

;
; VsmtSlowHypercall(UINT64 callCode, UINT64 inGpa, UINT64 outGpa) -> UINT64 hvStatus
;
; Memory-based (slow) hypercall using pre-allocated physical pages.
; callCode in RCX, inGpa in RDX, outGpa in R8 -- standard x64 ABI.
;
PUBLIC VsmtSlowHypercall
VsmtSlowHypercall PROC
    ; RCX = callCode, RDX = inGpa, R8 = outGpa
    vmcall
    ret
VsmtSlowHypercall ENDP

;
; VsmtCpuid(UINT32 leaf, UINT32 subleaf,
;           UINT32* eax, UINT32* ebx, UINT32* ecx, UINT32* edx)
;
; Issues CPUID from kernel mode.  Safer than __cpuid in driver context.
;
PUBLIC VsmtCpuid
VsmtCpuid PROC
    ; RCX=leaf, RDX=subleaf, R8=eax*, R9=ebx*, [rsp+28h]=ecx*, [rsp+30h]=edx*
    push rbx
    push rdi
    push rsi

    mov  eax, ecx           ; leaf
    mov  ecx, edx           ; subleaf
    cpuid

    mov  [r8],  eax
    mov  [r9],  ebx
    mov  rdi,   [rsp+28h+18h]   ; ecx* (adjusted for pushes: 3*8=18h)
    mov  [rdi], ecx
    mov  rsi,   [rsp+30h+18h]   ; edx*
    mov  [rsi], edx

    pop  rsi
    pop  rdi
    pop  rbx
    ret
VsmtCpuid ENDP

;
; VsmtRdmsr(UINT32 msr) -> UINT64
;
; Raw rdmsr without SEH -- only use when you know the MSR is safe.
;
PUBLIC VsmtRdmsr
VsmtRdmsr PROC
    mov  ecx, ecx    ; msr index (already in ECX from ABI)
    rdmsr
    shl  rdx, 32
    or   rax, rdx    ; combine EDX:EAX into RAX
    ret
VsmtRdmsr ENDP

;
; VsmtWrmsr(UINT32 msr, UINT64 value)
;
PUBLIC VsmtWrmsr
VsmtWrmsr PROC
    ; RCX = msr, RDX = value (low 32), but value is UINT64 in RDX
    mov  eax, edx           ; low DWORD of value
    shr  rdx, 32            ; high DWORD of value into EDX
    wrmsr
    ret
VsmtWrmsr ENDP

END
