.. _security-spec:

Intel® Trust Domain Extension Linux\* Guest Kernel Security Specification
#########################################################################

Contributors:

Andi Kleen
Elena Reshetova

Threat model
************


.. figure:: images/linux-tdx-sw-stack.png
   :width: 3.63944in
   :height: 3.65625in

   Figure 1. Linux TDX 1.0 SW stack

The main security goal of Intel® Trust Domain Extension (Intel® TDX)
technology is to remove the need for a TDX guest to trust the host and
virtual machine manager (VMM). It is important to note that this
security objective is not unique to the TDX architecture, but it is
common across all confidential cloud computing solutions (CCC) (such as
TDX, AMD SEV, etc) and therefore many aspects described below will be
applicable to other CCC technologies. The trusted computing base (TCB)
for the Linux TDX SW stack shown in Figure 1 includes the Intel
platform, the TDX module, and the SW stack running inside the TDX guest.

The purpose of this document is to describe the security architecture of
the Linux guest kernel running inside the TDX guest. The major security
objectives of the TDX guest kernel security architecture are to help to prevent
privilege escalation as well as kernel data confidentiality/integrity
violations by the untrusted VMM. The denial-of-service (DoS) attacks
towards the TDX guest kernel is out of the threat model’s scope since
the TDX guest resources are fully under the control of the VMM and are
able to perform DoS towards the TDX guest by default.

The TDX module and the Intel platform help ensure the protection of the TDX
guest memory and registers. However, they cannot protect the TDX guest
from host/VMM attacks that leverage existing communication interfaces
between the host/VMM and the guest:

-  TDVMCALL hypercalls (through the TDX-module)

-  Shared memory for IO

The primary goal of the security architecture described below is to help to
protect the TDX Linux guest kernel from attacks from the hypervisor
through these communication interfaces. Additionally, there should not
be any new additional attack vectors introduced towards the TDX Linux
guest kernel (ring 0) from the TDX guest userspace (ring 3). The TDX
guest userspace is omitted from the scope of this threat model. The
threat model does not address any threats made possible by the TDX guest
userspace directly using the above-mentioned interfaces exposed to an
untrusted host/VMM. For example, if the TDX guest userspace enables
debug or test tools that perform MMIO or pci config space reading on
their own but do not carefully validate the input that comes from
untrusted host/VMM, many additional attacks are possible. This threat
model also assumes the KVM/Qemu to be the hypervisor running the
protected TDX guest. As a result, other hypervisors and their hardening
are also out of the scope of this document. Another potential attack
vector that is not covered by this threat model is abusing the Linux
kernel printout and debug routines that can now take parameters directly
from the untrusted host/VMM.

1) TDX Linux guest kernel overall hardening methodology
=======================================================

Document :ref:`tdx-guest-hardening` describes the hardening methodology
that is used to perform systematic audits and fuzzing of the communication
interfaces exposed to the malicious hypervisor. This document covers the
kernel subsystems that are relevant to the described threat model and provides
details on their hardening principles. The overall security principle is
that in case of any corruption event, the safest default option is to
raise the kernel panic.

2) TDVMCALL-hypercall-based communication interfaces
====================================================

TDVMCALLs are used to communicate between the TDX guest and the
host/VMM. The host/VMM can try to attack the TDX guest kernel by
supplying a maliciously crafted input as a response to a TDVMCALL. While
TDVMCALLs are proxied via the TDX module, only a small portion of them
(mainly some CPUIDs and MSRs) are controlled and enforced by the TDX
module. Most of the TDVMCALLs are passed through and their values are
controlled by the host/VMM. Instead of inserting the TDVMCALL directly
in many code paths within the guest kernel, a #VE handler is used as a
primary centralized TDVMCALL invocation place. However, for some cases
TDVMCALL can be also invoked directly to boost the performance
for a certain hot code path. The #VE handler is invoked by the
TDX module for the actions it cannot handle. The #VE handler either
decodes the executed instruction (using the standard Linux x86
instruction decoder) and converts it into a TDVMCALL or rejects it
(panic). The implementation of the #VE handler is simple and does not
require an in-depth security audit or fuzzing since it is not the actual
consumer of the host/VMM supplied untrusted data. However, it does
implement a simple allow list for the port IO filtering (see `2.5) IO ports`_ ).

2.1) MMIO
---------

MMIO is controlled by the untrusted host and handled through #VE for
most cases, or a special fast path through pci iomap for
performance-critical cases. The instructions in the kernel are trusted.
The #VE handler will decode a subset of instructions using the Linux
instruction decoder. We only care about users that read from MMIO.

2.1.1) Kernel MMIO
~~~~~~~~~~~~~~~~~~

By default, all MMIO regions reside in the TDX guest private memory and
are not accessible to the host/VMM. To explicitly share a MMIO region,
the device must be authorized through the device filter framework,
enabling MMIO operations. The handling of the
MMIO input from the untrusted host/VMM must be hardened (see
:ref:`tdx-guest-hardening` for more information).

The static code analysis tool should generate a list of all MMIO users
based on use of the standard io.h macros. All portable code should use
these macros. The only known exception to this is the MMIO APIC direct
accesses, which should be disabled.

Open: there might be other non-portable (x86-specific) code that does
not use the io.h macros, but directly accesses IO mappings. Sparse
should be able to find those using the \_\_iomem annotations.

2.1.2) User MMIO
~~~~~~~~~~~~~~~~

In the current Linux implementation user MMIO is not supported
and results in SIGSEGV. Therefore, it cannot be used to attack
the kernel (other than DoS).

2.2) APIC
---------

Interrupts are controlled by the host and therefore the guest kernel
code that handles them must be audited and fuzzed as any other code that
receives malicious host input See :ref:`tdx-guest-hardening` for more details
on such hardening.

2.2.1) X2APIC
~~~~~~~~~~~~~

The X2APIC MSRs are proxied through TDVMCALLs and handled by the
untrusted hypervisor.

The X2APIC code should hardened by performing code audit and fuzzing as
outlined in :ref:`tdx-guest-hardening`.

2.2.2) IPIs
~~~~~~~~~~~

IPIs are initiated by triggering TDVMCALL on the X2APIC ICR MSRs. The
host controls the delivery of the IPI, so IPIs might get lost. We need
to make sure all missing IPIs result in panics or stop the operation (in
case the timeout is controlled by the host). This should be already
handled by the normal timeout in smp\_call\_function\*()

2.2.3) Legacy MMIO XAPIC
~~~~~~~~~~~~~~~~~~~~~~~~

We will not support legacy XAPIC; we will use special checks in the kernel
APIC code to disallow it.

2.3) PCI config space
---------------------

The host controls the PCI config space, so in general, any PCI config
space reads are untrusted. Apart from hardening the generic PCI code, we
plan to have a special config space filter that prevents random
initcalls from accessing the PCI config space of unauthorized devices
not allowed by the device filter. The config space filter is implemented
by setting unauthorized devices to the “errored” state, which prevents
any config space accesses.

Inside Linux, the PCI config space is used by several entities:

2.3.1) PCI subsystem for probing drivers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PCI subsystem enumerates all PCI devices through config space. The
host owns the config space, which is untrusted. We’ll only support
probing through CF8 and disable MCFG config space in the ACPI filtering.
This implies that only the first 256 bytes are supported for now. We
have an explicit PCI device ID-based allow list of allowed drivers. All
these drivers will need to be hardened and fuzzed. This can be
overridden by a command line option; in this case the system might be
insecure.

2.3.2) Allocating resources
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The kernel can allocate resources such as MMIO for pci bridges or
drivers based on the information coming from the untrusted pci config
space supplied by the host/VMM. Therefore, this allocation process needs
to be verified to withstand the potential malicious input. As a result,
the code in the core pci subsystem, as well as enabled virtio drivers
have been audited and fuzzed using the techniques described in :ref:`tdx-guest-hardening`.
Specifically, we paid attention to make sure that the allocated resource
regions do not overlap with each other or with the rest of the TD guest
memory. The pci bridge support is planned to be disabled for the TDX
guest kernel.

2.3.3) Drivers
~~~~~~~~~~~~~~

All allow-listed drivers need to be audited and fuzzed for all
interactions (port IO, MMIO, and shared memory) they have with the host.
Initially this will be only a very small list in virtio and VMBus (see
`12 VirtIO and shared memory`_).

2.3.4) User programs accessing PCI devices through sysfs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

User programs can access PCI devices directly through sysfs or /dev/mem.
This could be an attack vector if the user program has an exploitable
hole in parsing config space or MMIO. If the user programs are using the
Linux-supplied PCI enumeration (/sys/bus/pci), the PCI device allow list
will protect user programs to some degree. But it won’t protect programs
that try to directly access devices that are on the allow list (like
virtio or VMBus).

Both MMIO and port IO access from the userspace is disallowed and
results in SIGSEGV.

It’s also possible, in principle, for programs to enumerate PCI directly
through MMIO or CF8 port IO, which would circumvent the allow list.
Subsequent sections explain how to filter those in the #VE handler
(see `2.4) MSRs`_ and `2.5) IO Ports`_ )

2.4) MSRs
---------

2.4.1) MSRs controlled by TDX module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two types of MSRs that are controlled by the TDX module:

-  Passthrough MSRs (direct read/write from the CPU, for example side
   channel related MSRs, such as ARCH\_CAPABILITIES)

-  Disallowed MSRs that result in #GP upon attempt to read/write
   such an MSR (for example, all IA32\_VMX\_\* KVM MSRs).

All these MSRs are controlled by the platform, are trusted, and do not
require any hardening. See 18.1 in https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf for the exact
list.

2.4.2) MSRs proxied through TDVMCALL and controlled by host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section refers to all the MSRs that are audited and fuzzed using
the methodology described in :ref:`tdx-guest-hardening`. One of the main
concerns is MSRs with complex multi-bit fields that result in memory
indexes. The other main concern is memory safety. The risk for
individual MSR bits or MSRs that are only saved/restored is likely low,
which covers a lot of MSRs. The full list of MSR accesses through the
kernel codebase is generated by the static analysis approach, and is
described in :ref:`tdx-guest-hardening`.

Nearly all MSRs used by the kernel are listed in
arch/x86/include/asm/msr-index.h, but might have aliases and ranges.
Some additional MSRs are in arch/x86/include/asm/perf\_event.h,
arch/x86/kernel/cpu/resctrl/internal.h, and arch/x86/kernel/cpu/intel.c

Some MSRs that can be populated by the host/VMM control rather complex
functionality, such as Machine Check MSRs, IA32\_MTRR\_\*, RTIT\_\*
MSRs, and Perfmon / LBR MSRs. We have disabled most of these features to
minimize the exposed attack surface (X86\_FEATURE\_MCE,
X86\_FEATURE\_MTRR, X86\_FEATURE\_TME). Should they need to be enabled,
a detailed code audit and fuzzing approach must be used to ensure the
respective code is hardened.

2.5) IO ports
-------------

IO ports are controlled by the host and could be an attack vector.

All IO port accesses go through #VE or direct TDVMCALLs. We’ll use a
small allow list of trusted ports. This helps to prevent the host from trying to
inject old ISA drivers that use port probing and might have
vulnerabilities processing port data. While normally these cannot be
auto loaded, they might be statically compiled into kernels and would do
standard port probing.

The most prominent user is the serial port driver. Using the serial port
(e.g. for early console) requires disabling security. In the secure mode
we only have the virtio console.

The table below shows the allow list ports in the current TDX guest
kernel:

.. list-table:: List ports
   :widths: 7 7 10
   :header-rows: 1


   * - Port range
     - Intended user
     - Comments
   * - 0x70 … 0x71
     - MC146818 RTC
     -
   * - 0xcf8 … 0xcff
     - PCI config space
     - Ideally this range should be further limited since likely not being
       needed in full
   * - 0x600 ... 0x62f
     - ACPI ports
     - 0600-0603 : ACPI PM1a\_EVT\_BLK
       0604-0605 : ACPI PM1a\_CNT\_BLK
       0608-060b : ACPI PM\_TMR
       0620-062f : ACPI GPE0\_BLK
   * - 0x3f8, 0x3f9,0x3fa, 0x3fd
     - COM1 serial
     - Only in debugmode

IO port accesses for the TDX guest userspace (ring 3) are not supported
and results in SIGSEGV.

2.6) KVM Hypercalls
-------------------

These are controlled by the host and untrusted. They are proxied through
TDVMCALL.

Based on the KVM CPUID enabled leaves
(see `2.7) KVM CPUID`_ ), only a KVM\_HC\_SEND\_IPI hypercall is enabled
currently and it is trivially safe. Three other KVM hypercalls are disabled
by disabling KVM CPUIDs:

 - KVM\_HC\_CLOCK\_PAIRING

 - KVM\_HC\_SCHED\_YIELD

 - KVM\_HC\_KICK\_CPU

There are more KVM hypercalls supported by the KVM host, but they don’t
seem to be used by the Linux guest.See
Documentation/virt/kvm/hypercalls.rst for detailed specifications.

2.7) KVM CPUID
--------------

KVM has many PV CPUIDs. Many of those are unsafe for a TD and are
filtered when TDX is active.

2.7.1) Unsafe CPUIDs
~~~~~~~~~~~~~~~~~~~~

.. list-table:: Unsafe CPUIDs
   :widths: 20 55
   :header-rows: 1

   * - CPUID
     - Notes
   * - KVM\_FEATURE\_CLOCKSOURCE
     - We don’t want to trust the host for time
   * - KVM\_FEATURE\_CLOCKSOURCE2
     -
   * - KVM\_FEATURE\_ASYNC\_PF
     - Allows injection of arbitrary page faults into
       the guest, which is almost certainly not safe.
   * - KVM\_FEATURE\_PV\_EOI
     - Relies on the host writing to the guest, which
       requires making that memory decrypted. The current code marks it already decrypted for AMD. Since the interrupts in the TDX module
       are posted, it is doubtful the EOI mechanism would work anyway,
       which is more for purely virtual interrupts. So it’s better to be
       disabled.

2.7.2) Unclear and not needed CPUIDs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These CPUIDs are disabled for now and potentially could be enabled after
audit:

 - KVM\_FEATURE\_MMU\_OP
 - KVM\_FEATURE\_STEAL\_TIME
 - KVM\_FEATURE\_PV\_UNHALT
 - KVM\_FEATURE\_PV\_TLB\_FLUSH
 - KVM\_FEATURE\_ASYNC\_PF\_VMEXIT
 - KVM\_FEATURE\_POLL\_CONTROL
 - KVM\_FEATURE\_PV\_SCHED\_YIELD: It is unused in Linux.
 - KVM\_FEATURE\_ASYNC\_PF\_INT
 - KVM\_FEATURE\_MSI\_EXT\_DEST\_ID

2.7.3) Safe CPUIDs
~~~~~~~~~~~~~~~~~~

 - KVM\_FEATURE\_NOP\_IO\_DELAY: Only affects nops.
 - KVM\_FEATURE\_PV\_SEND\_IPI: Equivalent to APIC write.
 - KVM\_HINTS\_REALTIME: Changes spinlock behavior, but just a hint.

2.8) CPUID
----------

In theory, CPUID could be used to let the guest kernel execute
non-hardened code paths. The TDX module ensures that most CPUID values
are trusted (see 18.2 in https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf), but some are configurable
via the TD\_PARAMS structure or can be provided by the untrusted
host/VMM via the logic implemented in #VE handler.

Since the TD\_PARAMS structure is measured into TDX measurement
registers and can be attested later, the CPUID bits that are configured
using this structure can be considered trusted.

The table below lists the CPUID leaves that can be supplied by the
untrusted Host/VMM:

.. list-table:: CPUID leaves
   :widths: 15 20 40
   :header-rows: 1

   * - Cpuid Leaf
     - Purpose
     - Comment
   * - 0x2
     - Cache & TLB info
     - Obsolete leaf, code will prefer CPUID 0x4 which is trusted
   * - 0x5
     - Monitor/Mwait
     -
   * - 0x6
     - Thermal & Power Mgmt
     -
   * - 0x9
     - Direct cache access info
     -
   * - 0xb
     - Extended topology enumeration
     -
   * - 0xc
     - Reserved
     - Not used in Linux
   * - 0xf
     - Platform QoS monitoring
     - Explicitly disabled in TDX guest via clearing X86\_FEATURE\_CQM\_LLC
       feature bit
   * - 0x10
     - Platform QoS Enforcement
     - Explicitly disabled in TDX guest via clearing X86\_FEATURE\_MBA
       feature bit
   * - 0x16
     - Processor frequency
     - The only user of this cpuid in the TDX guest is
       cpu\_khz\_from\_cpuid, but the TDX guest code has been changed to
       first use cpuid leaf 0x15 which is guaranteed by the TDX module
   * - 0x17
     - SoC Identification
     -
   * - 0x18
     - TLB Deterministic Parameters
     -
   * - 0x1a
     - Hybrid Information
     -
   * - 0x1b
     - MK TME
     - Explicitly disabled in TDX guest via clearing X86\_FEATURE\_TME
       feature bit
   * - 0x1f
     - V2 Extended Topology Enumeration
     -
   * - 0x80000002-4
     - Processor Brand String
     -
   * - 0x80000005
     - Reserved
     -
   * - 0x80000006
     - Cache parameters
     -
   * - 0x80000007
     - AMD Advanced Power Management
     -
   * - 0x40000000- 0x400000FF
     - MSRs reserved for SW use
     -

Most of the above CPUID leaves result in different feature bits and
therefore are harmless. The ones that have larger fields have been
audited and fuzzed in the same way as other untrusted inputs from the
hypervisor. In addition, it is also possible to sanitize multi-bit
CPUIDS against the bounds expected for a given platform.

2.9 IOMMU
---------

IOMMU is disabled for the TDX guest due to the DMAR ACPI table not being
included in the list of allowed ACPI tables for the TDX guest. Similar
for the AMD IOMMU. The other IOMMU drivers should not be active on x86.

2.10 Perfmon
------------

For CPUID, see `2.7) KVM CPUID`_ above.

For MSR, see `2.4) MSRs`_ .

The uncore drivers are explicitly disabled with a hypervisor check,
since they generally don’t work in virtualization of any kind. This
includes the architectural Chassis perfmon discovery, which works using
MMIO.

3 Randomness inside TDX guest
=============================

3.1 RDRAND/RDSEED
-----------------

RDRAND/RDSEED instructions are used for various security purposes and
their output is expected to conform to the output of the cryptographic
PRNG. The instructions can return failure, which is then expected to be
retried. The host could trigger that by depleting the shared hardware
RNG. Some of the users fall back to alternative ways, which are usually
insecure because they can be controlled by the host. The implementation
of the RDRAND/RDSEED invocation in the TDX guest kernel has been changed
to loop forever on failure.

3.2 Linux RNG
-------------

The Linux RNG uses timing from interrupts as the default entropy source;
this can be a problem for the TDX guest because timing of the interrupts
is controlled by the untrusted host/VMM. However, by using Linux RNG
design, a fresh entropy is added on each invocation of the Linux RNG’s
Cha-Cha20 DRNG (and for its early seeding) using CPU’s HW RNG
(RDRAND/RDSEED instructions on modern Intel platforms). We rely on the
RDRAND/RDSEED instructions as an independent source of entropy that is
not under the host/VMM control and enforce the
CONFIG\_RANDOM\_TRUST\_CPU inside a TDX guest. As a side effect, the
resulting entropy counts for blocking pool (/dev/random) can be
incorrect, but it is assumed that nowadays people use Cha-Cha20 DRNG
(/dev/urandom) for cryptographically secure values.

4 TSC and other timers
=======================

TDX has a limited secure time with the TSC timer. The TSC inside a TD is
guaranteed to be synchronized and monotonous, but not necessarily
matching real time. A guest can turn it into truly secure wall time by
using an authenticated time server.

By default, for the KVM hypervisor, kvmclock would have priority, which
is not secure anymore because it uses untrusted input from the host. To
avoid this the kvmclock has been disabled by default when running inside
a TDX guest. It would also be possible for the host to trigger a TSC
fallback (e.g. by not scheduling VCPUs or delaying IPIs), which also
would lead to insecure time. We’ve also disabledg acpi\_pm to prevent
fallback to that. Additionally, the TSC watchdog is also disabled (by
forcing the X86\_FEATURE\_TSC\_RELIABLE bit) to avoid the possible
fallback to jiffy time, which could be influenced by the host by
changing the frequency of the timer interrupts.

5 Declaring insecurity to user space
====================================

Many of the security measures described in this document can be disabled
with command line arguments, especially any kind of filtering. While
such a configuration change is detected by attestation, there are use
cases that don’t use full attestation and may continue running even if
it fails.

For this purpose, a taint flag TAINT\_CONF\_NO\_LOCKDOWN is set when any
command line overrides for lockdowns are used. The user agent could
check that by using /proc/sys/kernel/taint. Additionally, there are
warnings printed to indicate whenever the device filter has been
disabled, overridden over command line, etc.

The key server helps to ensure through attestation that the guest runs in secure
mode. It does that by attesting the kernel command line, as well as the
kernel binary. The kernel configuration should include module signing,
which can be enforced by the command line as well as the binary.

6 BIOS-supplied ACPI tables and mappings
========================================

ACPI table mappings and similar table mappings use the ioremap\_cache
interface, which is never set to shared with the untrusted host/VMM.

ACPI tables are (mostly) controlled by the host and only passed through
the TDVF (TDX guest virtual firmware,
see https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf for more information).
They should be attested and therefore trusted. However, we
cannot expect that an attesting entity fully understands what causes the
Linux kernel to open security holes based on some particular AML. Then a
malicious hypervisor might be able to attack the guest based on attack
surfaces exposed by the non-malicious and attested ACPI tables. The main
concern here is the tables and methods that configure some functionality
in the kernel,such as initializing drivers.

As a first step to minimize the above attack surface, the TDX guest
kernel defines an allow list for the ACPI tables. Currently the list
includes the following tables: XSDT, FACP, DSDT, FACS, APIC, and SVKL.
However, it still includes large tables like DSDT that contain a lot of
functionality. Ideally one would need to define a minimal set of methods
that such table needs to support and then perform a code audit and
fuzzing of these methods. All features that are not required (for
example CPPC throttling) should be disabled to minimize the attack
surface. This hardening activity has not been performed for the TDX
guest and remains a future task. Alternatively, for a more generic
hardening in-depth approach, the whole ACPI interpreter can be fuzzed
and hardened, but this is a considerable effort and also is left for the
future. For example, one possible future hardening is to add some range
checking in ACPI to not write from AML to memory outside MMIO.

7 TDX guest private memory page management
==========================================

All TDX guest private memory pages are allocated by the host and must be
explicitly “accepted” into the guest using the TDACCEPT command. The TDX
guest kernel needs to make sure that an already accepted page is not
accepted again, because doing so would change the content of the guest
private page to a zero page with possible security implications (zeroing
out keys, secrets, etc.). Additionally, per current design of the TDX
module, TDX guest memory access to a non-accepted page results in a #VE
inserted by the TDX guest module. It is very important for security that
it does not happen during certain TDX guest critical code paths (see
`7.3 Safety against #VE in kernel code`_ for more details).

7.1 TDVF conversion
-------------------

Most of the initial memory for the TDX guest is converted by the TDVF
and the TDX guest kernel can use all this memory through the normal UEFI
memory map. However, due to performance implications, it is not possible
to pre-accept all memory required for a guest to run, so the lazy memory
accept logic described the next section is used.

7.2 Lazy conversion
-------------------

To address the significant performance implications of pre-accepting all
the pages, the pages will be accepted in runtime as required. Once VMM
adds a private memory page to a TDX guest, its secure EPT entry resides
in the PENDING state before the TDX guest explicitly accepts this page
(secure EPT entry moves to PRESENT state) using the TDG.MEM.PAGE.ACCEPT
instruction.

According to the TDX module specification, if the TDX guest attempts to
accept the page that is already in the PRESENT state (essentially do a
double accept by chance), then the TDX module has a way to detect this
and supply a warning, so accepting an already accepted page is ok.

However, it is possible that that malicious host/VMM can execute the
sequence of TDH.MEM.RANGE.BLOCK; TDH.MEM.TRACK; and TDH.MEM.PAGE.REMOVE
calls on any present private page.Then it can quickly add it back with
TDH.MEM.PAGE.AUG, and it goes into pending state.If the guest does not
verify that it has previously accepted this page and accepts it again,
it would end up using a zero page instead of data it previously had
there. So, re-accept can happen if there is no TDX guest internal
tracking of which pages have been previously accepted. For this purpose,
the TDX guest kernel keeps track of already accepted pages in a 2MB
granularity bitmap allocated in decompressor. In turn the page allocator
accepts 2MB chunks as needed.

7.3 Safety against #VE in kernel code
-------------------------------------

The kernel needs to make sure it does not get #VE in certain critical
sections. One example of such a section is a system call gap: on
SYSCALL/SYSRET. There is a small instruction window where the kernel
runs with the user stack pointer. If a #VE event (for example due to a
malicious hypervisor removing a memory page as explained in the above
section) happens in that window, it would allow a malicious userspace
(ring 3) process in the guestto take over the guest kernel. As a result,
it must be ensured that it is not possible to get a #VE event on the
pages containing kernel code or data. For this reason, Linux guest
kernel verifies that ATTRIBUTES.SEPT\_VE\_DISABLE TD attribute is set
to 1 to prohibit the delivery of #VE exceptions when accessing a private
GPA for which the Secure EPT entry state is PENDING.

8 Panic
=======

In various situations when the TDX guest kernel detects a potential
security problem, it needs to reliably stop. Standard panic performs
many complex actions:

-  IPIs to other CPUs to stop them. This is not secure because the IPI
   is controlled by the host, which could choose not to execute them.

-  There can be notifiers to other drivers and subsystems which can do
   complex actions, including something that would cause the panic to
   wait for a host action.

As a result, it is not possible to guarantee that any other VCPU is
reliably stopped with the standard panic and therefore a reliable panic
is required. There is a potential path to make the panic more atomic
(prevent reentry), but not fully atomic (due to TDX module limitations).
This remains to be a direction for future work.

9 Kernel and initrd loading
===========================

In a simple reference configuration the TDVF loads the kernel,
the initrd, and a startup script from an
unencrypted UEFI VFAT volume in the guest storage area through virtio.
The startup script contains the kernel command line. The kernel is
booted through the Linux uEFI stub. Before booting the TDVF runs hashes
over the kernel image/initrd/startup script and attest those to a key
server through the SEAM measurement registers.

10 Kernel command line
======================

The kernel command line will allow to run an insecure kernel by
disabling various security features or injecting unsafe code. However,
we assume that the kernel command line is trusted, which is ensured by
measuring its contents by the TDVF into TDX attestation registers.

11 Storage protection
=====================

The confidentiality and authenticity of the TD guest disk volume’s needs
to be protected from the host/VMM that handles it. The exact protection
method is decided by the TD tenant, but we provide a default reference
setup. We use dmcrypt with LUKS with dm integrity to provide encryption
and authentication for the storage volumes. To retrieve the decryption
key during the TD boot process, the TD guest initrd contains an agent
that performs the TD attestation to a remote key server. The attestation
quote is going to contain the measurements from the TDVF, the boot
loader, kernel, its command line, and initrd itself. The actual
communication protocol between the remote key server and the initrd
attestation agent will be customer (cloud) specific. The reference
initrd attestation agent provided by Intel implements the Intel
reference protocol. After the attestation succeeds, the initrd
attestation agent obtains the key and it is used by the initrd to mount
the TD guest file system.

Users could use other encryption schemes for storage, such as not using
LUKS but some other encrypted storage format. Alternatively, they could
also not use local storage and rely on a volume mounted from the network
after attesting themselves to the network server. However, support for
such remote storage is out of the scope for this document for now.

12 VirtIO and shared memory
===========================

The virtIO subsystem is controlled by the untrusted host/VMM. For the
application data transferred over the virtIO communication channel, its
confidentiality and integrity must be guaranteed by the
application-level mechanisms. For example, virtio block IO is encrypted
and authenticated using dmcrypt or other similar mechanism, virtio
network communication uses TLS or similar for the transmitted data. All
the rest of virtio input received from the host/VMM must be considered
untrusted. We need to make sure the that the core virtio code and
enabled virtio drivers are hardened against the malicious inputs
received from host/VMM through exposed interfaces, such as pci config
space and shared memory.

The virtIO subsystem is also highly configurable with different options
possible for the virtual queue's types, transportation, etc. For the
virtual queues, currently the only mode that was hardened (by performing
code audit and fuzzing activities outlined in :ref:`tdx-guest-hardening`)
is a split virtqueue without indirect descriptor support, so this mode is the only
one recommended for the secure virtio communication. For the virtio
transportation, the Linux TDX guest kernel uses hardened virtio over PCI
transport and disables the virtio over MMIO. If virtio over MMIO support
is desired, it can be enabled given that the hardening of this mode is
performed. For the virtio over PCI, we also disable the
virtio-pci-legacy mode and only harden the virtio-pci-modern mode. For
some of above described virtio configurations (for example disabling the
virtio-pci-legacy mode), it is possible for the TDX guest userspace to
override the secure defaults (given enough privileges). But doing so
would open the unhardened code and is strongly discouraged.

VirtIO drivers are built around the virtio ring. The ring contains
descriptors, which are organized in a free list. The free list handling
has been recently hardened by moving out of the shared memory into
guest private memory. We assume the main attack point is the ring,
but we also harden the higher-level
enabled drivers such as virtio-block, virtio-net, virtio-console,
virtio-9p, and virtio-vsock. All other virtio drivers are disabled by
the TDX guest driver filter and are not hardened.

VirtIO accesses the pci config space by using virtio-specific pci config
space access functions that are part part of both code audit and fuzzing
activities. Most of the virtio shared memory accesses go through
virtio\_to\_cpu macros and their higher-level wrappers, which are also
used for auditing and injecting the fuzzing input. However, there still
can be other accesses to the shared memory that must be manually audited
and instrumented for fuzzing.

13 Summary
==========

The TDX guest kernel security architecture described in this document is
a first step towards building a secure Linux guest kernel for
confidential cloud computing (CCC). The security hardening techniques
described in this document are not specific to the Intel TDX technology,
but are applicable for any CCC technology that aims to help to remove the
host/VMM from TCB. While some of the hardening approaches outlined above
are still a work in progress or left for the future, it provides a solid
foundation for continuing this work by both the industry and the Linux
community.
