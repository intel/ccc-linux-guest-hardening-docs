.. _tdx-guest-hardening:

Intel® Trust Domain Extension Guest Linux Kernel Hardening Strategy
#####################################################################

Contributors:

Elena Reshetova, Tamas Lengyel, Sebastian Osterlund, Steffen Schulz


Purpose and Scope
=================

The main security goal of Intel® Trust Domain Extension (Intel® TDX)
technology is to remove the need for a guest VM to trust the host and
Virtual Machine Manager (VMM). However, it cannot by itself protect the
guest VM from host/VMM attacks that leverage existing paravirt-based
communication interfaces between the host/VMM and the guest, such as
MMIO, Port IO, etc. To achieve protection against such attacks, the guest
VM software stack needs to be hardened to securely handle an untrusted
and potentially malicious input from a host/VMM via the above-mentioned
interfaces. This hardening effort should be applied to a concrete set of
software components that are used within the guest software stack
(virtual BIOS, bootloader, Linux\* kernel and userspace), which is
specific to a concrete deployment scenario. To facilitate this process,
we have developed a hardening methodology and tools that are explained
below.

The hardening approach presented in this document is by no means an
ultimate guarantee of 100% security against the above-mentioned attacks,
but merely a methodology built to our best knowledge and resource
limitations. In our environment, we have successfully applied it to the
Linux TDX MVP software stack (https://github.com/intel/tdx-tools)
to the trust domain (TD) guest Linux kernel and hardened many involved
kernel subsystems. This guide is written with the Linux kernel in mind,
but the outlined principles can be applied to any software component.

The overall threat model and security architecture for the TD guest
kernel is described in the :ref:`security-spec` and it is
recommended to be read together with this document.

Hardening strategy overview
===========================

The overall hardening strategy shown in Figure 1 encompasses three
activities that are executed in parallel: attack surface minimization,
manual code audit, and code fuzzing. All of them are strongly linked and
the results from each activity are contributed as inputs to the other
activities. For example, the results of a manual code audit can be used
to decide whenever a certain feature should be disabled (attack surface
minimization) or should be a target for a detailed fuzzing campaign.
Similarly, the fuzzing results might affect the decision to disable a
certain functionality or indicate a place where a manual code audit is
required but have been missed by a static code analyzer.

.. figure:: images/strategy.png
   :width: 5.51418in
   :height: 3.23958in

   Figure 1. Linux Guest kernel hardening strategy.

The following section provides a detailed description of each of these
activities. An overall crucial aspect to consider is the “definition of
done”, i.e., the criteria for when a hardening effort can be finished
and how the success of such effort is defined.

The ideal “definition of done” criteria can be outlined as follows:

1. The guest kernel functionality and the VMM/host exposed interfaces
   are limited to the minimum required for its successful operation,
   given a chosen deployment scenario. This implies that only a minimal
   set of required drivers, kernel subsystems, and individual
   functionality is enabled.

2. All code paths that are enabled within the guest kernel and can take
   an untrusted input from VMM/host must be manually audited from the
   potential consequences of consuming the malformed data. Whenever a
   manual code audit identifies an issue that is a security concern, it
   must be addressed either by a bug fix or by disabling the involved
   code path, if possible.

3. All code paths that are enabled within the guest kernel and can take
   an untrusted input from VMM/host must be fuzzed using an appropriate
   fuzzing technique. The fuzzing technique must provide the coverage
   information to identify that a fuzzer has reached the required code
   paths and exercised them sufficiently. Whenever the fuzzing activity
   identifies an issue that is a security concern, it must be addressed
   either by a bug fix or by disabling the involved code path.

The success of the overall hardening effort is significantly more
difficult to measure. The total number of security concerns identified
by the manual code audit or fuzzing activity is a natural quantifier,
but it neither guarantees that the end goal of having a secure guest
kernel has been successfully reached nor does it necessarily indicate
that the chosen hardening approach is successful. The successful
operation of the guest kernel within the Linux TD software stack and the
absence of issues identified or reported during its deployment life cycle
is a much stronger, albeit a post-factum indicator.

Attack surface minimization
===========================

The main objective for this task is to disable as much code as possible
from the TD guest kernel to limit the number of interfaces exposed to
the malicious host/VMM. This is achieved by either explicitly disabling
certain unneeded features (for example early PCI code), by a generic
filtering approach, such as port IO filtering, driver filtering, etc or
by restricting access to the MMIO and PCI config space regions

Implemented filtering mechanisms
--------------------------------

All the implemented filtering mechanisms described below are runtime
mechanisms that limit TD guest functionality based on a set of default
allow lists defined in the kernel source code, but with a possibility to
override these defaults via a command line option mechanism. The latter
can be used for debugging purposes or for enabling a specific driver,
ACPI table, or KVM CPUID functionality that is required for a particular
deployment scenario.

.. list-table:: Filter status
   :widths: 10 30
   :header-rows: 1

   * - Filter name
     - Purpose and current state
   * - Driver filter
     - Limits a set of drivers that are enabled in runtime for the TD guest kernel.
       By default, all PCI and ACPI bus drivers are blocked unless they are in the allow
       list. The current default allow list for the PCI bus is limited to the
       following virtio drivers: virtio\_net, virtio\_console, virtio\_blk, and
       9pnet\_virtio.
   * - Port IO filter
     - Limits a set of IO ports that can be used for communication between a TD
       guest kernel and the host/VMM. This feature is needed in addition to the
       above driver filtering mechanism, because should some drivers escape this
       mechanism, its port IO communication with the host/VMM will be limited to a
       small set of allowed ports. For example, some linux drivers might perform
       port IO reads in their initialization functions before doing the driver
       registration or some legacy drivers might not utilize the modern driver
       registration interface at all and therefore would be allowed by the above
       driver filter. In any case port IO filter makes sure that only a limited
       number of ports are allowed to be communicating with host/VMM. The port IO
       allow list can be found in :ref:`sec-io-ports`.
       Note that in the decompressed mode, the port IO
       filter is not active and therefore it is only applicable for early port IO
       and normal port IO.
   * - ACPI table allow list
     - TDX virtual firmware (TDVF, for details see
       https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.pdf)
       measures a set of ACPI tables obtained from the host/VMM into TDX RTMR[
       0] measurement register. Thus, the set of tables passed by the host/VMM can
       be remotely attested and verified. However, it can be difficult for a
       remote verifier to understand the possible consequences from using a big
       set of various ACPI tables. Since most of the tables are not needed for a
       TDX guest, the implemented ACPI table allow list limits them to a small,
       predefined list with a possibility to pass additional tables via a command
       line option. The current allow list is limited to the following tables:
       XSDT, FACP, DSDT, FACS, APIC, and SVKL. Note that a presence of a minimal
       ACPI table configuration does not by itself guarantee the overall security
       hardening of ACPI subsystem in the TD guest kernel. The known limitations
       on ACPI hardening are described in :ref:`sec-acpi-tables`.
   * - KVM CPUID allow list and KVM hypercalls
     - KVM supports a set of hypercalls that a TD guest kernel can request a VMM to
       perform. On x86, this set is defined by a set of exposed CPUID bits. Some
       of the hypercalls can result in untrusted data being passed from a VMM
       KVM) to the guest kernel. To limit this attack vector, the implemented KVM
       CPUID allow list restricts the available KVM CPUID bits to a small
       predefined allow list. More information can be found in
       :ref:`sec-kvm-hypercalls` and :ref:`sec-kvm-cpuid`.

Explicitly disabled functionality
---------------------------------

Most of the functionality described below takes an untrusted host input
via MSR, port IO, MMIO, or pci config space reads through its codebase.
This has been identified using the static code analyzer described in the
next section. The decision to disable this functionality was made based
on the amount of code that would have to be manually audited, complexity
of the code involved, as well as the fact that this functionality is not
needed for the TD guest kernel.

.. list-table:: Features
   :widths: 15 60
   :header-rows: 1

   * - Feature type
     - Description
   * - x86 features
     - Some x86 feature bits are explicitly cleared out by the TD guest kernel
       during an initialization, such as X86\_FEATURE\_MCE, X86\_FEATURE\_MTRR,
       X86\_FEATURE\_TME, X86\_FEATURE\_APERFMPERF, X86\_FEATURE\_CQM\_LLC.
   * - Various PCI functionality
     - Some PCI related functionality that is not needed in the TD guest kernel is
       also explicitly disabled, such as early PCI, PCI quirks, and enhanced PCI
       parsing.
   * - Miscellaneous
     - A malicious host/VMM can fake PCI ids or some CPUID leaves to enable
       functionality that is normally disabled for a TDX guest and therefore not
       hardened. To help prevent this from happening, support for XEN, HyperV, and ACRN
       hypervisors, as well as AMD northbridge support, is explicitly disabled in
       the TD guest kernel.

Opt-in shared MMIO regions & PCI config space access
----------------------------------------------------

To further minimize the amount of code that needs to be hardened, we
require the TD guest kernel to explicitly opt-in any MMIO region that
needs to be shared with the host. This ensures that there is no
accidental shared MMIO regions created in the TD guest kernel that can
escape the hardening. A similar requirement applies to the PCI config
space accesses: only authorized devices are allowed to perform PCI
config space reads (this applies even to the PCI config space done from
the device initialization routine).

.. _hardening-smatch-report:

Static Analyzer and Code Audit
==============================

Requirements and goals
----------------------

The attack surface minimization activity outlined in the previous
section helps to limit the amount of TD guest kernel code that actively
interacts with the untrusted host/VMM. It is not possible to fully
remove this interaction due to the functional requirements that the TD
guest has; it needs to be able to perform network communication, it
should be possible to interact with the TD guest via console, etc. Thus,
we need to be able to manually audit all the TD guest kernel enabled
code that consumes an untrusted input from the host/VMM to ensure it
does not use this input in an unsecure way.

To perform a more focused manual code audit, the exact locations where
the untrusted host input is consumed by the TD guest kernel needs to be
identified automatically. We have defined the following requirements for
this process:

1. **Adjustability of custom kernel trees.** The method must be easy to
   use on any custom kernel tree with any set of applied patches and
   specified kernel configuration.

2. **Absence of code instrumentation.** The expected number of locations
   where the TD guest can take an untrusted input from the host goes
   well beyond 1500 places even after the functionality minimization
   step. This makes it impossible to manually instrument these
   locations, as well as keep maintaining the instrumentation through
   the kernel version changes, custom patch sets, etc.

3. **Open-source well established tool**. The tool should be easily
   accessible for open source and for the kernel community to use and
   should be actively maintained and supported.

Check\_host\_input Smatch pattern
---------------------------------

Based on the above requirements, a Smatch static code analyzer
(http://smatch.sourceforge.net/) has
been chosen since it provides an easy interface to write custom patterns
to search for problematic locations in the kernel source tree. Smatch
already has a big set of existing patterns that have been used to find
many security issues with the current mainline kernel.

To identify the locations where a TD guest kernel can take an untrusted
input from the host/VMM, a custom Smatch pattern 
`check_host_input <https://repo.or.cz/smatch.git/blob/HEAD:/check_host_input.c>`_ 
has been written.
It operates based on a list of base “input functions” (contained
in `smatch_kernel_host_data <https://repo.or.cz/smatch.git/blob/HEAD:/smatch_kernel_host_data.c>`_),
i.e. low-level
functions that perform MSR, port IO, and MMIO
reads, such as native\_read\_msr, inb/w/l, readb/w/l, as well as
higher-level wrappers specific to certain subsystems. For example, PCI
config space uses many wrappers like pci\_read\_config,
pci\_bus/user\_read\_\* through its code paths to read the information
from the untrusted host/VMM. Whenever a function listed in 
`smatch_kernel_host_data <https://repo.or.cz/smatch.git/blob/HEAD:/smatch_kernel_host_data.c>`_
is detected in the code, the correct parameters (containing an input that
could have been supplied by the host) are marked as 'host_data' and
Smatch's taint analysis will perform propagation of this data through
the whole kernel codebase. The output of the check\_host\_input
pattern when run against the whole kernel tree is a list of all locations
in kernel where the 'host_data' is being processed, with exact code locations
and some additional information to assist the manual code audit process.

Additionally existing smatch patterns can take a benefit from the fact
that 'host_data' is now correctly tracked. For example, a modified
`check_spectre <https://repo.or.cz/smatch.git/blob/HEAD:/check_spectre.c>`_ 
Smatch pattern now is able to detect spectre v1 gadgets not only on the
userspace <->kernel surface, but also host <->guest surface. More
information can be found in `Transient Execution attacks and their mitigation <https://intel.github.io/ccc-linux-guest-hardening-docs/security-spec.html#transient-execution-attacks-and-their-mitigation>`_

The current approach using the check\_host\_input Smatch pattern has
several limitations. The main limitation is the importance of having a
correct list of input functions since the pattern will not detect the
invocations of functions not present in this list. Fortunately, the
low-level base functions for performing MSR, port IO, and MMIO read
operations are well-defined in the Linux kernel. Another limitation of
this approach is the inability to detect generic DMA-style memory accesses, since they
typically do not use any specific functions or wrappers to receive the
data from the host/VMM. An exception here is a virtIO ring subsystem
that uses virtio16/32/64\_to\_cpu wrappers in most of the places to
access memory locations residing in virtIO ring DMA pages. The
invocation of these wrappers can be detected by the check\_host\_input
Smatch pattern and the findings can be reported similarly as for other
non-DMA accesses.

.. code-block:: shell

   arch/x86/pci/irq.c:1201 pirq_enable_irq() warn:
   {9123410094849481700}read from the host using function
   'pci_read_config_byte' to an int type local variable 'pin', type is
   uchar;

   arch/x86/pci/irq.c:1216 pirq_enable_irq() error:
   {11769853683657473858}Propagating an expression containing a tainted
   value from the host 'pin - 1' into a function
   'IO_APIC_get_PCI_irq_vector';

   arch/x86/pci/irq.c:1228 pirq_enable_irq() error:
   {15187152360757797804}Propagating a tainted value from the host 'pin'
   into a function 'pci_swizzle_interrupt_pin';

   arch/x86/pci/irq.c:1229 pirq_enable_irq() error:
   {8593519367775469163}Propagating an expression containing a tainted
   value from the host 'pin - 1' into a function
   'IO_APIC_get_PCI_irq_vector';

   arch/x86/pci/irq.c:1233 pirq_enable_irq() warn:
   {3245640912980979571}Propagating an expression containing a tainted
   value from the host '65 + pin - 1' into a function '_dev_warn';

   arch/x86/pci/irq.c:1243 pirq_enable_irq() warn:
   {11844818720957432302}Propagating an expression containing a tainted
   value from the host '65 + pin - 1' into a function '_dev_info';

   arch/x86/pci/irq.c:1262 pirq_enable_irq() warn:
   {14811741117821484023}Propagating an expression containing a tainted
   value from the host '65 + pin - 1' into a function '_dev_warn';

Figure 2. Sample output from the check\_host\_input Smatch pattern.

The sample output of the check\_host\_input Smatch pattern is shown on
Figure 2. The function pirq\_enable\_irq performs a PCI config space
read operation using a pci\_read\_config\_byte input function (PCI
config space specific higher-level wrapper) and stores the result in the
local variable pin (type uchar). Next, this local variable is being
supplied as an argument to the IO\_APIC\_get\_PCI\_irq\_vector and
pci\_swizzle\_interrupt\_pin functions, as well as to several
\_dev\_info/warn functions. The relevant code snippet with highlighted
markings is shown in Figure 3.

.. figure:: images/code-snipped-pirq.png
   :width: 6.14865in
   :height: 5.68750in

Figure 3. Code snippet for the pirq\_enable\_irq function.

.. _hardening-performing-manual-audit:

Performing a manual code audit
------------------------------

The check\_host\_input Smatch pattern can be run as any other existing
smatch patterns following instructions in `Smatch documentation <https://repo.or.cz/smatch.git/blob/HEAD:/Documentation/smatch.txt>`_ .
One important precondition before running the pattern is to build the smatch cross
function database first (at least 5-6 times) in order to make sure that
the database contains the propagated taint data. The database pre-build step needs
to happen only once per kernel tree and is not needed in the subsequent
analysis runs. Also, since the pattern is automatically disabled in the smatch
default configuration (due to a significant volume output), it must be explicitly 
enabled in the `smatch header file <https://repo.or.cz/smatch.git/blob/HEAD:/check_list.h#l232>`_ 
before performing an audit run.

The `ccc-linux-guest-hardening repository <https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/generate_smatch_audit_list.md>`_ 
contains instructions on how to obtain the output of check\_host\_input smatch pattern
using automated scripts provided with the repository.
Internally, when a manual code audit activity is performed, the list of overall
findings is filtered using the process\_smatch\_output.py python
script to discard the results for the areas that are disabled within the
TD guest kernel. For example, most of the drivers/\* and sound/\*
results are filtered out except for the drivers that are enabled in the
TD guest kernel. Additionally, process\_smatch\_output.py also discards
findings from other enabled by default smatch patterns. 

After following instructions in `ccc-linux-guest-hardening repository <https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/generate_smatch_audit_list.md>`_ the reduced list of smatch
pattern findings, smatch\_warns.txt, can be analyzed
manually by looking at each reported code location and verifying that
the consumed or propagated host input is used in a secure way.

Each finding is therefore manually classified into one of the following
statuses:

.. list-table:: Findings
   :widths: 15 60
   :header-rows: 1


   * - **Status**
     - **Meaning**
   * - excluded
     - This code location is not reachable inside a TD guest due to it being
       non-Intel code or functionality that is disabled for the TD guest kernel.
       The reason these lines are not filtered from the Smatch report by the above
       process\_smatch\_output.py python script is additional checks that we do
       when executing the fuzzing activity described in the next section. We
       perform an additional verification that none of these excluded code
       locations can be reached by the fuzzer.
   * - unclassified
     - This code location is reachable inside TDX guest (i.e. not excluded), but
       has not been manually audited yet. 
   * - wrapper
     - The function that consumes or propagates a host input is a higher-level wrapper. The
       function is being checked for processing the host input in a secure way,
       but additionally all its callers are also reported by the Smatch pattern
       and the code audit happens on each caller.
   * - trusted
     - The consumed input comes from a trusted source for Intel TDX guest, i.e.
       it is provided by the TDX module or context-switched for every TDX guest
       (i.e. native). This is applicable for both MSRs and CPUIDs. More information
       can be found in :ref:`sec-msrs` and :ref:`sec-cpuids`.
   * - safe
     - The consumed or propagated host input looks to be used in a secure way
   * - concern
     - The consumed or propagated host input is used in an unsecure way. There is an additional
       comment indicating the exact reason. All concern items must be addressed
       either by disabling the code that performs the host input processing or by
       writing a patch that fixes the problematic input processing.

The main challenge in this process is a decision whenever a certain
reported code location is considered “safe” or “concern”. The typical
list of “concern” items can be classified into two categories:

1. **Memory access issues**. A host input is being used as an address,
   pointer, buffer index, loop iterator bound or anything else that
   might result in the host/VMM being able to have at least partial
   control over the memory access that a TD guest kernel performs.

2. **Conceptual security issues.** A host input is being used to affect
   the overall security of the TD guest or its features. An example is
   when an untrusted host input is used for operating TD guest clock or
   affecting KASLR randomization.


Applying code audit results to different kernel trees
-----------------------------------------------------

The provided `sample audit output <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/audit/sample_output/6.0-rc2/smatch_warns_6.0_tdx_allyesconfig_filtered_analyzed>`_ 
of check\_host\_input smatch pattern findings for the version 6.0-rc2 kernel
contains results of our manual code audit activity for this kernel version
(Please note that the above provided list
does not have 'safe' or 'concern' markings published) and
can be used as a baseline for performing a manual audit on other kernel
versions or on custom vendor kernels. The suggested procedure to analyse
a custom kernel is documented in 'Targeting your own guest kernel'[TBD].

The automatic transfer of the code audit labels (trusted, excluded,
wrapper, etc.) from the baseline kernel audit version is  based on the
unique identifiers for each finding. Examples of these findings are
shown in orange in Figure 2. Identifiers from a baseline kernel tree
finding and target tree finding must match for a finding to be
automatically transferred. An identifier is a simple djb2 hash of
an analyzed code expression together with a relative offset from the
beginning of the function where this expression is located. It is
possible to further improve the calculation of identifiers (and
therefore improve the accuracy of automatic result transfer) to include
the code around the expression in a way that it is done in various
version control systems, but it has not been done yet.

TD Guest Fuzzing
================

Fuzzing is a well-established software validation technique that can be
used to find problems in input handling of various software components.
In our TD guest kernel hardening project, we used it to validate and
cross check the results from the manual code audit activity.

The main goals for the fuzzing activity are:

1. Automatically exercise the robustness of the existing TD guest kernel
   code that was identified by the Smatch pattern as handling the input
   from the host/VMM.

2. Identify new TD guest kernel code locations that handle the input
   from the host/VMM and were missed by the Smatch pattern (for example
   some virtIO DMA accesses). When such locations are identified, the
   Smatch pattern can be further improved to catch these and similar
   places in other parts of the kernel code.

3. Automatically verify that the code that is expected to be disabled in
   the TD guest kernel (and thus not manually audited at all) is indeed
   not executed/not reachable in practice.

The primary ways of consuming untrusted host/VMM is by using either TDVMCALLs or
DMA shared memory as used for example by the VirtIO layer. Additionally, the
code paths that consume untrusted input may invoked automatically during boot,
or require some additional stimulus to execute during runtime.

In the following we review options we considered for generating potential
relevant userspace activity and fuzzing the various relevant input interfaces
during boot as well as during runtime.

TDX emulation setup
===================

Running a fully functional TDX guest requires CPU and HW support that is only
available on future Intel Xeon platforms. On contrary, our TDX
emulation setup allows testing SW running inside TDX guest VM early on ahead of
HW availability. It can be run on any recent and commonly available Intel
platforms without any special HW features. However, it is important to note that
this emulation setup is very limited in the amount of features it supports
and is not secure: emulated TDX guest runs under full control of the host
and VMM.

The main challenge for the setup is the emulation of the Intel TDX module.
Intel TDX module is a special SW module that plays a role of a secure shim between
the TDX host and TDX guest and provides an extensive API towards both VMM and TDX guest.
However, since our goal is only fuzzing of the TDX guest kernel,
we need a minimal emulation of the TDX Seam module that can support the basic set
of calls that TDX guest does towards the TDX module,
as well as wrapping such calls into existing kvm interfaces.
For more details about the actual Intel TDX module and its functionality please see
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_


Implementation details
----------------------
The TDX emulation setup is implemented as a simple Linux kernel module with the
code in arch/x86/kvm/vmx/seam.c. Whenever the core TDX code in KVM performs
basic lifecycle operations on the TDX guest (initialization, startup, destruction,
etc.) it would call the respected functions in the TDX emulation setup (seam_tdcreatevp,
seam_tdinitvp/tdfreevp, seam_tdenter, etc.) instead of the actual TDX functions.
The emulated seam module supports a minimal set of exit reasons from the TDX guest
(including EXIT_REASON_TDCALL, EXIT_REASON_CPUID, EXIT_REASON_EPT_VIOLATION) and
inserts a #VE exception into an emulated TDX guest when the guest performs
operations on MSRs, CPUIDs, portIO and MMIO, as well as on guest's EPT violations.
Emulation performed by the TDX emulation setup is currently not exact but mainly focused
on exercising and testing the relevant TDX support by the guest OS.
Please refer to section 24 of 
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ for official guidance on TDX module interfaces. 
For example, for the emulation of the MSRs and CPUIDs virtualization the emulated seam
module does not adhere to the TDX module specification on MSR and CPUID accesses
outlined in section 19 of 
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ Instead it just inserts a #VE event on most of the MSRs
operations and for the CPUID leaves greater than 0x1f or outside of 0x80000000u-0x80000008u
range. The code in arch/x86/kvm/vmx/seam.c: seam_inject_ve() function can be checked
for up-to-date details. 

Fuzzing Kernel Boot
===================

The majority of input points identified by Smatch analysis and manual audit are
invoked as part of kernel boot.
The invocation of these code paths is usually hard to achieve at runtime
after the kernel has already booted due to absence of re-initialization
paths for many of these kernel subsystems.

We have adopted the `kAFL Fuzzer
<https://github.com/IntelLabs/kAFL>`__ for effective feedback fuzzing of the Linux
bootstrapping phase. Using a combination of fast VM snapshots and kernel
hooks, kAFL allows flexible harnessing of the relevant kernel
sub-systems, fast recovery from benign error conditions, and automated
reporting of any desired errors and exceptions handlers.

.. figure:: images/kAFL-overview.png
   :width: 3.48364in
   :height: 3.73366in

   Figure 4. kAFL overview. 1) start of fuzzing (entry to kernel) 2)
   fuzzing harness 3) input fuzz buffer from host 4) MSR/PIO/MMIO causes a
   #VE 5) the agent injects a value obtained from 6) the input buffer 7)
   finally, reporting back the status to the host (crash/hang/ok)
   

Agent
-------

While kAFL can work based on binary rewrite and traps, the more
flexible approach is to modify the target’s source code. This
implements an agent that directly hooks relevant subsystems and
low-level input functions and feeds fuzzing input. At a high level,
our agent implementation consists of three parts:

a. **Core agent logic**: This includes fuzzer initialization and helper
   functions for logging and debug. The fuzzer is initialized with
   tdg\_fuzz\_enable(), and accepts control input via tdg\_fuzz\_event()
   to start/stop/pause input injection or report an error event.
   https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-3/arch/x86/kernel/kafl-agent.c

b. **Input hooks**: We leverage the tdx\_fuzz hooks of in the
   guest kernel as defined by `Simple Fuzzer Hooks`_ as well as
   virtio16/32/64\_to\_cpu wrappers for VirtIO DMA input.
   When enabled, the fuzzing hooks are implemented to sequentially
   consume input from a payload buffer maintained by the agent. Fuzzing
   stops when the buffer is fully consumed or other exit conditions are
   met.
   https://github.com/IntelLabs/kafl.linux/commit/1e5206fbd6a3050c4b812a826de29982be7a5905

c. **Exit and reporting hooks**: We added tdx\_fuzz\_event() calls to
   common error handlers such as panic() and kasan\_report(), but also
   halt\_loop() macros etc. Moreover, the printk subsystem has been
   modified to log buffers directly via hypercalls. This allows report
   error conditions to be returned to the fuzzer and to collect any
   diagnostics before immediately restoring the initial snapshot for
   next execution.

Harnesses Definition
--------------------

Our kAFL agent implements a number of harnesses covering key phases of boot:

-  Early boot process: EARLYBOOT, POST\_TRAP, and START\_KERNEL

-  Subsystem initialization: REST\_INIT, DO\_BASIC, DOINITCALLS,
   DOINITCALLS\_PCI, DOINITCALLS\_VIRTIO, DOINITCALLS\_ACPI, and
   DOINITCALLS\_LEVEL\_X

-  Full boot (ends just before dropping to userspace): FULL\_BOOT

-  Kretprobe-based single function harnesses: VIRTIO\_CONSOLE\_INIT and
   EARLY\_PCI\_SERIAL\_INIT

The full list of boot harnesses with descriptions is available at
https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/boot_harnesses.txt

These harnesses are enabled in the guest Linux kernel by setting up the
kernel build configuration parameters in such a way that the desired
harness is enabled. For example, set
CONFIG\_TDX\_FUZZ\_HARNESS\_EARLYBOOT=y to enable the EARLYBOOT harness.
When enabled, the kernel will execute a tdx\_fuzz\_enable() call at the
beginning of the harness and a corresponding end call at the end of the
harness. These calls cause kAFL to take a snapshot at the first fuzzing
input consumed in the harness, and to reset the snapshot once the
execution reaches the end of the harness. The fuzzer will continue
resetting the snapshot in a loop -- having it consume different fuzzing
input on each reset -- until the fuzzing campaign is terminated.

During the campaign, the fuzzer automatically logs error cases, such as
crashes, sanitizer violations, or timeouts. Detailed (binary edge)
traces and kernel logs can be extracted in post-processing runs
(coverage gathering). To understand the effectiveness of a campaign, we
map achieved code coverage to relevant input code paths identified by
:ref:`hardening-smatch-report` ("Smatch matching").


Example Workflow
--------------------

Running a boot time fuzzing campaign using our kAFL-based setup
typically consists of three stages, namely:

#. **Run fuzzing campaign(s).** Here we run the fuzzing campaign itself.
   The duration of the campaign typically depends on which harness is
   being used, how much parallelism can be used, etc. We have included a
   script (fuzz.sh) that sets up a campaign with some default settings.
   Make sure the guest kernel with the kAFL agent is checked out in
   ~/tdx/linux-guest. Select a harness that you want to use for fuzzing
   (in the next examples we will use the DOINITCALLS\_LEVEL\_4 harness).
   Using our fuzz.sh script, you can run a campaign in the following
   manner:

   .. code-block:: bash

      ./fuzz.sh full ./linux-guest/

   This starts a single fuzzing campaign, with the settings specified
   in fuzz.sh. You can get a more detailed view of the status of the
   campaign using the kafl\_gui.py tool:

   .. code-block:: bash

      kafl_gui.py /dev/shm/$USER_tdfl

#. **Gather the line coverage.** Once the campaign has run for long
   enough, we can extract the code line coverage from the campaign’s
   produced fuzzing corpus.

   .. code-block:: bash

      ./fuzz.sh cov /dev/shm/$USER\_tdfl

   This produces output files in the /dev/shm/$USER\_tdfl/traces
   directory, containing information, such as the line coverage (for
   example, see the file traces/addr2line.lst).

#. **Match coverage against Smatch report.** Finally, to get an idea of
   what the campaign has covered, we provide some functionality to
   analyze the obtained line coverage against the Smatch report. Using
   the following command, you can generate a file
   (traces/smatch\_match.lst) containing the lines from the Smatch
   report that the current fuzzing campaign has managed to reach. Run
   the Smatch analysis using:

   .. code-block:: bash

      ./fuzz.sh smatch /dev/shm/$USER_tdfl

   For a more complete mapping of the PT trace to line coverage, we
   have included functionality to augment the line coverage with
   information obtained using Ghidra. For example, if you want to make
   sure that code lines in in-lined functions are also considered, run
   the previous command, but set the environmental variable
   USE\_GHIDRA=1. E.g.:

   .. code-block:: bash

      USE_GHIDRA=1 ./fuzz.sh smatch /dev/shm/$USER_tdfl

We have included a script (`run\_experiments.py <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/kafl/run_experiments.py>`_) that automatically runs
these three steps for all the different relevant boot time harnesses.


Setup Instructions
-------------------

The full setup instructions for our kAFL-based fuzzing setup can be found at
https://github.com/intel/ccc-linux-guest-hardening


Fuzzing Kernel Runtime
======================

Fuzzing the TD Guest Kernel at runtime is relevant for any code paths that are
not exercised during boot or exercised during runtime with different context.
Finding a way to reliably activate these code paths can be more difficult as an
appropriate `stimulus` must be found. We present multiple options for finding
a stimulus program and then fuzzing untrusted host/VMM inputs in context of that
stimulus.

Fuzzing Stimulus
----------------

One challenge with TD guest kernel fuzzing is to create an
appropriate stimulus for the fuzzing process, i.e. to find a way to
reliably invoke the desired code paths in the TD guest kernel that
handle an input from the host/VMM. Without such stimulus, it is hard to
create good fuzzing coverage even for the code locations reported by the
Smatch static analyzer. We considered the following options:

-  **Write a set of dedicated tests that exercises the desired code
   paths**. The obvious downside of this approach is that it is very
   labor-intensive and manual. Also, the Smatch static analyzer list of
   findings goes well beyond 1500 unique entries; this approach does not
   scale since some of the tests might have to be modified manually as
   the mainline Linux kernel keeps developing.

-  **Use existing test suites for kernel subsystems.** This approach
   works well for the cases when a certain type of operation is known to
   eventually trigger an input from the host/VMM. Examples include Linux
   Test Project (LTP), as well as networking and filesystem test suites
   (netperf, stress-ng, perf-fuzzer). The challenge here is to identify test programs
   that trigger all the desired code paths. **Todo:** put a coverage info +
   refer to section for usermode tracing/fuzzing for how to find/test
   own stimulus.

-  **Automatically produced stimulus corpus.** An alternative way of
   using existing test suites or creating new ones can be a method that
   would programmatically exercise the existing TD guest kernel runtime
   code paths and produce a set of programs that allow invocation of the
   paths that lead to obtaining an input from the host/VMM. Fortunately,
   the Linux kernel has a well-known tool for exercising the kernel in
   runtime – Syzkaller fuzzer. While being a fuzzing tool that was
   originally created to test the robustness of ring 3 to ring 0
   interfaces, Syzkaller fuzzer can be used to automatically generate a
   set of stimulus programs once it is modified to understand whenever a
   code path that triggers an input from the host/VMM is invoked.
   However, the biggest problem with using Syzkaller in this way is to
   create a bias towards executing syscalls that would end up consuming
   the input from the host/VMM. This remains a direction for future
   research.

Simple Fuzzer Hooks
--------------------

This simple fuzzer defines the basic fuzzer structure and the fuzzing
injection input hooks that can be used by more advanced fuzzers (and in
our case, used by the kAFL fuzzer) to supply the fuzzing input to the TD
guest kernel. The fuzzing input is consumed using the tdx\_fuzz() function
that is called right after the input has been consumed from the host
using the **TDG.VP.VMCALL** CPU interface.

The fuzzing input that is used by the basic fuzzer is a simple mutation
using random values and shifts of the actual supplied input from the
host/VMM. The algorithm to produce the fuzzing input can be found in
\_\_tdx\_fuzz() from arch/x86/kernel/tdx-fuzz.c. The main limitation of
this fuzzing approach is an absence of any feedback during the fuzzing
process, as well as an inability to recover from kernel crashes or
hangs.

The simple fuzzer exposes several statistics and input injection options via
debugfs. **TODO** Refer documentation as part of Linux kernel sources.

KF/x DMA Fuzzing
-----------------

Overview
~~~~~~~~

DMA shared memory is designed to be accessible by the host hypervisor to
facilitate fast I/O operations. DMA is setup using the Linux kernel’s
DMA API and the allocated memory regions are then used by various
drivers to facilitate I/O for disk, network, and console connections via
the VirtIO protocol. The goal of using the KF/x fuzzer on these DMA
memory regions is to identify issues in these drivers and the VirtIO
protocol that may lead to security issues.

To fuzz the code that interacts with DMA memory, do the following:

#. Capture VM snapshot when DMA memory read access is performed

#. Transfer VM snapshot to KF/x fuzzing host

#. Identify stop-point in the snapshot

#. Fuzz target using KF/x

.. figure:: images/kf-x-overview.png
   :width: 5.86458in
   :height: 3.29883in

   Figure 5. KF/x overview

Details
~~~~~~~

A. As the memory underpinning DMA is regular RAM, the guest-physical
   address is bound to run through the MMU’s Second Layer Address
   Translation via the Extended Page Tables (EPT). This allows us to
   restrict the EPT permissions and remove read-access rights from the VM.
   By removing EPT access rights of the memory regions designated to be
   DMA, the hypervisor gets a page-fault notification of all code-locations
   that interact with DMA memory. The `Bitdefender KVM VMI
   patch-set <https://github.com/kvm-vmi>`__ is used for this
   introspection.

   DMA regions are identified by hooking the Linux kernel’s DMA API via
   hypervisor-level breakpoint injection. By injecting a breakpoint into
   the DMA API responsible for mapping and unmapping memory, we can track
   which memory pages are designated to be DMA. The VM is booted with this
   monitoring enabled from the start and the EPT permissions are
   automatically restricted for all pages that are currently DMA mapped.

   As DMA accesses are very frequent, the number of snapshots taken are
   reduced by observing the call-stack leading to the DMA access. For this,
   the kernel is compiled with stack frame pointers enabled. By hashing the
   four top-level functions on the call-stack, we identify whether a given
   DMA access is performed under a unique context or not (such as a
   particular system-call, kernel thread, etc.).

   The faulting instruction is then emulated by the hypervisor to allow the
   DMA access to continue without the kernel getting stuck trying to access
   memory.

B. Snapshots are transferred to KF/x fuzzing hosts running on Xen.
   Snapshots are loaded into VM-shells by transplanting the snapshots’
   memory and vCPU context.

C. The transplanted snapshot is executed up to a limited number of
   instructions (usually between 100k-250k) and logged to a file.
   Cross-reference the log with stacktrace to see how far back up the stack
   the execution reached. Place a breakpoint at that address.

D. KF/x is set up to fuzz the entire DMA page (4096 bytes) where the
   memory access was captured. The fuzzer is set to log any fuzzed input
   that leads to KASAN, UBSAN, or panic in the VM.

Setup instructions
~~~~~~~~~~~~~~~~~~

`Virtio snapshotting with KVM VMI · intel/kernel-fuzzer-for-xen-project
Wiki
(github.com) <https://github.com/intel/kernel-fuzzer-for-xen-project/wiki/Virtio-snapshotting-with-KVM-VMI>`__


kAFL Stimulus Fuzzing
---------------------

.. figure:: images/kAFL-runtime-overview.png
   :width: 3.60417in
   :height: 3.98958in

   Figure 6. kAFL runtime fuzzing overview. 1) start of fuzzing 2)
   input fuzz buffer from host 3) stimulus is consumed from userspace
   4) MSR/PIO/MMIO causes a #VE 5) the agent injects a value obtained
   from 6) the input buffer 7) finally, reporting back the status to
   the host (crash/ hang/ ok)


The kAFL agent described earlier can also be used to trace and fuzz custom
stimulus programs from userspace. The kAFL setp for userspace fuzzing uses to
following additional components:

-  kAFL agent exposes a userspace interface via debugfs. The interface
   offers similar controls to those used to implement boot-time harneses
   inside the kernel, i.e. start/stop as well as basic statistics.

-  The VM must be started with a valid rootfs, such as an initrd that
   contains the stimulus program. The kernel is configured with
   CONFIG\_TDX\_FUZZ\_HARNESS\_NONE; it boots normally and launches the
   designated ‘init’ process. Fuzzer configuration and control is done
   via debugfs.

-  To avoid managing a large range of filesystems, kAFL offers a
   ‘sharedir’ option that allows to download files into the guest at
   runtime. This way, the rootfs only contains a basic loader while
   actual execution is driven by scripts and programs on the Host.
   Communication is done using hypercalls and works independently of
   virtio or other guest drivers.

Harness Setup
~~~~~~~~~~~~~

As with the other runtime fuzzing setups, the kAFL setup requires an
adequate “stimulus” to trigger kernel code paths that consume data from
the untrusted host/VMM (either using **TDG.VP.VMCALL**-based interface
or virtIO DMA shared memory). We setup kAFL to run any desired userspace
binaries as stimulus input, using a flexible bash script to initialize
snapshotting & stimulus execution from /sbin/init.

The usermode harness that is downloaded and launched by the loader can
be any script or binary and may also act as an intermediate loader or
even compiler of further input. The main difference from regular VM
userspace is that the harness eventually enables the fuzzer, at which
point the kAFL/Qemu frontend creates the initial VM snapshot and
provides a first candidate payload to the kAFL agent. Once the snapshot
loop has started, execution is traced for coverage feedback and the
userspace is fully reset after timeout, crashes, or when the “done”
event is signaled via debugfs.

Example harness using a stimulus.elf program:

.. code-block:: bash

      #!/bin/bash
      KAFL_CTL=/sys/kernel/debug/kafl
      hget stimulus.elf # fetch test binary from host
      echo "[*] kAFL agent status:"
      grep . $KAFL_CTL/*
      # "start" signal initializes agent and triggers snapshot
      echo "start" > $KAFL_CTL/control
      # execute the stimulus, redirecting outputs to host hprintf log
      ./stimulus.elf 2>&1 |hcat
      # if we have not crashed, signal "success" and restore snapshot
      echo "done" > $KAFL_CTL/control


Detailed setup and scripts to generate small rootfs/initrd:
https://github.com/intel/ccc-linux-guest-hardening/tree/master/bkc/kafl/userspace

More sophisticated “harness” for randomized stimulus execution:
https://github.com/intel/ccc-linux-guest-hardening/tree/master/bkc/kafl/userspace/sharedir_template/init.sh

Enabling additional kernel drivers
==================================

The reference TDX guest kernel implementation provided for the `Linux SW stack for
Intel TDX <https://github.com/intel/tdx-tools>`_ only enables a small set of
virtio drivers that are essential for the TDX guest basic functionality. These
drivers have been hardened using the methodology described in this document,
but naturally different deployment scenarios and use cases for the TDX will
require many more additional drivers to be enabled in the TDX guest kernel.

This section provides guidance on how to use the methodology presented
in this document for adding and hardening a new driver for the TDX guest kernel.

In order to explain better on how to perform the below steps, we will
use virtio-vsock driver as an example. This driver was the last one to
be enabled and hardened
for the `Linux SW stack for Intel TDX <https://github.com/intel/tdx-tools>`_.
Its primary usage in TDX guest kernel is to communicate with the host to
request converting a local TDX attestation report into a remotely verifiable
TDX attestation quote.

Identify the device/driver pair
-------------------------------

The first step includes locating the source code of a target driver in
the Linux kernel tree, understanding the bus that this driver
is registered for (typically it would be a pci or acpi bus), as well as
how the driver registration is done, how to perform functional testing
for this driver and any higher-level interface abstractions present.

**Example**. For our :code:`virtio-vsock` driver example, the source code of this
driver is located at `/net/vmw_vsock/virtio_transport.c <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/net/vmw_vsock/virtio_transport.c>`_ and the driver
registers itself on the virtio bus (an abstraction level over the pci bus)
using `register_virtio_driver() <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/net/vmw_vsock/virtio_transport.c#L754>`_.

Perform code audit
------------------

In this step, the source code of the driver
is manually audited to determine the input points where the untrusted data
from the host or `VMM` is consumed and how this data is being processed.
In order to facilitate the manual audit, the :code:`check_host_input` smatch pattern can
be used to identify these input points. For that, a smatch run can be done on
an individual driver source file using :code:`kchecker` command.

**Example**. The below command line for :code:`virtio-vsock` driver assumes
that you have
a smatch instance with the :code:`check_host_input` pattern installed at
:code:`~/smatch` folder and the command is invoked from the kernel source tree root.
For the instructions on how to install smatch please consult
`README.md <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/audit/README.md>`_

.. code-block:: bash

      ~/smatch_scripts/kchecker net/vmw_vsock/virtio_transport.c > driver_results

The :code:`driver_results` output file will contain the list of input points
and the limited
propagation information:

.. code-block:: shell

   net/vmw_vsock/virtio_transport.c:305 virtio_transport_tx_work() error:
   {8890488479003397221} 'check_host_input' read from the host using function
   'virtqueue_get_buf' to a non int type local variable 'pkt', type is struct virtio_vsock_pkt*;   
   net/vmw_vsock/virtio_transport.c:306 virtio_transport_tx_work() error:
   {5556237559821482352} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_free_pkt';
   net/vmw_vsock/virtio_transport.c:305 virtio_transport_tx_work() warn:
   {8890488479003397221} 'check_host_input' potential read from the host using
   function 'virtqueue_get_buf';
   net/vmw_vsock/virtio_transport.c:375 virtio_vsock_update_guest_cid() error:
   {7572251756130242} 'check_host_input' propagating a tainted value from
   the host 'guest_cid' into a function 'get';
   net/vmw_vsock/virtio_transport.c:377 virtio_vsock_update_guest_cid() error:
   {16638257021812442297} 'check_host_input' propagating read value from
   the host 'guest_cid' into a different complex variable 'vsock->guest_cid';
   net/vmw_vsock/virtio_transport.c:410 virtio_transport_event_work() error:
   {8890488479003397221} 'check_host_input' read from the host using function
   'virtqueue_get_buf' to a non int type local variable 'event', type is struct virtio_vsock_event*;
   net/vmw_vsock/virtio_transport.c:412 virtio_transport_event_work() error:
   {8840682050757106252} 'check_host_input' propagating a tainted value from
   the host 'event' into a function 'virtio_vsock_event_handle';
   net/vmw_vsock/virtio_transport.c:414 virtio_transport_event_work() error:
   {83481497696856778} 'check_host_input' propagating a tainted value from
   the host 'event' into a function 'virtio_vsock_event_fill_one';
   net/vmw_vsock/virtio_transport.c:410 virtio_transport_event_work() warn:
   {8890488479003397221} 'check_host_input' potential read from the host
   using function 'virtqueue_get_buf';
   net/vmw_vsock/virtio_transport.c:541 virtio_transport_rx_work() error:
   {8890488479003397230} 'check_host_input' read from the host using function
   'virtqueue_get_buf' to a non int type local variable 'pkt', type is struct virtio_vsock_pkt*;
   net/vmw_vsock/virtio_transport.c:551 virtio_transport_rx_work() error:
   {5556237559821482370} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_free_pkt';
   net/vmw_vsock/virtio_transport.c:556 virtio_transport_rx_work() error:
   {5857033014461230228} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_deliver_tap_pkt';
   net/vmw_vsock/virtio_transport.c:557 virtio_transport_rx_work() error:
   {8453424129492944817} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_recv_pkt';

Given this information the manual code audit can be performed by looking at each
reported entry in the source code to determine whenever the input consumed
from host or `VMM` is processed securely. Please consult section `Static Analyzer and Code Audit`_
for more information on how to interpret each reported entry and how to perform
manual analysis. The output of this step is a list of entries that are marked
'concern' that would require patches to be created in order to harden
the given driver based on the manual code audit step.

Perform driver fuzzing
----------------------

Ideally each code location reported by the smatch
in step 2 needs to be exercised by using either `kafl` or `kfx` fuzzers (or both).
However, if resource or timing is very limited, the fuzzing can be
primary focused
only on the 'concern' entries from the step 2 or on any other entries
that are considered potentially problematic (complex parsing of data, many call
chains, etc.).
The typical reported input locations can be divided into two groups:
driver initialization
code (init and probe functions) and runtime operation. The first group would be
the easiest one to reach by a fuzzer since it does not require any
external stimulus:
it only requires a creation of a separate fuzzing harness. The second
one ideally
requires a functional test suite to be run to exercise the driver
functionality as a stimulus.
However, in the absence of such a test suite, a set of simple manual
tests can be
created or certain userspace commands/operations performed that trigger
invocation of the functions reported by smatch in step 2. Setting up
the driver fuzzing can also be very beneficial even in cases when
smatch does not report any hits in driver’s init or probe functions,
because smatch can miss some host input consumption points in some
cases and fuzzing can help discover such cases.

**Example**. Enabling fuzzing targets like the :code:`virtio-vsock` driver
requires some manual work and modifications of the fuzzing setup (as
opposite to more straightforward examples like :code:`virtio-net` or
:code:`virtio-console`) and below steps explain how to add support for such a
target. In a nutshell, :code:`virtio-vsock` sets up a socket on the host or `VMM`,
allowing a host process to setup a direct socket connection to the
guest VM over `VirtIO`. For fuzzing, this requires some initial setup in
the host, as well as establishing a connection from the guest.
It is also important to make sure that the targeted device is allowed
by the device filter when performing the fuzzing. See  
`Enable driver in the TDX filter``  below for the instructions. 

**Host steps**. First, the `VMM` host kernel must support :code:`VSOCK`. The
corresponding kernel module can be loaded using :code:`modprobe vhost_vsock`.
If this fails, it might be required to install a
different kernel which has :code:`CONFIG_VHOST_VSOCK` set. When the
:code:`vhost_vsock` driver is enabled, a device shall appear at
:code:`/dev/vhost-vsock`. Its default permissions might be insufficient for
`QEMU` to access, but it can be fixed by executing :code:`chmod 0666 /dev/vhost-vsock`.
Now that the :code:`vhost-vsock` device is available to
`QEMU`, the device for the guest VM can be enabled by appending the
string :code:`-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3` to
QEMU options. The guest-cid value is a connection identifier that
needs to be unique for the system. In other words, when fuzzing with
multiple workers, each `QEMU` instance must use a separate guest-cid.
For kAFL we have added some syntax magic to allow for these
kinds of situations. In your :code:`kafl_config.yaml` (by default found in
:code:`$BKC_ROOT/bkc/kafl/kafl_config.yaml`),  the following string can be
appended to the :code:`qemu_base` entry: :code:`-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={QEMU_ID + 3}`.
The expression :code:`QEMU_ID + 3`, will evaluate to the `QEMU` worker instance id
(which is unique) plus 3. We need to add 3, since the vsock guest cid
range starts at 3. `CIDs` 0,1,2 are reserved for the hypervisor,
generally reserved, and reserved for the host respectively. Now each
fuzzing worker instance should get its own unique `CID`, allowing a
connection to be made from the guest to the host. Finally, to be able
to test vsock and setup connections, the :code:`socat` utility can be used.
While :code:`socat` can be already installed on your fuzzing system, the socat
vsock support is a recent addition and it might be required to
download or build a more recent version of socat to enable this
functionality. Pre-built binaries and the source code is available at
`socat project page <http://www.dest-unreach.org/socat/>`` To test
whether the installed :code:`socat` supports vsock execute: :code:`socat VSOCK-LISTEN:8089,fork`.

To summarize, these are the main steps to be performed on the host:

.. code-block:: bash

	modprobe vhost_vsock
	chmod 0666 /dev/vhost-vsock
	qemu: -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3

**Guest steps**. The next step in enabling :code:`virtio-vsock` fuzzing is to
set up the kAFL userspace fuzzing harness in the following way.

First, the guest kernel needs to be compiled with :code:`vsock` support
(:code:`CONFIG_VIRTIO_VSOCKET=y` and :code:`CONFIG_VHOST_VSOCK=y`). Alternatively, it
can be also enabled as a kernel module, but this will require an
additional step to load the module later. To make things easier, just
build the drivers as built-in.

Since we have opted to use the socat tool, the socat utility needs to
be enabled in guest’s busybox :code:`initrd.cpio.gz`. It can be done during
the socat built by either setting :code:`BR2_PACKAGE_SOCAT /` in the
:code:`bkc/kafl/userspace/buildroot.config`, or alternatively in
:code:`$BKC_ROOT/buildroot-2021.11` use :code:`make menuconfig` navigate to the
right menu entry, save the config, and then build using :code:`make`.

Finally, the following steps will add the correct kAFL userspace
harness. In :code:`$BKC_ROOT/sharedir`, edit your :code:`init.sh` to include the
following snippet early in the script:

.. code-block:: bash

	mount -t debugfs none /sys/kernel/debug/
	KAFL_CTL=/sys/kernel/debug/kafl
	echo “VSOCK fuzzing harness” | hcat
	echo "start"  > $KAFL_CTL/control
	socat - VSOCK-CONNECT:2:8089
	echo "done"  > $KAFL_CTL/control

Now it should be possible to start up a new `VSOCK` harness by first,
start listening on the host using :code:`socat VSOCK-LISTEN:8089,fork –`,
and then start kAFL (make sure it’s using HARNESS_NONE, as always when
using userspace harnesses) using :code:`fuzz.sh run linux-guest --debug -p1 --sharedir sharedir/`.
You should see the text :code:`VSOCK fuzzing harness`
appear in your kAFL process.

To summarize these steps can be executed to start a `VSOCK` harness:

On the guest:

.. code-block:: bash

	socat VSOCK-LISTEN:8089,fork –

On the host:

.. code-block:: bash

	socat - vsock-accept:3:8089

On the guest:

.. code-block:: bash

	socat - VSOCK-CONNECT:2:8089

On the host:

.. code-block:: bash

	socat VSOCK-LISTEN:8089,fork –

It is also likely that in the above-mentioned setup the kAFL fuzzer
will not make any progress. This is due to the fact that the inputs
are not stable. This happens due to the fact that an external process
is part of the fuzzing setup. If you encounter this issue, you might
need to modify kAFL slightly. In the function :code:`execute()` in
:code:`$BKC_ROOT/kafl/fuzzer/kafl_fuzzer/worker/worker.py`, when a value is
assigned to the variable :code:`stable`, make sure to overwrite this with
True. It is also possible to add a custom command line flag enabling
this feature to the kAFL settings in
:code:`$BKC_ROOT/kafl/fuzzer/kafl_fuzzer/common/config.py`.

The above example for the :code:`virtio-vsock` has demonstrated how to enable
fuzzing in a more complex driver setup scenario using a userspace kAFL
harness. The end output of the fuzzing step is a set of reproducible
crashes that a fuzzer finds for the given driver. The crashes needs to
be investigated and the ones that are determined to be real security
issues need to be fixed in the code.

Perform code fixes
------------------

Based on the above steps 2 and 3, a set of hardening patches
need to be created to fix the identified issues. We strongly encourage to submit
any such hardening patches to the mainline Linux kernel to ensure
everyone benefits
the joint hardened kernel, as well to get suggestions on the most
appropriate way of
fixing these issues. Also in order to verify that the issues have been
addressed by
respective patches, a new round of fuzzing needs to be performed to
verify that the
issues found in step 3 are not reproducible anymore.

Enable driver in the TDX filter
-------------------------------

When the driver code has been hardened and all
the patches are integrated and verified, the driver can be enabled in
the TDX guest by modifying
the allow list in the TDX driver filter code in `arch/x86/kernel/tdx-filter.c <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/arch/x86/kernel/tdx-filter.c>`_.

**Example**. For the virtio-vsock driver the following patch adds it
to the list of allowed devices on the virtio bus.

.. code-block:: diff

	Vsock driver has been audited, add it to the allow list in the TDX device
	filter.

	Signed-off-by: Alexander Shishkin <alexander.shishkin@linux.intel.com>
	---
	arch/x86/kernel/tdx-filter.c    | 1 +
	include/uapi/linux/virtio_ids.h | 1 +
	2 files changed, 2 insertions(+)

	diff --git a/arch/x86/kernel/tdx-filter.c b/arch/x86/kernel/tdx-filter.c
	index 47fda826aec4..fd759680bd2a 100644
	--- a/arch/x86/kernel/tdx-filter.c
	+++ b/arch/x86/kernel/tdx-filter.c
	@@ -64,6 +64,7 @@ struct pci_device_id pci_allow_ids[] = {
	  { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_BLOCK) },
	  { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_CONSOLE) },
	  { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_9P) },
	+ { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_VSOCK) },
	  { 0, },
	};

	diff --git a/include/uapi/linux/virtio_ids.h b/include/uapi/linux/virtio_ids.h
	index a2fcb4681028..f592efd82450 100644
	--- a/include/uapi/linux/virtio_ids.h
	+++ b/include/uapi/linux/virtio_ids.h
	@@ -88,5 +88,6 @@
	#define VIRTIO1_ID_BLOCK 0x1042 /* transitional virtio block */
	#define VIRTIO1_ID_CONSOLE 0x1043 /* transitional virtio console */
	#define VIRTIO1_ID_9P 0x1049 /* transitional virtio 9p console */
	+ #define VIRTIO1_ID_VSOCK 0x1053 /* transitional virtio vsock transport */

	#endif /* _LINUX_VIRTIO_IDS_H */
	--
	2.25.1
