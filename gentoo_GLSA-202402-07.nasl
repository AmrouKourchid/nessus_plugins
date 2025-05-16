#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-07.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(189976);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/04");

  script_cve_id(
    "CVE-2021-28703",
    "CVE-2021-28704",
    "CVE-2021-28705",
    "CVE-2021-28706",
    "CVE-2021-28707",
    "CVE-2021-28708",
    "CVE-2021-28709",
    "CVE-2022-23816",
    "CVE-2022-23824",
    "CVE-2022-23825",
    "CVE-2022-26356",
    "CVE-2022-26357",
    "CVE-2022-26358",
    "CVE-2022-26359",
    "CVE-2022-26360",
    "CVE-2022-26361",
    "CVE-2022-27672",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-33746",
    "CVE-2022-33747",
    "CVE-2022-33748",
    "CVE-2022-33749",
    "CVE-2022-42309",
    "CVE-2022-42310",
    "CVE-2022-42319",
    "CVE-2022-42320",
    "CVE-2022-42321",
    "CVE-2022-42322",
    "CVE-2022-42323",
    "CVE-2022-42324",
    "CVE-2022-42325",
    "CVE-2022-42326",
    "CVE-2022-42327",
    "CVE-2022-42330",
    "CVE-2022-42331",
    "CVE-2022-42332",
    "CVE-2022-42333",
    "CVE-2022-42334",
    "CVE-2022-42335"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"GLSA-202402-07 : Xen: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-07 (Xen: Multiple Vulnerabilities)

  - grant table v2 status pages may remain accessible after de-allocation (take two) Guest get permitted
    access to certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with
    a guest for its entire lifetime. Grant table v2 status pages, however, get de-allocated when a guest
    switched (back) from v2 to v1. The freeing of such pages requires that the hypervisor know where in the
    guest these pages were mapped. The hypervisor tracks only one use within guest space, but racing requests
    from the guest to insert mappings of these pages may result in any of them to become mapped in multiple
    locations. Upon switching back from v2 to v1, the guest would then retain access to a page that was freed
    and perhaps re-used for other purposes. This bug was fortuitously fixed by code cleanup in Xen 4.14, and
    backported to security-supported Xen branches as a prerequisite of the fix for XSA-378. (CVE-2021-28703)

  - PoD operations on misaligned GFNs T[his CNA information record relates to multiple CVEs; the text explains
    which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be started in populate-
    on-demand (PoD) mode, to provide a way for them to later easily have more memory assigned. Guests are
    permitted to control certain P2M aspects of individual pages via hypercalls. These hypercalls may act on
    ranges of pages specified via page orders (resulting in a power-of-2 number of pages). The implementation
    of some of these hypercalls for PoD does not enforce the base page frame number to be suitably aligned for
    the specified order, yet some code involved in PoD handling actually makes such an assumption. These
    operations are XENMEM_decrease_reservation (CVE-2021-28704) and XENMEM_populate_physmap (CVE-2021-28707),
    the latter usable only by domains controlling the guest, i.e. a de-privileged qemu or a stub domain.
    (Patch 1, combining the fix to both these two issues.) In addition handling of XENMEM_decrease_reservation
    can also trigger a host crash when the specified page order is neither 4k nor 2M nor 1G (CVE-2021-28708,
    patch 2). (CVE-2021-28704, CVE-2021-28707, CVE-2021-28708)

  - issues with partially successful P2M updates on x86 T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be
    started in populate-on-demand (PoD) mode, to provide a way for them to later easily have more memory
    assigned. Guests are permitted to control certain P2M aspects of individual pages via hypercalls. These
    hypercalls may act on ranges of pages specified via page orders (resulting in a power-of-2 number of
    pages). In some cases the hypervisor carries out the requests by splitting them into smaller chunks. Error
    handling in certain PoD cases has been insufficient in that in particular partial success of some
    operations was not properly accounted for. There are two code paths affected - page removal
    (CVE-2021-28705) and insertion of new pages (CVE-2021-28709). (We provide one patch which combines the fix
    to both issues.) (CVE-2021-28705, CVE-2021-28709)

  - guests may exceed their designated memory limit When a guest is permitted to have close to 16TiB of
    memory, it may be able to issue hypercalls to increase its memory allocation beyond the administrator
    established limit. This is a result of a calculation done with 32-bit precision, which may overflow. It
    would then only be the overflowed (and hence small) number which gets compared against the established
    upper bound. (CVE-2021-28706)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by
    its CNA. Notes: none. (CVE-2022-23816)

  - IBPB may not prevent return branch predictions from being specified by pre-IBPB branch targets leading to
    a potential information disclosure. (CVE-2022-23824)

  - Aliases in the branch predictor may cause some AMD processors to predict the wrong branch type potentially
    leading to information disclosure. (CVE-2022-23825)

  - Racy interactions between dirty vram tracking and paging log dirty hypercalls Activation of log dirty mode
    done by XEN_DMOP_track_dirty_vram (was named HVMOP_track_dirty_vram before Xen 4.9) is racy with ongoing
    log dirty hypercalls. A suitably timed call to XEN_DMOP_track_dirty_vram can enable log dirty while
    another CPU is still in the process of tearing down the structures related to a previously enabled log
    dirty mode (XEN_DOMCTL_SHADOW_OP_OFF). This is due to lack of mutually exclusive locking between both
    operations and can lead to entries being added in already freed slots, resulting in a memory leak.
    (CVE-2022-26356)

  - race in VT-d domain ID cleanup Xen domain IDs are up to 15 bits wide. VT-d hardware may allow for only
    less than 15 bits to hold a domain ID associating a physical device with a particular domain. Therefore
    internally Xen domain IDs are mapped to the smaller value range. The cleaning up of the housekeeping
    structures has a race, allowing for VT-d domain IDs to be leaked and flushes to be bypassed.
    (CVE-2022-26357)

  - IOMMU: RMRR (VT-d) and unity map (AMD-Vi) handling issues T[his CNA information record relates to multiple
    CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Certain PCI devices in a
    system might be assigned Reserved Memory Regions (specified via Reserved Memory Region Reporting, RMRR)
    for Intel VT-d or Unity Mapping ranges for AMD-Vi. These are typically used for platform tasks such as
    legacy USB emulation. Since the precise purpose of these regions is unknown, once a device associated with
    such a region is active, the mappings of these regions need to remain continuouly accessible by the
    device. This requirement has been violated. Subsequent DMA or interrupts from the device may have
    unpredictable behaviour, ranging from IOMMU faults to memory corruption. (CVE-2022-26358, CVE-2022-26359,
    CVE-2022-26360, CVE-2022-26361)

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution
    under certain microarchitecture-dependent conditions. (CVE-2022-29900)

  - Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29901)

  - P2M pool freeing may take excessively long The P2M pool backing second level address translation for
    guests may be of significant size. Therefore its freeing may take more time than is reasonable without
    intermediate preemption checks. Such checking for the need to preempt was so far missing. (CVE-2022-33746)

  - Arm: unbounded memory consumption for 2nd-level page tables Certain actions require e.g. removing pages
    from a guest's P2M (Physical-to-Machine) mapping. When large pages are in use to map guest pages in the
    2nd-stage page tables, such a removal operation may incur a memory allocation (to replace a large mapping
    with individual smaller ones). These memory allocations are taken from the global memory pool. A malicious
    guest might be able to cause the global memory pool to be exhausted by manipulating its own P2M mappings.
    (CVE-2022-33747)

  - lock order inversion in transitive grant copy handling As part of XSA-226 a missing cleanup call was
    inserted on an error handling path. While doing so, locking requirements were not paid attention to. As a
    result two cooperating guests granting each other transitive grants can cause locks to be acquired nested
    within one another, but in respectively opposite order. With suitable timing between the involved grant
    copy operations this may result in the locking up of a CPU. (CVE-2022-33748)

  - XAPI open file limit DoS It is possible for an unauthenticated client on the network to cause XAPI to hit
    its file-descriptor limit. This causes XAPI to be unable to accept new requests for other (trusted)
    clients, and blocks XAPI from carrying out any tasks that require the opening of file descriptors.
    (CVE-2022-33749)

  - Xenstore: Guests can crash xenstored Due to a bug in the fix of XSA-115 a malicious guest can cause
    xenstored to use a wrong pointer during node creation in an error path, resulting in a crash of xenstored
    or a memory corruption in xenstored causing further damage. Entering the error path can be controlled by
    the guest e.g. by exceeding the quota value of maximum nodes per domain. (CVE-2022-42309)

  - Xenstore: Guests can create orphaned Xenstore nodes By creating multiple nodes inside a transaction
    resulting in an error, a malicious guest can create orphaned nodes in the Xenstore data base, as the
    cleanup after the error will not remove all nodes already created. When the transaction is committed after
    this situation, nodes without a valid parent can be made permanent in the data base. (CVE-2022-42310)

  - Xenstore: Guests can cause Xenstore to not free temporary memory When working on a request of a guest,
    xenstored might need to allocate quite large amounts of memory temporarily. This memory is freed only
    after the request has been finished completely. A request is regarded to be finished only after the guest
    has read the response message of the request from the ring page. Thus a guest not reading the response can
    cause xenstored to not free the temporary memory. This can result in memory shortages causing Denial of
    Service (DoS) of xenstored. (CVE-2022-42319)

  - Xenstore: Guests can get access to Xenstore nodes of deleted domains Access rights of Xenstore nodes are
    per domid. When a domain is gone, there might be Xenstore nodes left with access rights containing the
    domid of the removed domain. This is normally no problem, as those access right entries will be corrected
    when such a node is written later. There is a small time window when a new domain is created, where the
    access rights of a past domain with the same domid as the new one will be regarded to be still valid,
    leading to the new domain being able to get access to a node which was meant to be accessible by the
    removed domain. For this to happen another domain needs to write the node before the newly created domain
    is being introduced to Xenstore by dom0. (CVE-2022-42320)

  - Xenstore: Guests can crash xenstored via exhausting the stack Xenstored is using recursion for some
    Xenstore operations (e.g. for deleting a sub-tree of Xenstore nodes). With sufficiently deep nesting
    levels this can result in stack exhaustion on xenstored, leading to a crash of xenstored. (CVE-2022-42321)

  - Xenstore: Cooperating guests can create arbitrary numbers of nodes T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Since the fix of
    XSA-322 any Xenstore node owned by a removed domain will be modified to be owned by Dom0. This will allow
    two malicious guests working together to create an arbitrary number of Xenstore nodes. This is possible by
    domain A letting domain B write into domain A's local Xenstore tree. Domain B can then create many nodes
    and reboot. The nodes created by domain B will now be owned by Dom0. By repeating this process over and
    over again an arbitrary number of nodes can be created, as Dom0's number of nodes isn't limited by
    Xenstore quota. (CVE-2022-42322, CVE-2022-42323)

  - Oxenstored 32->31 bit integer truncation issues Integers in Ocaml are 63 or 31 bits of signed precision.
    The Ocaml Xenbus library takes a C uint32_t out of the ring and casts it directly to an Ocaml integer. In
    64-bit Ocaml builds this is fine, but in 32-bit builds, it truncates off the most significant bit, and
    then creates unsigned/signed confusion in the remainder. This in turn can feed a negative value into logic
    not expecting a negative value, resulting in unexpected exceptions being thrown. The unexpected exception
    is not handled suitably, creating a busy-loop trying (and failing) to take the bad packet out of the
    xenstore ring. (CVE-2022-42324)

  - Xenstore: Guests can create arbitrary number of nodes via transactions T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] In
    case a node has been created in a transaction and it is later deleted in the same transaction, the
    transaction will be terminated with an error. As this error is encountered only when handling the deleted
    node at transaction finalization, the transaction will have been performed partially and without updating
    the accounting information. This will enable a malicious guest to create arbitrary number of nodes.
    (CVE-2022-42325, CVE-2022-42326)

  - x86: unintended memory sharing between guests On Intel systems that support the virtualize APIC accesses
    feature, a guest can read and write the global shared xAPIC page by moving the local APIC out of xAPIC
    mode. Access to this shared page bypasses the expected isolation that should exist between two guests.
    (CVE-2022-42327)

  - Guests can cause Xenstore crash via soft reset When a guest issues a Soft Reset (e.g. for performing a
    kexec) the libxl based Xen toolstack will normally perform a XS_RELEASE Xenstore operation. Due to a bug
    in xenstored this can result in a crash of xenstored. Any other use of XS_RELEASE will have the same
    impact. (CVE-2022-42330)

  - x86: speculative vulnerability in 32bit SYSCALL path Due to an oversight in the very original
    Spectre/Meltdown security work (XSA-254), one entrypath performs its speculation-safety actions too late.
    In some configurations, there is an unprotected RET instruction which can be attacked with a variety of
    speculative attacks. (CVE-2022-42331)

  - x86 shadow plus log-dirty mode use-after-free In environments where host assisted address translation is
    necessary but Hardware Assisted Paging (HAP) is unavailable, Xen will run guests in so called shadow mode.
    Shadow mode maintains a pool of memory used for both shadow page tables as well as auxiliary data
    structures. To migrate or snapshot guests, Xen additionally runs them in so called log-dirty mode. The
    data structures needed by the log-dirty tracking are part of aformentioned auxiliary data. In order to
    keep error handling efforts within reasonable bounds, for operations which may require memory allocations
    shadow mode logic ensures up front that enough memory is available for the worst case requirements.
    Unfortunately, while page table memory is properly accounted for on the code path requiring the potential
    establishing of new shadows, demands by the log-dirty infrastructure were not taken into consideration. As
    a result, just established shadow page tables could be freed again immediately, while other code is still
    accessing them on the assumption that they would remain allocated. (CVE-2022-42332)

  - x86/HVM pinned cache attributes mis-handling T[his CNA information record relates to multiple CVEs; the
    text explains which aspects/vulnerabilities correspond to which CVE.] To allow cachability control for HVM
    guests with passed through devices, an interface exists to explicitly override defaults which would
    otherwise be put in place. While not exposed to the affected guests themselves, the interface specifically
    exists for domains controlling such guests. This interface may therefore be used by not fully privileged
    entities, e.g. qemu running deprivileged in Dom0 or qemu running in a so called stub-domain. With this
    exposure it is an issue that - the number of the such controlled regions was unbounded (CVE-2022-42333), -
    installation and removal of such regions was not properly serialized (CVE-2022-42334). (CVE-2022-42333,
    CVE-2022-42334)

  - x86 shadow paging arbitrary pointer dereference In environments where host assisted address translation is
    necessary but Hardware Assisted Paging (HAP) is unavailable, Xen will run guests in so called shadow mode.
    Due to too lax a check in one of the hypervisor routines used for shadow page handling it is possible for
    a guest with a PCI device passed through to cause the hypervisor to access an arbitrary pointer partially
    under guest control. (CVE-2022-42335)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-07");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=754105");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=757126");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=826998");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=837575");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=858122");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876790");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=879031");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903624");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905389");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915970");
  script_set_attribute(attribute:"solution", value:
"All Xen users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/xen-4.16.6_pre1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28709");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'app-emulation/xen',
    'unaffected' : make_list("ge 4.16.6_pre1"),
    'vulnerable' : make_list("lt 4.16.6_pre1")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Xen');
}
