#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0083. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187326);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/26");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2021-33655",
    "CVE-2021-33656",
    "CVE-2022-0171",
    "CVE-2022-0494",
    "CVE-2022-0500",
    "CVE-2022-0995",
    "CVE-2022-1012",
    "CVE-2022-1184",
    "CVE-2022-1462",
    "CVE-2022-1652",
    "CVE-2022-1679",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1786",
    "CVE-2022-1789",
    "CVE-2022-1836",
    "CVE-2022-1966",
    "CVE-2022-1972",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-2078",
    "CVE-2022-2153",
    "CVE-2022-2318",
    "CVE-2022-2503",
    "CVE-2022-2585",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-2602",
    "CVE-2022-2639",
    "CVE-2022-2663",
    "CVE-2022-2905",
    "CVE-2022-2959",
    "CVE-2022-2978",
    "CVE-2022-3028",
    "CVE-2022-3061",
    "CVE-2022-3169",
    "CVE-2022-3176",
    "CVE-2022-3435",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3534",
    "CVE-2022-3535",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3564",
    "CVE-2022-3565",
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-3621",
    "CVE-2022-3623",
    "CVE-2022-3625",
    "CVE-2022-3628",
    "CVE-2022-3629",
    "CVE-2022-3633",
    "CVE-2022-3635",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-4378",
    "CVE-2022-4696",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-21499",
    "CVE-2022-21505",
    "CVE-2022-23816",
    "CVE-2022-26365",
    "CVE-2022-26373",
    "CVE-2022-28893",
    "CVE-2022-29581",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-32250",
    "CVE-2022-32296",
    "CVE-2022-32981",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-33743",
    "CVE-2022-33744",
    "CVE-2022-34918",
    "CVE-2022-36123",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-39189",
    "CVE-2022-39190",
    "CVE-2022-39842",
    "CVE-2022-40307",
    "CVE-2022-40768",
    "CVE-2022-41222",
    "CVE-2022-41674",
    "CVE-2022-42719",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722",
    "CVE-2022-42895",
    "CVE-2022-42896",
    "CVE-2022-43750"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");

  script_name(english:"NewStart CGSL MAIN 6.06 : kernel Multiple Vulnerabilities (NS-SA-2023-0083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.06, has kernel packages installed that are affected by multiple
vulnerabilities:

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - When setting font with malicous data by ioctl cmd PIO_FONT,kernel will write memory out of bounds.
    (CVE-2021-33656)

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root
    (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD
    CPU that supports Secure Encrypted Virtualization (SEV). (CVE-2022-0171)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A flaw was found in unrestricted eBPF usage by the BPF_BTF_LOAD, leading to a possible out-of-bounds
    memory write in the Linux kernel's BPF subsystem due to the way a user loads BTF. This flaw allows a local
    user to crash or escalate their privileges on the system. (CVE-2022-0500)

  - An out-of-bounds (OOB) memory write flaw was found in the Linux kernel's watch_queue event notification
    subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain
    privileged access or cause a denial of service on the system. (CVE-2022-0995)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a
    user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage
    of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read
    unauthorized random data from memory. (CVE-2022-1462)

  - Linux Kernel could allow a local attacker to execute arbitrary code on the system, caused by a concurrency
    use-after-free flaw in the bad_flp_intr function. By executing a specially-crafted program, an attacker
    could exploit this vulnerability to execute arbitrary code or cause a denial of service condition on the
    system. (CVE-2022-1652)

  - A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user
    forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local
    user to crash or potentially escalate their privileges on the system. (CVE-2022-1679)

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use
    after free both read or write when non synchronized between cleanup routine and firmware download routine.
    (CVE-2022-1734)

  - A use-after-free flaw was found in the Linux kernel's io_uring subsystem in the way a user sets up a ring
    with IORING_SETUP_IOPOLL with more than one task completing submissions on this ring. This flaw allows a
    local user to crash or escalate their privileges on the system. (CVE-2022-1786)

  - With shadow paging enabled, the INVPCID instruction results in a call to kvm_mmu_invpcid_gva. If INVPCID
    is executed with CR0.PG=0, the invlpg callback is not set and the result is a NULL pointer dereference.
    (CVE-2022-1789)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2022-33981. Reason: This candidate is a
    reservation duplicate of CVE-2022-33981. Notes: All CVE users should reference CVE-2022-33981 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage (CVE-2022-1836)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2022-32250. Reason: This candidate is a
    duplicate of CVE-2022-32250. Notes: All CVE users should reference CVE-2022-32250 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2022-1966)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2022-2078. Reason: This candidate is a
    reservation duplicate of CVE-2022-2078. Notes: All CVE users should reference CVE-2022-2078 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage (CVE-2022-1972)

  - A use-after-free flaw was found in the Linux kernel's NFC core functionality due to a race condition
    between kobject creation and delete. This vulnerability allows a local attacker with CAP_NET_ADMIN
    privilege to leak kernel information. (CVE-2022-1974)

  - There is a sleep-in-atomic bug in /net/nfc/netlink.c that allows an attacker to crash the Linux kernel by
    simulating a nfc device from user-space. (CVE-2022-1975)

  - A vulnerability was found in the Linux kernel's nft_set_desc_concat_parse() function .This flaw allows an
    attacker to trigger a buffer overflow via nft_set_desc_concat_parse() , causing a denial of service and
    possibly to run code. (CVE-2022-2078)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - KGDB and KDB allow read and write access to kernel memory, and thus should be restricted during lockdown.
    An attacker with access to a serial port could trigger the debugger so it is important that the debugger
    respect the lockdown mode when/if it is triggered. (CVE-2022-21499)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - There are use-after-free vulnerabilities caused by timer handler in net/rose/rose_timer.c of linux that
    allow attackers to crash linux kernel without any privileges. (CVE-2022-2318)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by
    its CNA. Notes: none. (CVE-2022-23816)

  - Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to
    restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently
    allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass
    verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and
    unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for
    peripherals that do not verify firmware updates. We recommend upgrading past commit
    4caae58406f8ceb741603eee460d79bacca9b1b5 (CVE-2022-2503)

  - Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text
    explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device
    frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740).
    Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to
    unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend
    (CVE-2022-33741, CVE-2022-33742). (CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow
    an authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - The SUNRPC subsystem in the Linux kernel through 5.17.2 can call xs_xprt_free before ensuring that sockets
    are in the intended state. (CVE-2022-28893)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - A race condition was found in the Linux kernel's watch queue due to a missing lock in pipe_resize_ring().
    The specific flaw exists within the handling of pipe buffers. The issue results from the lack of proper
    locking when performing operations on an object. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-2959)

  - A flaw use after free in the Linux kernel NILFS file system was found in the way user triggers function
    security_inode_alloc to fail with following call to function nilfs_mdt_destroy. A local user could use
    this flaw to crash the system or potentially escalate their privileges on the system. (CVE-2022-2978)

  - Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution
    under certain microarchitecture-dependent conditions. (CVE-2022-29900)

  - Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29901)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - Found Linux Kernel flaw in the i740 driver. The Userspace program could pass any values to the driver
    through ioctl() interface. The driver doesn't check the value of 'pixclock', so it may cause a divide by
    zero error. (CVE-2022-3061)

  - A flaw was found in the Linux kernel. A denial of service flaw may occur if there is a consecutive request
    of the NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
    in a PCIe link disconnect. (CVE-2022-3169)

  - There exists a use-after-free in io_uring in the Linux kernel. Signalfd_poll() and binder_poll() use a
    waitqueue whose lifetime is the current task. It will send a POLLFREE notification to all waiters before
    the queue is freed. Unfortunately, the io_uring poll doesn't handle POLLFREE. This allows a use-after-free
    to occur if a signalfd or binder fd is polled with io_uring poll, and the waitqueue gets freed. We
    recommend upgrading past commit fc78b2fc21f10c4c9c4d5d659a685710ffa63659 (CVE-2022-3176)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. This occurs because of use of Algorithm 4 (Double-Hash Port Selection Algorithm) of RFC 6056.
    (CVE-2022-32296)

  - An issue was discovered in the Linux kernel through 5.18.3 on powerpc 32-bit platforms. There is a buffer
    overflow in ptrace PEEKUSER and POKEUSER (aka PEEKUSR and POKEUSR) when accessing floating point
    registers. (CVE-2022-32981)

  - network backend may cause Linux netfront to use freed SKBs While adding logic to support XDP (eXpress Data
    Path), a code label was moved in a way allowing for SKBs having references (pointers) retained for further
    processing to nevertheless be freed. (CVE-2022-33743)

  - Arm guests can cause Dom0 DoS via PV devices When mapping pages of guests on Arm, dom0 is using an rbtree
    to keep track of the foreign mappings. Updating of that rbtree is not always done completely with the
    related lock held, resulting in a small race window, which can be used by unprivileged guests via PV
    devices to cause inconsistencies of the rbtree. These inconsistencies can lead to Denial of Service (DoS)
    of dom0, e.g. by causing crashes or the inability to perform further mappings of other guests' memory
    pages. (CVE-2022-33744)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init
    (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different
    vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an
    unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data
    in net/netfilter/nf_tables_api.c. (CVE-2022-34918)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability classified as critical has been found in Linux Kernel. Affected is the function
    btf_dump_name_dups of the file tools/lib/bpf/btf_dump.c of the component libbpf. The manipulation leads to
    use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability
    is VDB-211032. (CVE-2022-3534)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn
    by its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2022-3535,
    CVE-2022-3542)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the
    function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated
    identifier of this vulnerability is VDB-211087. (CVE-2022-3564)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function
    tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It
    is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this
    vulnerability. (CVE-2022-3566)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier
    assigned to this vulnerability. (CVE-2022-3567)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - The Linux kernel before 5.18.13 lacks a certain clear operation for the block starting symbol (.bss). This
    allows Xen PV guest OS users to cause a denial of service or gain privileges. (CVE-2022-36123)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_bmap_lookup_at_level of the file fs/nilfs2/inode.c of the component nilfs2. The manipulation leads
    to null pointer dereference. It is possible to launch the attack remotely. It is recommended to apply a
    patch to fix this issue. The identifier of this vulnerability is VDB-211920. (CVE-2022-3621)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A buffer overflow flaw was found in the Linux kernel Broadcom Full MAC Wi-Fi driver. This issue occurs
    when a user connects to a malicious USB device. This can allow a local user to crash the system or
    escalate their privileges. (CVE-2022-3628)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak.
    The complexity of an attack is rather high. The exploitation appears to be difficult. It is recommended to
    apply a patch to fix this issue. VDB-211930 is the identifier assigned to this vulnerability.
    (CVE-2022-3629)

  - A vulnerability classified as problematic has been found in Linux Kernel. Affected is the function
    j1939_session_destroy of the file net/can/j1939/transport.c. The manipulation leads to memory leak. It is
    recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211932.
    (CVE-2022-3633)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation
    leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the
    identifier assigned to this vulnerability. (CVE-2022-3635)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

  - An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users
    can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED
    situations. (CVE-2022-39189)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

  - An issue was discovered in the Linux kernel before 5.19. In pxa3xx_gcu_write in
    drivers/video/fbdev/pxa3xx-gcu.c, the count parameter has a type conflict of size_t versus int, causing an
    integer overflow and bypassing the size check. After that, because it is used as the third argument to
    copy_from_user(), a heap overflow may occur. NOTE: the original discoverer disputes that the overflow can
    actually happen. (CVE-2022-39842)

  - An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a
    race condition with a resultant use-after-free. (CVE-2022-40307)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

  - mm/mremap.c in the Linux kernel before 5.13.3 has a use-after-free via a stale TLB because an rmap lock is
    not held during a PUD move. (CVE-2022-41222)

  - An issue was discovered in the Linux kernel before 5.19.16. Attackers able to inject WLAN frames could
    cause a buffer overflow in the ieee80211_bss_info_update function in net/mac80211/scan.c. (CVE-2022-41674)

  - A use-after-free in the mac80211 stack when parsing a multi-BSSID element in the Linux kernel 5.2 through
    5.19.x before 5.19.16 could be used by attackers (able to inject WLAN frames) to crash the kernel and
    potentially execute code. (CVE-2022-42719)

  - Various refcounting bugs in the multi-BSS handling in the mac80211 stack in the Linux kernel 5.1 through
    5.19.x before 5.19.16 could be used by local attackers (able to inject WLAN frames) to trigger use-after-
    free conditions to potentially execute code. (CVE-2022-42720)

  - A list management bug in BSS handling in the mac80211 stack in the Linux kernel 5.1 through 5.19.x before
    5.19.16 could be used by local attackers (able to inject WLAN frames) to corrupt a linked list and, in
    turn, potentially execute code. (CVE-2022-42721)

  - In the Linux kernel 5.8 through 5.19.x before 5.19.16, local attackers able to inject WLAN frames into the
    mac80211 stack could cause a NULL pointer dereference denial-of-service attack against the beacon
    protection of P2P devices. (CVE-2022-42722)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain
    kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2022-4378)

  - There exists a use-after-free vulnerability in the Linux kernel through io_uring and the IORING_OP_SPLICE
    operation. If IORING_OP_SPLICE is missing the IO_WQ_WORK_FILES flag, which signals that the operation
    won't use current->nsproxy, so its reference counter is not increased. This assumption is not always true
    as calling io_splice on specific files will call the get_uts function which will use current->nsproxy
    leading to invalidly decreasing its reference counter later causing the use-after-free vulnerability. We
    recommend upgrading to version 5.10.160 or above (CVE-2022-4696)

  - An out-of-bounds write flaw was found in the Linux kernel's framebuffer-based console driver
    functionality in the way a user triggers ioctl FBIOPUT_VSCREENINFO with malicious data. This flaw allows a
    local user to crash or potentially escalate their privileges on the system. (CVE-2021-33655)
    (CVE-2022-21505)

  - kernel: posix cpu timer use-after-free may lead to local privilege escalation (CVE-2022-2585)

  - kernel: nf_tables cross-table potential use-after-free may lead to local privilege escalation
    (CVE-2022-2586)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - 2023-08-03: CVE-2023-3812 was added to this advisory. (CVE-2022-2602)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0083");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33655");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-33656");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0171");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0494");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0500");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-0995");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1462");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1786");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1789");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1836");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1966");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1972");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2078");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-21499");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-21505");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2318");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-23816");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2503");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2585");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2602");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26365");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28893");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2905");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29581");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2959");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2978");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3061");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3169");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3176");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-32296");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-32981");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-33740");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-33741");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-33742");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-33743");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-33744");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3435");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-34918");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3521");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3524");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3534");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3535");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3564");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3566");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3567");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-36123");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3621");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3623");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3625");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3628");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3629");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3633");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3635");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3646");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-3649");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-39189");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-39190");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-39842");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40307");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-40768");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41222");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41674");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42719");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42720");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42721");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42722");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42895");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-42896");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-43750");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4378");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-4696");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34918");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Watch Queue Out of Bounds Write');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kata-linux-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.06': [
    'bpftool-5.10.134-13.1.zncgsl6.t2.0',
    'kata-linux-container-5.10.134-13.1.zncgsl6kata.t2.0',
    'kernel-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-core-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-devel-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-headers-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-modules-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-modules-extra-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-tools-5.10.134-13.1.zncgsl6.t2.0',
    'kernel-tools-libs-5.10.134-13.1.zncgsl6.t2.0',
    'perf-5.10.134-13.1.zncgsl6.t2.0',
    'python3-perf-5.10.134-13.1.zncgsl6.t2.0'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
