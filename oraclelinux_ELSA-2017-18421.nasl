#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2017-1842-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-18421.
##

include('compat.inc');

if (description)
{
  script_id(180805);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2014-7970",
    "CVE-2014-7975",
    "CVE-2015-8839",
    "CVE-2015-8970",
    "CVE-2016-6213",
    "CVE-2016-7042",
    "CVE-2016-7097",
    "CVE-2016-8645",
    "CVE-2016-9576",
    "CVE-2016-9588",
    "CVE-2016-9604",
    "CVE-2016-9685",
    "CVE-2016-9806",
    "CVE-2016-10088",
    "CVE-2016-10147",
    "CVE-2016-10200",
    "CVE-2017-2596",
    "CVE-2017-2647",
    "CVE-2017-2671",
    "CVE-2017-5970",
    "CVE-2017-6001",
    "CVE-2017-6951",
    "CVE-2017-7187",
    "CVE-2017-7616",
    "CVE-2017-7889",
    "CVE-2017-8797",
    "CVE-2017-8890",
    "CVE-2017-9074",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077",
    "CVE-2017-9242"
  );

  script_name(english:"Oracle Linux 7 : ELSA-2017-1842-1: / kernel (ELSA-2017-18421) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2017-18421 advisory.

  - The do_umount function in fs/namespace.c in the Linux kernel through 3.17 does not require the
    CAP_SYS_ADMIN capability for do_remount_sb calls that change the root filesystem to read-only, which
    allows local users to cause a denial of service (loss of writability) by making certain unshare system
    calls, clearing the / MNT_LOCKED flag, and making an MNT_FORCE umount system call. (CVE-2014-7975)

  - The proc_keys_show function in security/keys/proc.c in the Linux kernel through 4.8.2, when the GNU
    Compiler Collection (gcc) stack protector is enabled, uses an incorrect buffer size for certain timeout
    data, which allows local users to cause a denial of service (stack memory corruption and panic) by reading
    the /proc/keys file. (CVE-2016-7042)

  - Race condition in the netlink_dump function in net/netlink/af_netlink.c in the Linux kernel before 4.6.3
    allows local users to cause a denial of service (double free) or possibly have unspecified other impact
    via a crafted application that makes sendmsg system calls, leading to a free operation associated with a
    new dump that started earlier than anticipated. (CVE-2016-9806)

  - The blk_rq_map_user_iov function in block/blk-map.c in the Linux kernel before 4.8.14 does not properly
    restrict the type of iterator, which allows local users to read or write to arbitrary kernel memory
    locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg device.
    (CVE-2016-9576)

  - The sg implementation in the Linux kernel through 4.9 does not properly restrict write operations in
    situations where the KERNEL_DS option is set, which allows local users to read or write to arbitrary
    kernel memory locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2016-9576. (CVE-2016-10088)

  - The filesystem implementation in the Linux kernel through 4.8.2 preserves the setgid bit during a setxattr
    call, which allows local users to gain group privileges by leveraging the existence of a setgid program
    with restrictions on execute permissions. (CVE-2016-7097)

  - The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel through 4.10.4 allows local users to cause
    a denial of service (stack-based buffer overflow) or possibly have unspecified other impact via a large
    command size in an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds write access in the sg_write
    function. (CVE-2017-7187)

  - crypto/mcryptd.c in the Linux kernel before 4.8.15 allows local users to cause a denial of service (NULL
    pointer dereference and system crash) by using an AF_ALG socket with an incompatible algorithm, as
    demonstrated by mcryptd(md5). (CVE-2016-10147)

  - arch/x86/kvm/vmx.c in the Linux kernel through 4.9 mismanages the #BP and #OF exceptions, which allows
    guest OS users to cause a denial of service (guest OS crash) by declining to handle an exception thrown by
    an L2 guest. (CVE-2016-9588)

  - The nested_vmx_check_vmptr function in arch/x86/kvm/vmx.c in the Linux kernel through 4.9.8 improperly
    emulates the VMXON instruction, which allows KVM L1 guest OS users to cause a denial of service (host OS
    memory consumption) by leveraging the mishandling of page references. (CVE-2017-2596)

  - The TCP stack in the Linux kernel before 4.8.10 mishandles skb truncation, which allows local users to
    cause a denial of service (system crash) via a crafted application that makes sendto system calls, related
    to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c. (CVE-2016-8645)

  - The ipv4_pktinfo_prepare function in net/ipv4/ip_sockglue.c in the Linux kernel through 4.9.9 allows
    attackers to cause a denial of service (system crash) via (1) an application that makes crafted system
    calls or possibly (2) IPv4 traffic with invalid IP options. (CVE-2017-5970)

  - Race condition in kernel/events/core.c in the Linux kernel before 4.9.7 allows local users to gain
    privileges via a crafted application that makes concurrent perf_event_open system calls for moving a
    software group into a hardware context. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2016-6786. (CVE-2017-6001)

  - The KEYS subsystem in the Linux kernel before 3.18 allows local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash) via vectors involving a NULL value for a certain
    match field, related to the keyring_search_iterator function in keyring.c. (CVE-2017-2647)

  - The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15
    allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by
    leveraging use of the accept system call. (CVE-2017-8890)

  - The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel through 4.11.1 mishandles
    inheritance, which allows local users to cause a denial of service or possibly have unspecified other
    impact via crafted system calls, a related issue to CVE-2017-8890. (CVE-2017-9077)

  - The pivot_root implementation in fs/namespace.c in the Linux kernel through 3.17 does not properly
    interact with certain locations of a chroot directory, which allows local users to cause a denial of
    service (mount-tree loop) via . (dot) values in both arguments to the pivot_root system call.
    (CVE-2014-7970)

  - crypto/algif_skcipher.c in the Linux kernel before 4.4.2 does not verify that a setkey operation has been
    performed on an AF_ALG socket before an accept system call is processed, which allows local users to cause
    a denial of service (NULL pointer dereference and system crash) via a crafted application that does not
    supply a key, related to the lrw_crypt function in crypto/lrw.c. (CVE-2015-8970)

  - Race condition in the L2TPv3 IP Encapsulation feature in the Linux kernel before 4.8.14 allows local users
    to gain privileges or cause a denial of service (use-after-free) by making multiple bind system calls
    without properly ascertaining whether a socket has the SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c
    and net/l2tp/l2tp_ip6.c. (CVE-2016-10200)

  - fs/namespace.c in the Linux kernel before 4.9 does not restrict how many mounts may exist in a mount
    namespace, which allows local users to cause a denial of service (memory consumption and deadlock) via
    MS_BIND mount system calls, as demonstrated by a loop that triggers exponential growth in the number of
    mounts. (CVE-2016-6213)

  - It was discovered in the Linux kernel before 4.11-rc8 that root can gain direct access to an internal
    keyring, such as '.dns_resolver' in RHEL-7 or '.builtin_trusted_keys' upstream, by joining it as its
    session keyring. This allows root to bypass module signature verification by adding a new public key of
    its own devising to the keyring. (CVE-2016-9604)

  - The ping_unhash function in net/ipv4/ping.c in the Linux kernel through 4.10.8 is too late in obtaining a
    certain lock and consequently cannot ensure that disconnect function calls are safe, which allows local
    users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a
    socket system call. (CVE-2017-2671)

  - The keyring_search_aux function in security/keys/keyring.c in the Linux kernel through 3.14.79 allows
    local users to cause a denial of service (NULL pointer dereference and OOPS) via a request_key system call
    for the dead type. (CVE-2017-6951)

  - Incorrect error handling in the set_mempolicy and mbind compat syscalls in mm/mempolicy.c in the Linux
    kernel through 4.10.9 allows local users to obtain sensitive information from uninitialized stack data by
    triggering failure of a certain bitmap operation. (CVE-2017-7616)

  - The mm subsystem in the Linux kernel through 3.2 does not properly enforce the CONFIG_STRICT_DEVMEM
    protection mechanism, which allows local users to read or write to kernel memory locations in the first
    megabyte (and bypass slab-allocation access restrictions) via an application that opens the /dev/mem file,
    related to arch/x86/mm/init.c and drivers/char/mem.c. (CVE-2017-7889)

  - The IPv6 fragmentation implementation in the Linux kernel through 4.11.1 does not consider that the
    nexthdr field may be associated with an invalid option, which allows local users to cause a denial of
    service (out-of-bounds read and BUG) or possibly have unspecified other impact via crafted socket and send
    system calls. (CVE-2017-9074)

  - The dccp_v6_request_recv_sock function in net/dccp/ipv6.c in the Linux kernel through 4.11.1 mishandles
    inheritance, which allows local users to cause a denial of service or possibly have unspecified other
    impact via crafted system calls, a related issue to CVE-2017-8890. (CVE-2017-9076)

  - The __ip6_append_data function in net/ipv6/ip6_output.c in the Linux kernel through 4.11.3 is too late in
    checking whether an overwrite of an skb data structure may occur, which allows local users to cause a
    denial of service (system crash) via crafted system calls. (CVE-2017-9242)

  - Multiple race conditions in the ext4 filesystem implementation in the Linux kernel before 4.5 allow local
    users to cause a denial of service (disk corruption) by writing to a page that is associated with a
    different user's file after unsynchronized hole punching and page-fault handling. (CVE-2015-8839)

  - Multiple memory leaks in error paths in fs/xfs/xfs_attr_list.c in the Linux kernel before 4.5.1 allow
    local users to cause a denial of service (memory consumption) via crafted XFS filesystem operations.
    (CVE-2016-9685)

  - The NFSv4 server in the Linux kernel before 4.11.3 does not properly validate the layout type when
    processing the NFSv4 pNFS GETDEVICEINFO or LAYOUTGET operand in a UDP packet from a remote attacker. This
    type value is uninitialized upon encountering certain error conditions. This value is used as an array
    index for dereferencing, which leads to an OOPS and eventually a DoS of knfsd and a soft-lockup of the
    whole system. (CVE-2017-8797)

  - The sctp_v6_create_accept_sk function in net/sctp/ipv6.c in the Linux kernel through 4.11.1 mishandles
    inheritance, which allows local users to cause a denial of service or possibly have unspecified other
    impact via crafted system calls, a related issue to CVE-2017-8890. (CVE-2017-9075)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2017-1842-1.nasl (plugin ID 102511).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-1842-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-9077");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2017-1842-1.nasl (plugin ID 102511) instead.");
