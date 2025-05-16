#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198188);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id(
    "CVE-2021-33631",
    "CVE-2022-48619",
    "CVE-2023-6040",
    "CVE-2023-6121",
    "CVE-2023-6531",
    "CVE-2023-6606",
    "CVE-2023-6915",
    "CVE-2023-6931",
    "CVE-2023-7192",
    "CVE-2023-51043",
    "CVE-2023-52340",
    "CVE-2023-52438",
    "CVE-2023-52527",
    "CVE-2024-0193",
    "CVE-2024-0340",
    "CVE-2024-0565",
    "CVE-2024-0607",
    "CVE-2024-0639",
    "CVE-2024-0641",
    "CVE-2024-0841",
    "CVE-2024-1086"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"EulerOS 2.0 SP12 : kernel (EulerOS-SA-2024-1741)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    In the Linux kernel, the following vulnerability has been resolved: ipv4, ipv6: Fix handling of
    transhdrlen in __ip{,6}_append_data() Including the transhdrlen in length is a problem when the packet is
    partially filled (e.g. something like send(MSG_MORE) happened previously) when appending to an IPv4 or
    IPv6 packet as we don't want to repeat the transport header or account for it twice. This can happen under
    some circumstances, such as splicing into an L2TP socket. The symptom observed is a warning in
    __ip6_append_data(): WARNING: CPU: 1 PID: 5042 at net/ipv6/ip6_output.c:1800
    __ip6_append_data.isra.0+0x1be8/0x47f0 net/ipv6/ip6_output.c:1800 that occurs when MSG_SPLICE_PAGES is
    used to append more data to an already partially occupied skbuff. The warning occurs when 'copy' is larger
    than the amount of data in the message iterator. This is because the requested length includes the
    transport header length when it shouldn't. This can be triggered by, for example: sfd = socket(AF_INET6,
    SOCK_DGRAM, IPPROTO_L2TP); bind(sfd, ...); // ::1 connect(sfd, ...); // ::1 port 7 send(sfd, buffer, 4100,
    MSG_MORE); sendfile(sfd, dfd, NULL, 1024); Fix this by only adding transhdrlen into the length if the
    write queue is empty in l2tp_ip6_sendmsg(), analogously to how UDP does things. l2tp_ip_sendmsg() looks
    like it won't suffer from this problem as it builds the UDP packet itself.(CVE-2023-52527)

    In the Linux kernel, the following vulnerability has been resolved: binder: fix use-after-free in
    shinker's callback The mmap read lock is used during the shrinker's callback, which means that using
    alloc-vma pointer isn't safe as it can race with munmap(). As of commit dd2283f2605e ('mm: mmap: zap
    pages with read mmap_sem in munmap') the mmap lock is downgraded after the vma has been isolated. I was
    able to reproduce this issue by manually adding some delays and triggering page reclaiming through the
    shrinker's debug sysfs.(CVE-2023-52438)

    A flaw in the routing table size was found in the ICMPv6 handling of  Packet Too Big . The size of the
    routing table is regulated by periodic garbage collection. However, with  Packet Too Big Messages  it is
    possible to exceed the routing table size and garbage collector threshold. A user located in the local
    network or with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6
    connections up to 95%.(CVE-2023-52340)

    A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation.The nft_verdict_init() function allows positive values as drop error
    within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when
    NF_DROP is issued with a drop error which resembles NF_ACCEPT.(CVE-2024-1086)

    A null pointer dereference flaw was found in the hugetlbfs_fill_super function in the Linux kernel
    hugetlbfs (HugeTLB pages) functionality. This issue may allow a local user to crash the system or
    potentially escalate their privileges on the system.(CVE-2024-0841)

    In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race
    condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

    A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval()
    function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes
    are written, but `dst` is an array of u32, so each element only has space for 4 bytes. That means every
    iteration overwrites part of the previous element corrupting this array of u32. This flaw allows a local
    user to cause a denial of service or potentially break NetFilter functionality.(CVE-2024-0607)

    A denial of service vulnerability due to a deadlock was found in sctp_auto_asconf_init in
    net/sctp/socket.c in the Linux kernels SCTP subsystem. This flaw allows guests with local user
    privileges to trigger a deadlock and potentially crash the system.(CVE-2024-0639)

    A Null pointer dereference problem was found in ida_free in lib/idr.c in the Linux Kernel. This issue may
    allow an attacker using this library to cause a denial of service problem due to a missing check at a
    function return.(CVE-2023-6915)

    Integer Overflow or Wraparound vulnerability in openEuler kernel on Linux (filesystem modules) allows
    Forced Integer Overflow.This issue affects openEuler kernel: from 4.19.90 before 4.19.90-2401.3, from
    5.10.0-60.18.0 before 5.10.0-183.0.0.(CVE-2021-33631)

    A denial of service vulnerability was found in tipc_crypto_key_revoke in net/tipc/crypto.c in the Linux
    kernels TIPC subsystem. This flaw allows guests with local user privileges to trigger a deadlock and
    potentially crash the system.(CVE-2024-0641)

    A use-after-free flaw was found in the Linux Kernel due to a race problem in the unix garbage collector's
    deletion of SKB races with unix_stream_read_generic() on the socket that the SKB is queued
    on.(CVE-2023-6531)

    An out-of-bounds access vulnerability involving netfilter was reported and fixed as: f1082dd31fe4
    (netfilter: nf_tables: Reject tables of unsupported family); While creating a new netfilter table, lack of
    a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function enables an
    attacker to achieve out-of-bounds access.(CVE-2023-6040)

    An out-of-bounds memory read flaw was found in receive_encrypted_standard in fs/smb/client/smb2ops.c in
    the SMB Client sub-component in the Linux Kernel. This issue occurs due to integer underflow on the memcpy
    length, leading to a denial of service.(CVE-2024-0565)

    An issue was discovered in drivers/input/input.c in the Linux kernel before 5.17.10. An attacker can cause
    a denial of service (panic) because input_set_capability mishandles the situation in which an event code
    falls outside of a bitmap.(CVE-2022-48619)

    A vulnerability was found in vhost_new_msg in drivers/vhost/vhost.c in the Linux kernel, which does not
    properly initialize memory in messages passed between virtual guests and the host operating system in the
    vhost/vhost.c:vhost_new_msg() function. This issue can allow local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net device file.(CVE-2024-0340)

    A memory leak problem was found in ctnetlink_create_conntrack in net/netfilter/nf_conntrack_netlink.c in
    the Linux Kernel. This issue may allow a local attacker with CAP_NET_ADMIN privileges to cause a denial of
    service (DoS) attack due to a refcount overflow.(CVE-2023-7192)

    A use-after-free flaw was found in the netfilter subsystem of the Linux kernel. If the catchall element is
    garbage-collected when the pipapo set is removed, the element can be deactivated twice. This can cause a
    use-after-free issue on an NFT_CHAIN object or NFT_OBJECT object, allowing a local unprivileged user with
    CAP_NET_ADMIN capability to escalate their privileges on the system.(CVE-2024-0193)

    An out-of-bounds read vulnerability was found in the NVMe-oF/TCP subsystem in the Linux kernel. This flaw
    allows a remote attacker to send a crafted TCP packet, triggering a heap-based buffer overflow that
    results in kmalloc data to be printed (and potentially leaked) to the kernel ring buffer
    (dmesg).(CVE-2023-6121)

    An out-of-bounds read vulnerability was found in smbCalcSize in fs/smb/client/netmisc.c in the Linux
    Kernel. This issue could allow a local attacker to crash the system or leak internal kernel
    information.(CVE-2023-6606)

    A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be
    exploited to achieve local privilege escalation.A perf_event's read_size can overflow, leading to an heap
    out-of-bounds increment or write in perf_read_group().(CVE-2023-6931)

Tenable has extracted the preceding description block directly from the EulerOS kernel security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1741
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47ab4938");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-1086");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-136.12.0.86.h1526.eulerosv2r12",
  "kernel-5.10.0-136.12.0.86.h1526.eulerosv2r12",
  "kernel-abi-stablelists-5.10.0-136.12.0.86.h1526.eulerosv2r12",
  "kernel-tools-5.10.0-136.12.0.86.h1526.eulerosv2r12",
  "kernel-tools-libs-5.10.0-136.12.0.86.h1526.eulerosv2r12",
  "python3-perf-5.10.0-136.12.0.86.h1526.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
