#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(202393);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_cve_id(
    "CVE-2021-47459",
    "CVE-2024-27010",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36244"
  );

  script_name(english:"CentOS 9 : kernel-5.14.0-479.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for bpftool.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
kernel-5.14.0-479.el9 build changelog.

  - In the Linux kernel, the following vulnerability has been resolved: can: j1939: j1939_netdev_start(): fix
    UAF for rx_kref of j1939_priv It will trigger UAF for rx_kref of j1939_priv as following. cpu0 cpu1
    j1939_sk_bind(socket0, ndev0, ...) j1939_netdev_start j1939_sk_bind(socket1, ndev0, ...)
    j1939_netdev_start j1939_priv_set j1939_priv_get_by_ndev_locked j1939_jsk_add ..... j1939_netdev_stop
    kref_put_lock(&priv->rx_kref, ...) kref_get(&priv->rx_kref, ...) REFCOUNT_WARN(addition on 0;...)
    ==================================================== refcount_t: addition on 0; use-after-free. WARNING:
    CPU: 1 PID: 20874 at lib/refcount.c:25 refcount_warn_saturate+0x169/0x1e0 RIP:
    0010:refcount_warn_saturate+0x169/0x1e0 Call Trace: j1939_netdev_start+0x68b/0x920
    j1939_sk_bind+0x426/0xeb0 ? security_socket_bind+0x83/0xb0 The rx_kref's kref_get() and kref_put() should
    use j1939_netdev_lock to protect. (CVE-2021-47459)

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: Fix mirred deadlock on
    device recursion When the mirred action is used on a classful egress qdisc and a packet is mirrored or
    redirected to self we hit a qdisc lock deadlock. See trace below. [..... other info removed for
    brevity....] [ 82.890906] [ 82.890906] ============================================ [ 82.890906] WARNING:
    possible recursive locking detected [ 82.890906] 6.8.0-05205-g77fadd89fe2d-dirty #213 Tainted: G W [
    82.890906] -------------------------------------------- [ 82.890906] ping/418 is trying to acquire lock: [
    82.890906] ffff888006994110 (&sch->q.lock){+.-.}-{3:3}, at: __dev_queue_xmit+0x1778/0x3550 [ 82.890906] [
    82.890906] but task is already holding lock: [ 82.890906] ffff888006994110 (&sch->q.lock){+.-.}-{3:3}, at:
    __dev_queue_xmit+0x1778/0x3550 [ 82.890906] [ 82.890906] other info that might help us debug this: [
    82.890906] Possible unsafe locking scenario: [ 82.890906] [ 82.890906] CPU0 [ 82.890906] ---- [ 82.890906]
    lock(&sch->q.lock); [ 82.890906] lock(&sch->q.lock); [ 82.890906] [ 82.890906] *** DEADLOCK *** [
    82.890906] [..... other info removed for brevity....] Example setup (eth0->eth0) to recreate tc qdisc add
    dev eth0 root handle 1: htb default 30 tc filter add dev eth0 handle 1: protocol ip prio 2 matchall \
    action mirred egress redirect dev eth0 Another example(eth0->eth1->eth0) to recreate tc qdisc add dev eth0
    root handle 1: htb default 30 tc filter add dev eth0 handle 1: protocol ip prio 2 matchall \ action mirred
    egress redirect dev eth1 tc qdisc add dev eth1 root handle 1: htb default 30 tc filter add dev eth1 handle
    1: protocol ip prio 2 matchall \ action mirred egress redirect dev eth0 We fix this by adding an owner
    field (CPU id) to struct Qdisc set after root qdisc is entered. When the softirq enters it a second time,
    if the qdisc owner is the same CPU, the packet is dropped to break the loop. (CVE-2024-27010)

  - In the Linux kernel, the following vulnerability has been resolved: tty: n_gsm: fix possible out-of-bounds
    in gsm0_receive() Assuming the following: - side A configures the n_gsm in basic option mode - side B
    sends the header of a basic option mode frame with data length 1 - side A switches to advanced option mode
    - side B sends 2 data bytes which exceeds gsm->len Reason: gsm->len is not used in advanced option mode. -
    side A switches to basic option mode - side B keeps sending until gsm0_receive() writes past gsm->buf
    Reason: Neither gsm->state nor gsm->len have been reset after reconfiguration. Fix this by changing
    gsm->count to gsm->len comparison from equal to less than. Also add upper limit checks against the
    constant MAX_MRU in gsm0_receive() and gsm1_receive() to harden against memory corruption of gsm->len and
    gsm->mru. All other checks remain as we still need to limit the data according to the user configuration
    and actual payload size. (CVE-2024-36016)

  - In the Linux kernel, the following vulnerability has been resolved: rtnetlink: Correct nested
    IFLA_VF_VLAN_LIST attribute validation Each attribute inside a nested IFLA_VF_VLAN_LIST is assumed to be a
    struct ifla_vf_vlan_info so the size of such attribute needs to be at least of sizeof(struct
    ifla_vf_vlan_info) which is 14 bytes. The current size validation in do_setvfinfo is against NLA_HDRLEN (4
    bytes) which is less than sizeof(struct ifla_vf_vlan_info) so this validation is not enough and a too
    small attribute might be cast to a struct ifla_vf_vlan_info, this might result in an out of bands read
    access when accessing the saved (casted) entry in ivvl. (CVE-2024-36017)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=65628");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream bpftool package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47459");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-64k-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-zfcpdump-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libperf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'bpftool-7.4.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.4.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.4.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-devel-matched-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-extra-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-debug-modules-partner-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-devel-matched-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-extra-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-64k-modules-partner-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-5.14.0-479.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-479.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-matched-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-core-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-internal-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-internal-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-partner-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-partner-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-partner-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-uki-virt-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-matched-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-5.14.0-479.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-ipaclones-internal-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-core-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-internal-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-internal-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-partner-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-partner-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-partner-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-matched-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-matched-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-internal-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-partner-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-partner-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-matched-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-matched-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-core-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-core-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-internal-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-partner-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-partner-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-selftests-internal-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-selftests-internal-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-selftests-internal-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uki-virt-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-core-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-matched-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-core-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-extra-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-internal-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-partner-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-devel-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-devel-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libperf-devel-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-479.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-479.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-479.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-64k / kernel-64k-core / kernel-64k-debug / etc');
}
