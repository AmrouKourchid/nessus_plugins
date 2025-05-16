#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1070.
##

include('compat.inc');

if (description)
{
  script_id(208490);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2015-9289",
    "CVE-2017-17807",
    "CVE-2018-7191",
    "CVE-2018-19985",
    "CVE-2018-20169",
    "CVE-2019-3901",
    "CVE-2019-9503",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-11190",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-13233",
    "CVE-2019-14283",
    "CVE-2019-14815",
    "CVE-2019-15221",
    "CVE-2019-15916",
    "CVE-2019-16746"
  );
  script_xref(name:"RHSA", value:"2020:1070");

  script_name(english:"CentOS 7 : kernel-rt (RHSA-2020:1070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:1070 advisory.

  - In the Linux kernel before 4.1.4, a buffer overflow occurs when checking userspace params in
    drivers/media/dvb-frontends/cx24116.c. The maximum size for a DiSEqC command is 6, according to the
    userspace API. However, the code allows larger values such as 23. (CVE-2015-9289)

  - The KEYS subsystem in the Linux kernel before 4.14.6 omitted an access-control check when adding a key to
    the current task's default request-key keyring via the request_key() system call, allowing a local user
    to use a sequence of crafted system calls to add keys to a keyring with only Search permission (not Write
    permission) to that keyring, related to construct_get_dest_keyring() in security/keys/request_key.c.
    (CVE-2017-17807)

  - The function hso_get_config_data in drivers/net/usb/hso.c in the Linux kernel through 4.19.8 reads if_num
    from the USB device (as a u8) and uses it to index a small array, resulting in an object out-of-bounds
    (OOB) read that potentially allows arbitrary read in the kernel address space. (CVE-2018-19985)

  - An issue was discovered in the Linux kernel before 4.19.9. The USB subsystem mishandles size checks during
    the reading of an extra descriptor, related to __usb_get_extra_descriptor in drivers/usb/core/usb.c.
    (CVE-2018-20169)

  - In the tun subsystem in the Linux kernel before 4.13.14, dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a denial of service (NULL pointer dereference and
    panic) via an ioctl(TUNSETIFF) call with a dev name containing a / character. This is similar to
    CVE-2013-4343. (CVE-2018-7191)

  - A flaw was found in the Linux kernel's Bluetooth implementation of UART, all versions kernel 3.x.x before
    4.18.0 and kernel 5.x.x. An attacker with local access and write permissions to the Bluetooth hardware
    could use this flaw to issue a specially crafted ioctl function call and cause the system to crash.
    (CVE-2019-10207)

  - In the Linux kernel before 5.1.7, a device can be tracked by an attacker using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). An attack may be conducted by hosting a crafted web page
    that uses WebRTC or gQUIC to force UDP traffic to attacker-controlled IP addresses. (CVE-2019-10638)

  - The Linux kernel 4.x (starting from 4.1) and 5.x before 5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass. Specifically, it is possible to extract the KASLR kernel
    image offset using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is exposed. This attack can be carried out remotely, by the
    attacker forcing the target device to send UDP or ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is trivial if the server is a DNS server. ICMP traffic
    is trivial if the server answers ICMP Echo requests (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used to force UDP traffic to attacker-controlled IP
    addresses. NOTE: this attack against KASLR became viable in 4.1 because IP ID generation was changed to
    have a dependency on an address associated with a network namespace. (CVE-2019-10639)

  - The Linux kernel before 4.8 allows local users to bypass ASLR on setuid programs (such as /bin/su) because
    install_exec_creds() is called too late in load_elf_binary() in fs/binfmt_elf.c, and thus the
    ptrace_may_access() check has a race condition when reading /proc/pid/stat. (CVE-2019-11190)

  - The do_hidp_sock_ioctl function in net/bluetooth/hidp/sock.c in the Linux kernel before 5.0.15 allows a
    local user to obtain potentially sensitive information from kernel stack memory via a HIDPCONNADD command,
    because a name field may not end with a '\0' character. (CVE-2019-11884)

  - An issue was discovered in drm_load_edid_firmware in drivers/gpu/drm/drm_edid_load.c in the Linux kernel
    through 5.1.5. There is an unchecked kstrdup of fwstr, which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash). NOTE: The vendor disputes this issues as not being a
    vulnerability because kstrdup() returning NULL is handled sufficiently and there is no chance for a NULL
    pointer dereference (CVE-2019-12382)

  - In arch/x86/lib/insn-eval.c in the Linux kernel before 5.1.9, there is a use-after-free for access to an
    LDT entry because of a race condition between modify_ldt() and a #BR exception for an MPX bounds
    violation. (CVE-2019-13233)

  - In the Linux kernel before 5.2.3, set_geometry in drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by
    default. (CVE-2019-14283)

  - A vulnerability was found in Linux Kernel, where a Heap Overflow was found in mwifiex_set_wmm_params()
    function of Marvell Wifi Driver. (CVE-2019-14815)

  - An issue was discovered in the Linux kernel before 5.1.17. There is a NULL pointer dereference caused by a
    malicious USB device in the sound/usb/line6/pcm.c driver. (CVE-2019-15221)

  - An issue was discovered in the Linux kernel before 5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which will cause denial of service. (CVE-2019-15916)

  - An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check
    the length of variable elements in a beacon head, leading to a buffer overflow. (CVE-2019-16746)

  - A race condition in perf_event_open() allows local attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the cred_guard_mutex) are held during the ptrace_may_access() call, it
    is possible for the specified target task to perform an execve() syscall with setuid execution before
    perf_event_alloc() actually attaches to it, allowing an attacker to bypass the ptrace_may_access() check
    and the perf_event_exit_task(current) call that is performed in install_exec_creds() during privileged
    execve() calls. This issue affects kernel versions before 4.8. (CVE-2019-3901)

  - The Broadcom brcmfmac WiFi driver prior to commit a4176ec356c73a46c07c181c6d04039fafa34a9f is vulnerable
    to a frame validation bypass. If the brcmfmac driver receives a firmware event frame from a remote source,
    the is_wlc_event_frame function will cause this frame to be discarded and unprocessed. If the driver
    receives the firmware event frame from the host, the appropriate handler is called. This frame validation
    can be bypassed if the bus used is USB (for instance by a wifi dongle). This can allow firmware event
    frames from a remote source to be processed. In the worst case scenario, by sending specially-crafted WiFi
    packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a vulnerable system.
    More typically, this vulnerability will result in denial-of-service conditions. (CVE-2019-9503)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1070");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16746");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-rt-trace-kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'kernel-rt-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-doc-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-trace-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-trace-devel-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-trace-kvm-3.10.0-1127.rt56.1093.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-debug / kernel-rt-debug-devel / etc');
}
