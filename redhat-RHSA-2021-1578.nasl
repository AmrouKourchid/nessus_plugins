#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1578. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149670);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2019-18811",
    "CVE-2019-19523",
    "CVE-2019-19528",
    "CVE-2020-0431",
    "CVE-2020-11608",
    "CVE-2020-12114",
    "CVE-2020-12362",
    "CVE-2020-12363",
    "CVE-2020-12364",
    "CVE-2020-12464",
    "CVE-2020-14314",
    "CVE-2020-14356",
    "CVE-2020-15437",
    "CVE-2020-24394",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25643",
    "CVE-2020-25704",
    "CVE-2020-27786",
    "CVE-2020-27835",
    "CVE-2020-28974",
    "CVE-2020-35508",
    "CVE-2020-36322",
    "CVE-2020-36557",
    "CVE-2020-36694",
    "CVE-2021-0342",
    "CVE-2021-0605",
    "CVE-2021-3428",
    "CVE-2023-1390"
  );
  script_xref(name:"RHSA", value:"2021:1578");

  script_name(english:"RHEL 8 : kernel (RHSA-2021:1578)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1578 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: Integer overflow in Intel(R) Graphics Drivers (CVE-2020-12362)

    * kernel: memory leak in sof_set_get_large_ctrl_data() function in sound/soc/sof/ipc.c (CVE-2019-18811)

    * kernel: use-after-free caused by a malicious USB device in the drivers/usb/misc/adutux.c driver
    (CVE-2019-19523)

    * kernel: use-after-free bug caused by a malicious USB device in the drivers/usb/misc/iowarrior.c driver
    (CVE-2019-19528)

    * kernel: possible out of bounds write in kbd_keycode of keyboard.c (CVE-2020-0431)

    * kernel: DoS by corrupting mountpoint reference counter (CVE-2020-12114)

    * kernel: use-after-free in usb_sg_cancel function in drivers/usb/core/message.c (CVE-2020-12464)

    * kernel: buffer uses out of index in ext3/4 filesystem (CVE-2020-14314)

    * kernel: Use After Free vulnerability in cgroup BPF component (CVE-2020-14356)

    * kernel: NULL pointer dereference in serial8250_isa_init_ports function in
    drivers/tty/serial/8250/8250_core.c (CVE-2020-15437)

    * kernel: umask not applied on filesystem without ACL support (CVE-2020-24394)

    * kernel: TOCTOU mismatch in the NFS client code (CVE-2020-25212)

    * kernel: incomplete permission checking for access to rbd devices (CVE-2020-25284)

    * kernel: race condition between hugetlb sysctl handlers in mm/hugetlb.c (CVE-2020-25285)

    * kernel: improper input validation in ppp_cp_parse_cr function leads to memory corruption and read
    overflow (CVE-2020-25643)

    * kernel: perf_event_parse_addr_filter memory (CVE-2020-25704)

    * kernel: use-after-free in kernel midi subsystem (CVE-2020-27786)

    * kernel: child process is able to access parent mm through hfi dev file handle (CVE-2020-27835)

    * kernel: slab-out-of-bounds read in fbcon (CVE-2020-28974)

    * kernel: fork: fix copy_process(CLONE_PARENT) race with the exiting ->real_parent (CVE-2020-35508)

    * kernel: fuse: fuse_do_getattr() calls make_bad_inode() in inappropriate situations (CVE-2020-36322)

    * kernel: use after free in tun_get_user of tun.c could lead to local escalation of privilege
    (CVE-2021-0342)

    * kernel: NULL pointer dereferences in ov511_mode_init_regs and ov518_mode_init_regs in
    drivers/media/usb/gspca/ov519.c (CVE-2020-11608)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.4 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_1578.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63f15479");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.4_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?862005a9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1777455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1831726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1833445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1848084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1848652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1853922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1868453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1869141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1895961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1900933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1911343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1915799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949560");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-27786");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(1050, 20, 119, 125, 190, 284, 362, 367, 400, 401, 416, 459, 476, 665, 732);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:1578');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/baseos/debug',
      'content/dist/rhel8/8.10/aarch64/baseos/os',
      'content/dist/rhel8/8.10/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/baseos/debug',
      'content/dist/rhel8/8.10/ppc64le/baseos/os',
      'content/dist/rhel8/8.10/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/baseos/debug',
      'content/dist/rhel8/8.10/s390x/baseos/os',
      'content/dist/rhel8/8.10/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.10/s390x/codeready-builder/os',
      'content/dist/rhel8/8.10/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/baseos/debug',
      'content/dist/rhel8/8.10/x86_64/baseos/os',
      'content/dist/rhel8/8.10/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/baseos/debug',
      'content/dist/rhel8/8.6/aarch64/baseos/os',
      'content/dist/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/baseos/debug',
      'content/dist/rhel8/8.6/ppc64le/baseos/os',
      'content/dist/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/baseos/debug',
      'content/dist/rhel8/8.6/s390x/baseos/os',
      'content/dist/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.6/s390x/codeready-builder/os',
      'content/dist/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/baseos/debug',
      'content/dist/rhel8/8.6/x86_64/baseos/os',
      'content/dist/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/baseos/debug',
      'content/dist/rhel8/8.8/aarch64/baseos/os',
      'content/dist/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/baseos/debug',
      'content/dist/rhel8/8.8/ppc64le/baseos/os',
      'content/dist/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/baseos/debug',
      'content/dist/rhel8/8.8/s390x/baseos/os',
      'content/dist/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.8/s390x/codeready-builder/os',
      'content/dist/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/baseos/debug',
      'content/dist/rhel8/8.8/x86_64/baseos/os',
      'content/dist/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/baseos/debug',
      'content/dist/rhel8/8.9/aarch64/baseos/os',
      'content/dist/rhel8/8.9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/baseos/debug',
      'content/dist/rhel8/8.9/ppc64le/baseos/os',
      'content/dist/rhel8/8.9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/baseos/debug',
      'content/dist/rhel8/8.9/s390x/baseos/os',
      'content/dist/rhel8/8.9/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.9/s390x/codeready-builder/os',
      'content/dist/rhel8/8.9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/baseos/debug',
      'content/dist/rhel8/8.9/x86_64/baseos/os',
      'content/dist/rhel8/8.9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/s390x/baseos/debug',
      'content/dist/rhel8/8/s390x/baseos/os',
      'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8/s390x/codeready-builder/os',
      'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/os',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/debug',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/os',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/debug',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/os',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/os',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-core-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-cross-headers-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-debug-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-debug-core-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-debug-devel-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-debug-modules-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-debug-modules-extra-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-devel-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-headers-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-modules-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-modules-extra-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-libs-4.18.0-305.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-libs-4.18.0-305.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-libs-4.18.0-305.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-zfcpdump-4.18.0-305.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-zfcpdump-core-4.18.0-305.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-305.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-305.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-305.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'perf-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']},
      {'reference':'python3-perf-4.18.0-305.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-18811', 'CVE-2019-19523', 'CVE-2019-19528', 'CVE-2020-0431', 'CVE-2020-11608', 'CVE-2020-12114', 'CVE-2020-12362', 'CVE-2020-12363', 'CVE-2020-12364', 'CVE-2020-12464', 'CVE-2020-14314', 'CVE-2020-14356', 'CVE-2020-15437', 'CVE-2020-24394', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27786', 'CVE-2020-27835', 'CVE-2020-28974', 'CVE-2020-35508', 'CVE-2020-36322', 'CVE-2020-36557', 'CVE-2020-36694', 'CVE-2021-0342', 'CVE-2021-0605', 'CVE-2021-3428', 'CVE-2023-1390']}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
