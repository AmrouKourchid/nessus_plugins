##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4751-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147978);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-27673",
    "CVE-2020-27675",
    "CVE-2020-27777",
    "CVE-2020-27815",
    "CVE-2020-27830",
    "CVE-2020-27835",
    "CVE-2020-28588",
    "CVE-2020-28941",
    "CVE-2020-28974",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-35508"
  );
  script_xref(name:"USN", value:"4751-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-4751-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4751-1 advisory.

    It was discovered that the console keyboard driver in the Linux kernel contained a race condition. A local
    attacker could use this to expose sensitive information (kernel memory). (CVE-2020-25656)

    Minh Yuan discovered that the tty driver in the Linux kernel contained race conditions when handling
    fonts. A local attacker could possibly use this to expose sensitive information (kernel memory).
    (CVE-2020-25668)

    Bodong Zhao discovered a use-after-free in the Sun keyboard driver implementation in the Linux kernel. A
    local attacker could use this to cause a denial of service or possibly execute arbitrary code.
    (CVE-2020-25669)

    Kiyin () discovered that the perf subsystem in the Linux kernel did not properly deallocate memory
    in some situations. A privileged attacker could use this to cause a denial of service (kernel memory
    exhaustion). (CVE-2020-25704)

    Julien Grall discovered that the Xen dom0 event handler in the Linux kernel did not properly limit the
    number of events queued. An attacker in a guest VM could use this to cause a denial of service in the host
    OS. (CVE-2020-27673)

    Jinoh Kang discovered that the Xen event channel infrastructure in the Linux kernel contained a race
    condition. An attacker in guest could possibly use this to cause a denial of service (dom0 crash).
    (CVE-2020-27675)

    Daniel Axtens discovered that PowerPC RTAS implementation in the Linux kernel did not properly restrict
    memory accesses in some situations. A privileged local attacker could use this to arbitrarily modify
    kernel memory, potentially bypassing kernel lockdown restrictions. (CVE-2020-27777)

    It was discovered that the jfs file system implementation in the Linux kernel contained an out-of-bounds
    read vulnerability. A local attacker could use this to possibly cause a denial of service (system crash).
    (CVE-2020-27815)

    Shisong Qin and Bodong Zhao discovered that Speakup screen reader driver in the Linux kernel did not
    correctly handle setting line discipline in some situations. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2020-27830, CVE-2020-28941)

    It was discovered that a use-after-free vulnerability existed in the infiniband hfi1 device driver in the
    Linux kernel. A local attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2020-27835)

    It was discovered that an information leak existed in the syscall implementation in the Linux kernel on 32
    bit systems. A local attacker could use this to expose sensitive information (kernel memory).
    (CVE-2020-28588)

    Minh Yuan discovered that the framebuffer console driver in the Linux kernel did not properly handle fonts
    in some conditions. A local attacker could use this to cause a denial of service (system crash) or
    possibly expose sensitive information (kernel memory). (CVE-2020-28974)

    Michael Kurth and Pawel Wieczorkiewicz discovered that the Xen event processing backend in the Linux
    kernel did not properly limit the number of events queued. An attacker in a guest VM could use this to
    cause a denial of service in the host OS. (CVE-2020-29568)

    Olivier Benjamin and Pawel Wieczorkiewicz discovered a race condition the Xen paravirt block backend in
    the Linux kernel, leading to a use-after-free vulnerability. An attacker in a guest VM could use this to
    cause a denial of service in the host OS. (CVE-2020-29569)

    Jann Horn discovered that the tty subsystem of the Linux kernel did not use consistent locking in some
    situations, leading to a read-after-free vulnerability. A local attacker could use this to cause a denial
    of service (system crash) or possibly expose sensitive information (kernel memory). (CVE-2020-29660)

    Jann Horn discovered a race condition in the tty subsystem of the Linux kernel in the locking for the
    TIOCSPGRP ioctl(), leading to a use-after- free vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-29661)

    It was discovered that a race condition existed that caused the Linux kernel to not properly restrict exit
    signal delivery. A local attacker could possibly use this to send signals to arbitrary processes.
    (CVE-2020-35508)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4751-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29661");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-44-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-44-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-44-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.8.0': {
      'generic': '5.8.0-44',
      'generic-lpae': '5.8.0-44',
      'lowlatency': '5.8.0-44'
    }
  }
};

var host_kernel_release = get_kb_item('Host/uptrack-uname-r');
if (empty_or_null(host_kernel_release)) host_kernel_release = get_kb_item_or_exit('Host/uname-r');
var host_kernel_base_version = get_kb_item_or_exit('Host/Debian/kernel-base-version');
var host_kernel_type = get_kb_item_or_exit('Host/Debian/kernel-type');
if(empty_or_null(kernel_mappings[os_release][host_kernel_base_version][host_kernel_type])) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + host_kernel_release);

var extra = '';
var kernel_fixed_version = kernel_mappings[os_release][host_kernel_base_version][host_kernel_type] + "-" + host_kernel_type;
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4751-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-25656', 'CVE-2020-25668', 'CVE-2020-25669', 'CVE-2020-25704', 'CVE-2020-27673', 'CVE-2020-27675', 'CVE-2020-27777', 'CVE-2020-27815', 'CVE-2020-27830', 'CVE-2020-27835', 'CVE-2020-28588', 'CVE-2020-28941', 'CVE-2020-28974', 'CVE-2020-29568', 'CVE-2020-29569', 'CVE-2020-29660', 'CVE-2020-29661', 'CVE-2020-35508');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4751-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
