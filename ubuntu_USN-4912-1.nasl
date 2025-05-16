##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4912-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148494);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-0423",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-14351",
    "CVE-2020-14390",
    "CVE-2020-25285",
    "CVE-2020-25645",
    "CVE-2020-25669",
    "CVE-2020-27830",
    "CVE-2020-36158",
    "CVE-2021-3178",
    "CVE-2021-3411",
    "CVE-2021-20194",
    "CVE-2021-29154"
  );
  script_xref(name:"USN", value:"4912-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-4912-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4912-1 advisory.

    Piotr Krysiuk discovered that the BPF JIT compiler for x86 in the Linux kernel did not properly validate
    computation of branch displacements in some situations. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2021-29154)

    It was discovered that a race condition existed in the binder IPC implementation in the Linux kernel,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2020-0423)

    It was discovered that the HID multitouch implementation within the Linux kernel did not properly validate
    input events in some situations. A physically proximate attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2020-0465)

    It was discovered that the eventpoll (aka epoll) implementation in the Linux kernel contained a logic
    error that could lead to a use after free vulnerability. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2020-0466)

    It was discovered that a race condition existed in the perf subsystem of the Linux kernel, leading to a
    use-after-free vulnerability. An attacker with access to the perf subsystem could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-14351)

    It was discovered that the frame buffer implementation in the Linux kernel did not properly handle some
    edge cases in software scrollback. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2020-14390)

    It was discovered that a race condition existed in the hugetlb sysctl implementation in the Linux kernel.
    A privileged attacker could use this to cause a denial of service (system crash). (CVE-2020-25285)

    It was discovered that the GENEVE tunnel implementation in the Linux kernel when combined with IPSec did
    not properly select IP routes in some situations. An attacker could use this to expose sensitive
    information (unencrypted network traffic). (CVE-2020-25645)

    Bodong Zhao discovered a use-after-free in the Sun keyboard driver implementation in the Linux kernel. A
    local attacker could use this to cause a denial of service or possibly execute arbitrary code.
    (CVE-2020-25669)

    Shisong Qin and Bodong Zhao discovered that Speakup screen reader driver in the Linux kernel did not
    correctly handle setting line discipline in some situations. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2020-27830)

    It was discovered that the Marvell WiFi-Ex device driver in the Linux kernel did not properly validate ad-
    hoc SSIDs. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2020-36158)

    Loris Reiff discovered that the BPF implementation in the Linux kernel did not properly validate
    attributes in the getsockopt BPF hook. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2021-20194)

    Adam Zabrocki discovered that the kprobes subsystem in the Linux kernel did not properly detect linker
    padding in some situations. A privileged attacker could use this to cause a denial of service (system
    crash) or possibly expose sensitive information. (CVE-2021-3411)

     discovered that the NFS implementation in the Linux kernel did not properly prevent access outside
    of an NFS export that is a subdirectory of a file system. An attacker could possibly use this to bypass
    NFS access restrictions. (CVE-2021-3178)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4912-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.6.0-1053-oem");
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
    '5.6.0': {
      'oem': '5.6.0-1053'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4912-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-0423', 'CVE-2020-0465', 'CVE-2020-0466', 'CVE-2020-14351', 'CVE-2020-14390', 'CVE-2020-25285', 'CVE-2020-25645', 'CVE-2020-25669', 'CVE-2020-27830', 'CVE-2020-36158', 'CVE-2021-3178', 'CVE-2021-3411', 'CVE-2021-20194', 'CVE-2021-29154');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4912-1');
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
