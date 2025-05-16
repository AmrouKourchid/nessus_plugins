#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5377-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159729);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/19");

  script_cve_id(
    "CVE-2021-4135",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2021-45469",
    "CVE-2021-45480",
    "CVE-2022-0435",
    "CVE-2022-0492",
    "CVE-2022-1055",
    "CVE-2022-27666"
  );
  script_xref(name:"USN", value:"5377-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (BlueField) vulnerabilities (USN-5377-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5377-1 advisory.

    It was discovered that the network traffic control implementation in the Linux kernel contained a use-
    after-free vulnerability. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2022-1055)

    Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the Linux kernel did not properly
    restrict access to the cgroups v1 release_agent feature. A local attacker could use this to gain
    administrative privileges. (CVE-2022-0492)

    Jrgen Gro discovered that the Xen subsystem within the Linux kernel did not adequately limit the
    number of events driver domains (unprivileged PV backends) could send to other guest VMs. An attacker in a
    driver domain could use this to cause a denial of service in other guest VMs. (CVE-2021-28711,
    CVE-2021-28712, CVE-2021-28713)

    Jrgen Gro discovered that the Xen network backend driver in the Linux kernel did not adequately limit
    the amount of queued packets when a guest did not process them. An attacker in a guest VM can use this to
    cause a denial of service (excessive kernel memory consumption) in the network backend domain.
    (CVE-2021-28714, CVE-2021-28715)

    It was discovered that the simulated networking device driver for the Linux kernel did not properly
    initialize memory in certain situations. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2021-4135)

    Brendan Dolan-Gavitt discovered that the Marvell WiFi-Ex USB device driver in the Linux kernel did not
    properly handle some error conditions. A physically proximate attacker could use this to cause a denial of
    service (system crash). (CVE-2021-43976)

    It was discovered that the ARM Trusted Execution Environment (TEE) subsystem in the Linux kernel contained
    a race condition leading to a use- after-free vulnerability. A local attacker could use this to cause a
    denial of service or possibly execute arbitrary code. (CVE-2021-44733)

    It was discovered that the Phone Network protocol (PhoNet) implementation in the Linux kernel did not
    properly perform reference counting in some error conditions. A local attacker could possibly use this to
    cause a denial of service (memory exhaustion). (CVE-2021-45095)

    Wenqing Liu discovered that the f2fs file system in the Linux kernel did not properly validate the last
    xattr entry in an inode. An attacker could use this to construct a malicious f2fs image that, when mounted
    and operated on, could cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-45469)

    It was discovered that the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel did
    not properly deallocate memory in some error conditions. A local attacker could possibly use this to cause
    a denial of service (memory exhaustion). (CVE-2021-45480)

    Samuel Page discovered that the Transparent Inter-Process Communication (TIPC) protocol implementation in
    the Linux kernel contained a stack-based buffer overflow. A remote attacker could use this to cause a
    denial of service (system crash) for systems that have a TIPC bearer configured. (CVE-2022-0435)

    It was discovered that the IPsec implementation in the Linux kernel did not properly allocate enough
    memory when performing ESP transformations, leading to a heap-based buffer overflow. A local attacker
    could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2022-27666)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5377-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2022-1055");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Docker cgroups Container Escape');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
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
    '5.4.0': {
      'bluefield': '5.4.0-1032'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5377-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-4135', 'CVE-2021-28711', 'CVE-2021-28712', 'CVE-2021-28713', 'CVE-2021-28714', 'CVE-2021-28715', 'CVE-2021-43976', 'CVE-2021-44733', 'CVE-2021-45095', 'CVE-2021-45469', 'CVE-2021-45480', 'CVE-2022-0435', 'CVE-2022-0492', 'CVE-2022-1055', 'CVE-2022-27666');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5377-1');
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
