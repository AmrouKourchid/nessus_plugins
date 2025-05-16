#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4302-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134660);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-15217",
    "CVE-2019-19046",
    "CVE-2019-19051",
    "CVE-2019-19056",
    "CVE-2019-19058",
    "CVE-2019-19066",
    "CVE-2019-19068",
    "CVE-2020-2732",
    "CVE-2020-8832"
  );
  script_xref(name:"USN", value:"4302-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-4302-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-4302-1 advisory.

    Paulo Bonzini discovered that the KVM hypervisor implementation in the Linux kernel could improperly let a
    nested (level 2) guest access the resources of a parent (level 1) guest in certain situations. An attacker
    could use this to expose sensitive information. (CVE-2020-2732)

    Gregory Herrero discovered that the fix for CVE-2019-14615 to address the Linux kernel not properly
    clearing data structures on context switches for certain Intel graphics processors was incomplete. A local
    attacker could use this to expose sensitive information. (CVE-2020-8832)

    It was discovered that the IPMI message handler implementation in the Linux kernel did not properly
    deallocate memory in certain situations. A local attacker could use this to cause a denial of service
    (kernel memory exhaustion). (CVE-2019-19046)

    It was discovered that the Intel WiMAX 2400 driver in the Linux kernel did not properly deallocate memory
    in certain situations. A local attacker could use this to cause a denial of service (kernel memory
    exhaustion). (CVE-2019-19051)

    It was discovered that the Marvell Wi-Fi device driver in the Linux kernel did not properly deallocate
    memory in certain error conditions. A local attacker could use this to possibly cause a denial of service
    (kernel memory exhaustion). (CVE-2019-19056)

    It was discovered that the Intel(R) Wi-Fi device driver in the Linux kernel device driver in the Linux
    kernel did not properly deallocate memory in certain error conditions. A local attacker could possibly use
    this to cause a denial of service (kernel memory exhaustion). (CVE-2019-19058)

    It was discovered that the Brocade BFA Fibre Channel device driver in the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could possibly use this to cause a denial
    of service (kernel memory exhaustion). (CVE-2019-19066)

    It was discovered that the Realtek RTL8xxx USB Wi-Fi device driver in the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could possibly use this to cause a denial
    of service (kernel memory exhaustion). (CVE-2019-19068)

    It was discovered that ZR364XX Camera USB device driver for the Linux kernel did not properly initialize
    memory. A physically proximate attacker could use this to cause a denial of service (system crash).
    (CVE-2019-15217)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4302-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2732");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1035-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1055-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1057-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1058-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1063-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1074-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1075-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1076-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-91-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-91-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-91-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'generic': '4.15.0-91',
      'generic-lpae': '4.15.0-91',
      'lowlatency': '4.15.0-91',
      'oracle': '4.15.0-1035',
      'gcp': '4.15.0-1058',
      'aws': '4.15.0-1063',
      'azure': '4.15.0-1075'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-91',
      'generic-lpae': '4.15.0-91',
      'lowlatency': '4.15.0-91',
      'oracle': '4.15.0-1035',
      'gke': '4.15.0-1055',
      'kvm': '4.15.0-1056',
      'raspi2': '4.15.0-1057',
      'aws': '4.15.0-1063',
      'snapdragon': '4.15.0-1074',
      'oem': '4.15.0-1076'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4302-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2019-15217', 'CVE-2019-19046', 'CVE-2019-19051', 'CVE-2019-19056', 'CVE-2019-19058', 'CVE-2019-19066', 'CVE-2019-19068', 'CVE-2020-2732', 'CVE-2020-8832');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4302-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
