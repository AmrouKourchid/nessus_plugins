#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6029-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174459);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-3903",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1281",
    "CVE-2023-26545"
  );
  script_xref(name:"USN", value:"6029-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS : Linux kernel vulnerabilities (USN-6029-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6029-1 advisory.

    It was discovered that the Traffic-Control Index (TCINDEX) implementation in the Linux kernel contained a
    use-after-free vulnerability. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2023-1281)

    It was discovered that the infrared transceiver USB driver did not properly handle USB control messages. A
    local attacker with physical access could plug in a specially crafted USB device to cause a denial of
    service (memory exhaustion). (CVE-2022-3903)

    It was discovered that the Human Interface Device (HID) support driver in the Linux kernel contained a
    type confusion vulnerability in some situations. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2023-1073)

    It was discovered that a memory leak existed in the SCTP protocol implementation in the Linux kernel. A
    local attacker could use this to cause a denial of service (memory exhaustion). (CVE-2023-1074)

    Lianhui Tang discovered that the MPLS implementation in the Linux kernel did not properly handle certain
    sysctl allocation failure conditions, leading to a double-free vulnerability. An attacker could use this
    to cause a denial of service or possibly execute arbitrary code. (CVE-2023-26545)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6029-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1281");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1063-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1117-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1130-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1138-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1148-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1154-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1163-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-209-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-209-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-209-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl", "linux_alt_patch_detect.nasl");
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

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'generic': '4.15.0-209',
      'lowlatency': '4.15.0-209',
      'oracle': '4.15.0-1117',
      'gcp': '4.15.0-1148',
      'aws': '4.15.0-1154',
      'azure': '4.15.0-1163'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-209',
      'generic-lpae': '4.15.0-209',
      'lowlatency': '4.15.0-209',
      'dell300x': '4.15.0-1063',
      'oracle': '4.15.0-1117',
      'raspi2': '4.15.0-1130',
      'kvm': '4.15.0-1138',
      'gcp': '4.15.0-1148',
      'aws': '4.15.0-1154',
      'azure': '4.15.0-1163'
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
if (!ubuntu_pro_detected) {
  extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
  extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
  extra += 'require an Ubuntu Pro subscription.\n\n';
}
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6029-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3903', 'CVE-2023-1073', 'CVE-2023-1074', 'CVE-2023-1281', 'CVE-2023-26545');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6029-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
