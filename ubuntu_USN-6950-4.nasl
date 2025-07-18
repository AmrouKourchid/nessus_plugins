#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6950-4. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206040);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2023-52585",
    "CVE-2023-52882",
    "CVE-2024-26900",
    "CVE-2024-26936",
    "CVE-2024-26980",
    "CVE-2024-27398",
    "CVE-2024-27399",
    "CVE-2024-27401",
    "CVE-2024-35848",
    "CVE-2024-35947",
    "CVE-2024-36017",
    "CVE-2024-36031",
    "CVE-2024-36880",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36889",
    "CVE-2024-36902",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36906",
    "CVE-2024-36916",
    "CVE-2024-36919",
    "CVE-2024-36928",
    "CVE-2024-36929",
    "CVE-2024-36931",
    "CVE-2024-36933",
    "CVE-2024-36934",
    "CVE-2024-36937",
    "CVE-2024-36938",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36944",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36950",
    "CVE-2024-36952",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-36955",
    "CVE-2024-36957",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36964",
    "CVE-2024-36965",
    "CVE-2024-36967",
    "CVE-2024-36969",
    "CVE-2024-36975",
    "CVE-2024-38600"
  );
  script_xref(name:"USN", value:"6950-4");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (HWE) vulnerabilities (USN-6950-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6950-4 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - ARM64 architecture;

    - Block layer subsystem;

    - Bluetooth drivers;

    - Clock framework and drivers;

    - FireWire subsystem;

    - GPU drivers;

    - InfiniBand drivers;

    - Multiple devices driver;

    - EEPROM drivers;

    - Network drivers;

    - Pin controllers subsystem;

    - Remote Processor subsystem;

    - S/390 drivers;

    - SCSI drivers;

    - 9P distributed file system;

    - Network file system client;

    - SMB network file system;

    - Socket messages infrastructure;

    - Dynamic debug library;

    - Bluetooth subsystem;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - Multipath TCP;

    - NSH protocol;

    - Phonet protocol;

    - TIPC protocol;

    - Wireless networking;

    - Key management;

    - ALSA framework;

    - HD-audio driver; (CVE-2024-36883, CVE-2024-36940, CVE-2024-36902, CVE-2024-36975, CVE-2024-36964,
    CVE-2024-36938, CVE-2024-36931, CVE-2024-35848, CVE-2024-26900, CVE-2024-36967, CVE-2024-36904,
    CVE-2024-27398, CVE-2024-36031, CVE-2023-52585, CVE-2024-36886, CVE-2024-36937, CVE-2024-36954,
    CVE-2024-36916, CVE-2024-36905, CVE-2024-36959, CVE-2024-26980, CVE-2024-26936, CVE-2024-36928,
    CVE-2024-36889, CVE-2024-36929, CVE-2024-36933, CVE-2024-27399, CVE-2024-36946, CVE-2024-36906,
    CVE-2024-36965, CVE-2024-36957, CVE-2024-36941, CVE-2024-36897, CVE-2024-36952, CVE-2024-36947,
    CVE-2024-36950, CVE-2024-36880, CVE-2024-36017, CVE-2023-52882, CVE-2024-36969, CVE-2024-38600,
    CVE-2024-36955, CVE-2024-36960, CVE-2024-27401, CVE-2024-36919, CVE-2024-36934, CVE-2024-35947,
    CVE-2024-36953, CVE-2024-36944, CVE-2024-36939)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6950-4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36940");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-118-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-118-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-118-generic-lpae");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '5.15.0': {
      'generic': '5.15.0-118',
      'generic-64k': '5.15.0-118',
      'generic-lpae': '5.15.0-118'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6950-4');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52585', 'CVE-2023-52882', 'CVE-2024-26900', 'CVE-2024-26936', 'CVE-2024-26980', 'CVE-2024-27398', 'CVE-2024-27399', 'CVE-2024-27401', 'CVE-2024-35848', 'CVE-2024-35947', 'CVE-2024-36017', 'CVE-2024-36031', 'CVE-2024-36880', 'CVE-2024-36883', 'CVE-2024-36886', 'CVE-2024-36889', 'CVE-2024-36902', 'CVE-2024-36904', 'CVE-2024-36905', 'CVE-2024-36906', 'CVE-2024-36916', 'CVE-2024-36919', 'CVE-2024-36928', 'CVE-2024-36929', 'CVE-2024-36931', 'CVE-2024-36933', 'CVE-2024-36934', 'CVE-2024-36937', 'CVE-2024-36938', 'CVE-2024-36939', 'CVE-2024-36940', 'CVE-2024-36941', 'CVE-2024-36944', 'CVE-2024-36946', 'CVE-2024-36947', 'CVE-2024-36950', 'CVE-2024-36952', 'CVE-2024-36953', 'CVE-2024-36954', 'CVE-2024-36955', 'CVE-2024-36957', 'CVE-2024-36959', 'CVE-2024-36960', 'CVE-2024-36964', 'CVE-2024-36965', 'CVE-2024-36967', 'CVE-2024-36969', 'CVE-2024-36975', 'CVE-2024-38600');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6950-4');
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
