#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6464-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184096);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-3772",
    "CVE-2023-3863",
    "CVE-2023-3865",
    "CVE-2023-3866",
    "CVE-2023-3867",
    "CVE-2023-4132",
    "CVE-2023-4134",
    "CVE-2023-31083",
    "CVE-2023-38430",
    "CVE-2023-38432",
    "CVE-2023-44466"
  );
  script_xref(name:"USN", value:"6464-1");

  script_name(english:"Ubuntu 22.04 LTS / 23.04 : Linux kernel vulnerabilities (USN-6464-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 23.04 host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6464-1 advisory.

    Yu Hao and Weiteng Chen discovered that the Bluetooth HCI UART driver in the Linux kernel contained a race
    condition, leading to a null pointer dereference vulnerability. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2023-31083)

    Lin Ma discovered that the Netlink Transformation (XFRM) subsystem in the Linux kernel contained a null
    pointer dereference vulnerability in some situations. A local privileged attacker could use this to cause
    a denial of service (system crash). (CVE-2023-3772)

    Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel did not properly validate SMB
    request protocol IDs, leading to a out-of- bounds read vulnerability. A remote attacker could possibly use
    this to cause a denial of service (system crash). (CVE-2023-38430)

    Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel did not properly validate
    command payload size, leading to a out-of-bounds read vulnerability. A remote attacker could possibly use
    this to cause a denial of service (system crash). (CVE-2023-38432)

    It was discovered that the NFC implementation in the Linux kernel contained a use-after-free vulnerability
    when performing peer-to-peer communication in certain conditions. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly expose sensitive information (kernel memory).
    (CVE-2023-3863)

    Laurence Wit discovered that the KSMBD implementation in the Linux kernel did not properly validate a
    buffer size in certain situations, leading to an out-of-bounds read vulnerability. A remote attacker could
    use this to cause a denial of service (system crash) or possibly expose sensitive information.
    (CVE-2023-3865)

    Laurence Wit discovered that the KSMBD implementation in the Linux kernel contained a null pointer
    dereference vulnerability when handling handling chained requests. A remote attacker could use this to
    cause a denial of service (system crash). (CVE-2023-3866)

    It was discovered that the KSMBD implementation in the Linux kernel did not properly handle session setup
    requests, leading to an out-of-bounds read vulnerability. A remote attacker could use this to expose
    sensitive information. (CVE-2023-3867)

    It was discovered that the Siano USB MDTV receiver device driver in the Linux kernel did not properly
    handle device initialization failures in certain situations, leading to a use-after-free vulnerability. A
    physically proximate attacker could use this cause a denial of service (system crash). (CVE-2023-4132)

    It was discovered that a race condition existed in the Cypress touchscreen driver in the Linux kernel
    during device removal, leading to a use-after- free vulnerability. A physically proximate attacker could
    use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-4134)

    Thelford Williams discovered that the Ceph file system messenger protocol implementation in the Linux
    kernel did not properly validate frame segment length in certain situation, leading to a buffer overflow
    vulnerability. A remote attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2023-44466)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6464-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38432");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1008-starfive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1015-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1015-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1016-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1018-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-36-generic-lpae");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('22.04' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.2.0': {
      'generic': '6.2.0-36',
      'generic-64k': '6.2.0-36',
      'generic-lpae': '6.2.0-36',
      'aws': '6.2.0-1015',
      'azure-fde': '6.2.0-1016',
      'gcp': '6.2.0-1018'
    }
  },
  '23.04': {
    '6.2.0': {
      'generic': '6.2.0-36',
      'generic-64k': '6.2.0-36',
      'generic-lpae': '6.2.0-36',
      'starfive': '6.2.0-1008',
      'aws': '6.2.0-1015',
      'oracle': '6.2.0-1015',
      'raspi': '6.2.0-1016',
      'gcp': '6.2.0-1018'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6464-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-3772', 'CVE-2023-3863', 'CVE-2023-3865', 'CVE-2023-3866', 'CVE-2023-3867', 'CVE-2023-4132', 'CVE-2023-4134', 'CVE-2023-31083', 'CVE-2023-38430', 'CVE-2023-38432', 'CVE-2023-44466');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6464-1');
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
