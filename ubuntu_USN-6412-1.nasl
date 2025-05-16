#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6412-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182530);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2022-45886",
    "CVE-2022-45887",
    "CVE-2022-45919",
    "CVE-2022-48425",
    "CVE-2023-1206",
    "CVE-2023-2156",
    "CVE-2023-3212",
    "CVE-2023-4155",
    "CVE-2023-4194",
    "CVE-2023-4273",
    "CVE-2023-20569",
    "CVE-2023-38427",
    "CVE-2023-38431"
  );
  script_xref(name:"USN", value:"6412-1");

  script_name(english:"Ubuntu 22.04 LTS / 23.04 : Linux kernel vulnerabilities (USN-6412-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 23.04 host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6412-1 advisory.

    Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel contained a race condition during
    device removal, leading to a use-after- free vulnerability. A physically proximate attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-45886,
    CVE-2022-45919)

    Hyunwoo Kim discovered that the Technotrend/Hauppauge USB DEC driver in the Linux kernel did not properly
    handle device removal events. A physically proximate attacker could use this to cause a denial of service
    (system crash). (CVE-2022-45887)

    It was discovered that the NTFS file system implementation in the Linux kernel did not properly validate
    MFT flags in certain situations. An attacker could use this to construct a malicious NTFS image that, when
    mounted and operated on, could cause a denial of service (system crash). (CVE-2022-48425)

    It was discovered that the IPv6 implementation in the Linux kernel contained a high rate of hash
    collisions in connection lookup table. A remote attacker could use this to cause a denial of service
    (excessive CPU consumption). (CVE-2023-1206)

    Danil Trujillo, Johannes Wikner, and Kaveh Razavi discovered that some AMD processors utilising
    speculative execution and branch prediction may allow unauthorised memory reads via a speculative side-
    channel attack. A local attacker could use this to expose sensitive information, including kernel memory.
    (CVE-2023-20569)

    It was discovered that the IPv6 RPL protocol implementation in the Linux kernel did not properly handle
    user-supplied data. A remote attacker could use this to cause a denial of service (system crash).
    (CVE-2023-2156)

    Yang Lan discovered that the GFS2 file system implementation in the Linux kernel could attempt to
    dereference a null pointer in some situations. An attacker could use this to construct a malicious GFS2
    image that, when mounted and operated on, could cause a denial of service (system crash). (CVE-2023-3212)

    It was discovered that the KSMBD implementation in the Linux kernel did not properly validate buffer sizes
    in certain operations, leading to an integer underflow and out-of-bounds read vulnerability. A remote
    attacker could use this to cause a denial of service (system crash) or possibly expose sensitive
    information. (CVE-2023-38427)

    Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel did not properly validate
    packet header sizes in certain situations, leading to an out-of-bounds read vulnerability. A remote
    attacker could use this to cause a denial of service (system crash) or possibly expose sensitive
    information. (CVE-2023-38431)

    Andy Nguyen discovered that the KVM implementation for AMD processors in the Linux kernel with Secure
    Encrypted Virtualization (SEV) contained a race condition when accessing the GHCB page. A local attacker
    in a SEV guest VM could possibly use this to cause a denial of service (host system crash).
    (CVE-2023-4155)

    It was discovered that the TUN/TAP driver in the Linux kernel did not properly initialize socket data. A
    local attacker could use this to cause a denial of service (system crash). (CVE-2023-4194)

    Maxim Suhanov discovered that the exFAT file system implementation in the Linux kernel did not properly
    check a file name length, leading to an out- of-bounds write vulnerability. An attacker could use this to
    construct a malicious exFAT image that, when mounted and operated on, could cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2023-4273)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6412-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38427");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1006-starfive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1013-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1014-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1014-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-1016-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-34-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-34-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.2.0-34-generic-lpae");
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
      'generic': '6.2.0-34',
      'generic-64k': '6.2.0-34',
      'generic-lpae': '6.2.0-34',
      'aws': '6.2.0-1013',
      'azure-fde': '6.2.0-1014',
      'gcp': '6.2.0-1016'
    }
  },
  '23.04': {
    '6.2.0': {
      'generic': '6.2.0-34',
      'generic-64k': '6.2.0-34',
      'generic-lpae': '6.2.0-34',
      'starfive': '6.2.0-1006',
      'aws': '6.2.0-1013',
      'oracle': '6.2.0-1013',
      'raspi': '6.2.0-1014',
      'gcp': '6.2.0-1016'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6412-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-45886', 'CVE-2022-45887', 'CVE-2022-45919', 'CVE-2022-48425', 'CVE-2023-1206', 'CVE-2023-2156', 'CVE-2023-3212', 'CVE-2023-4155', 'CVE-2023-4194', 'CVE-2023-4273', 'CVE-2023-20569', 'CVE-2023-38427', 'CVE-2023-38431');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6412-1');
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
