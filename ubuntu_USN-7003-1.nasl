#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7003-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207055);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id(
    "CVE-2023-52803",
    "CVE-2023-52887",
    "CVE-2024-36894",
    "CVE-2024-36974",
    "CVE-2024-36978",
    "CVE-2024-37078",
    "CVE-2024-38619",
    "CVE-2024-39469",
    "CVE-2024-39487",
    "CVE-2024-39495",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39503",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40912",
    "CVE-2024-40916",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40945",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40963",
    "CVE-2024-40968",
    "CVE-2024-40974",
    "CVE-2024-40978",
    "CVE-2024-40980",
    "CVE-2024-40981",
    "CVE-2024-40984",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40995",
    "CVE-2024-41006",
    "CVE-2024-41007",
    "CVE-2024-41034",
    "CVE-2024-41035",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41046",
    "CVE-2024-41049",
    "CVE-2024-41087",
    "CVE-2024-41089",
    "CVE-2024-41095",
    "CVE-2024-41097",
    "CVE-2024-42070",
    "CVE-2024-42076",
    "CVE-2024-42084",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42092",
    "CVE-2024-42093",
    "CVE-2024-42094",
    "CVE-2024-42096",
    "CVE-2024-42097",
    "CVE-2024-42101",
    "CVE-2024-42102",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42115",
    "CVE-2024-42119",
    "CVE-2024-42124",
    "CVE-2024-42127",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42153",
    "CVE-2024-42154",
    "CVE-2024-42157",
    "CVE-2024-42223",
    "CVE-2024-42224",
    "CVE-2024-42232",
    "CVE-2024-42236"
  );
  script_xref(name:"USN", value:"7003-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-7003-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7003-1 advisory.

    It was discovered that the JFS file system contained an out-of-bounds read vulnerability when printing
    xattr debug information. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2024-40902)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - MIPS architecture;

    - PowerPC architecture;

    - x86 architecture;

    - ACPI drivers;

    - Serial ATA and Parallel ATA drivers;

    - Drivers core;

    - GPIO subsystem;

    - GPU drivers;

    - Greybus drivers;

    - HID subsystem;

    - I2C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - Media drivers;

    - VMware VMCI Driver;

    - Network drivers;

    - Pin controllers subsystem;

    - S/390 drivers;

    - SCSI drivers;

    - USB subsystem;

    - JFFS2 file system;

    - JFS file system;

    - File systems infrastructure;

    - NILFS2 file system;

    - IOMMU subsystem;

    - Sun RPC protocol;

    - Netfilter;

    - Memory management;

    - B.A.T.M.A.N. meshing protocol;

    - CAN network layer;

    - Ceph Core library;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - IUCV driver;

    - MAC80211 subsystem;

    - NET/ROM layer;

    - Network traffic control;

    - SoC Audio for Freescale CPUs drivers; (CVE-2024-40905, CVE-2024-41095, CVE-2024-41035, CVE-2024-36974,
    CVE-2024-40959, CVE-2024-40978, CVE-2024-42236, CVE-2024-40963, CVE-2024-40916, CVE-2024-41006,
    CVE-2024-39495, CVE-2023-52803, CVE-2024-42070, CVE-2024-41041, CVE-2024-42157, CVE-2024-36894,
    CVE-2024-42153, CVE-2024-42127, CVE-2024-42224, CVE-2024-40932, CVE-2024-42105, CVE-2024-40968,
    CVE-2024-41044, CVE-2024-41046, CVE-2023-52887, CVE-2024-42094, CVE-2024-40960, CVE-2024-41007,
    CVE-2024-40961, CVE-2024-39487, CVE-2024-39502, CVE-2024-42086, CVE-2024-36978, CVE-2024-39503,
    CVE-2024-41049, CVE-2024-42090, CVE-2024-42232, CVE-2024-39499, CVE-2024-40902, CVE-2024-37078,
    CVE-2024-39501, CVE-2024-42119, CVE-2024-40901, CVE-2024-42101, CVE-2024-42104, CVE-2024-42145,
    CVE-2024-41097, CVE-2024-40942, CVE-2024-41034, CVE-2024-40904, CVE-2024-41089, CVE-2024-42084,
    CVE-2024-42093, CVE-2024-40945, CVE-2024-40958, CVE-2024-42124, CVE-2024-40987, CVE-2024-40912,
    CVE-2024-39506, CVE-2024-40941, CVE-2024-39509, CVE-2024-40974, CVE-2024-39505, CVE-2024-42115,
    CVE-2024-40988, CVE-2024-40995, CVE-2024-42097, CVE-2024-41087, CVE-2024-42106, CVE-2024-40984,
    CVE-2024-40981, CVE-2024-42102, CVE-2024-42148, CVE-2024-42154, CVE-2024-42096, CVE-2024-40934,
    CVE-2024-40980, CVE-2024-42076, CVE-2024-40943, CVE-2024-42092, CVE-2024-42089, CVE-2024-42223,
    CVE-2024-38619, CVE-2024-42087, CVE-2024-39469)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7003-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1079-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1092-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1099-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1120-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1131-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1132-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1136-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1137-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-195-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-195-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-195-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '5.4.0': {
      'generic': '5.4.0-195',
      'generic-lpae': '5.4.0-195',
      'lowlatency': '5.4.0-195',
      'ibm': '5.4.0-1079',
      'bluefield': '5.4.0-1092',
      'gkeop': '5.4.0-1099',
      'kvm': '5.4.0-1120',
      'oracle': '5.4.0-1131',
      'aws': '5.4.0-1132',
      'gcp': '5.4.0-1136',
      'azure': '5.4.0-1137'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7003-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52803', 'CVE-2023-52887', 'CVE-2024-36894', 'CVE-2024-36974', 'CVE-2024-36978', 'CVE-2024-37078', 'CVE-2024-38619', 'CVE-2024-39469', 'CVE-2024-39487', 'CVE-2024-39495', 'CVE-2024-39499', 'CVE-2024-39501', 'CVE-2024-39502', 'CVE-2024-39503', 'CVE-2024-39505', 'CVE-2024-39506', 'CVE-2024-39509', 'CVE-2024-40901', 'CVE-2024-40902', 'CVE-2024-40904', 'CVE-2024-40905', 'CVE-2024-40912', 'CVE-2024-40916', 'CVE-2024-40932', 'CVE-2024-40934', 'CVE-2024-40941', 'CVE-2024-40942', 'CVE-2024-40943', 'CVE-2024-40945', 'CVE-2024-40958', 'CVE-2024-40959', 'CVE-2024-40960', 'CVE-2024-40961', 'CVE-2024-40963', 'CVE-2024-40968', 'CVE-2024-40974', 'CVE-2024-40978', 'CVE-2024-40980', 'CVE-2024-40981', 'CVE-2024-40984', 'CVE-2024-40987', 'CVE-2024-40988', 'CVE-2024-40995', 'CVE-2024-41006', 'CVE-2024-41007', 'CVE-2024-41034', 'CVE-2024-41035', 'CVE-2024-41041', 'CVE-2024-41044', 'CVE-2024-41046', 'CVE-2024-41049', 'CVE-2024-41087', 'CVE-2024-41089', 'CVE-2024-41095', 'CVE-2024-41097', 'CVE-2024-42070', 'CVE-2024-42076', 'CVE-2024-42084', 'CVE-2024-42086', 'CVE-2024-42087', 'CVE-2024-42089', 'CVE-2024-42090', 'CVE-2024-42092', 'CVE-2024-42093', 'CVE-2024-42094', 'CVE-2024-42096', 'CVE-2024-42097', 'CVE-2024-42101', 'CVE-2024-42102', 'CVE-2024-42104', 'CVE-2024-42105', 'CVE-2024-42106', 'CVE-2024-42115', 'CVE-2024-42119', 'CVE-2024-42124', 'CVE-2024-42127', 'CVE-2024-42145', 'CVE-2024-42148', 'CVE-2024-42153', 'CVE-2024-42154', 'CVE-2024-42157', 'CVE-2024-42223', 'CVE-2024-42224', 'CVE-2024-42232', 'CVE-2024-42236');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7003-1');
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
