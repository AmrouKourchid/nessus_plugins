#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6725-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193084);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-1194",
    "CVE-2023-3867",
    "CVE-2023-32254",
    "CVE-2023-32258",
    "CVE-2023-38427",
    "CVE-2023-38430",
    "CVE-2023-38431",
    "CVE-2023-46838",
    "CVE-2023-52340",
    "CVE-2023-52429",
    "CVE-2023-52436",
    "CVE-2023-52438",
    "CVE-2023-52439",
    "CVE-2023-52441",
    "CVE-2023-52442",
    "CVE-2023-52443",
    "CVE-2023-52444",
    "CVE-2023-52445",
    "CVE-2023-52448",
    "CVE-2023-52449",
    "CVE-2023-52451",
    "CVE-2023-52454",
    "CVE-2023-52456",
    "CVE-2023-52457",
    "CVE-2023-52458",
    "CVE-2023-52462",
    "CVE-2023-52463",
    "CVE-2023-52464",
    "CVE-2023-52467",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52480",
    "CVE-2023-52609",
    "CVE-2023-52610",
    "CVE-2023-52612",
    "CVE-2024-22705",
    "CVE-2024-23850",
    "CVE-2024-23851",
    "CVE-2024-24860",
    "CVE-2024-26586",
    "CVE-2024-26589",
    "CVE-2024-26591",
    "CVE-2024-26597",
    "CVE-2024-26598",
    "CVE-2024-26631",
    "CVE-2024-26633"
  );
  script_xref(name:"USN", value:"6725-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Linux kernel vulnerabilities (USN-6725-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6725-1 advisory.

    Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel did not properly validate
    certain data structure fields when parsing lease contexts, leading to an out-of-bounds read vulnerability.
    A remote attacker could use this to cause a denial of service (system crash) or possibly expose sensitive
    information. (CVE-2023-1194)

    Quentin Minster discovered that a race condition existed in the KSMBD implementation in the Linux kernel,
    leading to a use-after-free vulnerability. A remote attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2023-32254)

    It was discovered that a race condition existed in the KSMBD implementation in the Linux kernel when
    handling session connections, leading to a use- after-free vulnerability. A remote attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-32258)

    It was discovered that the KSMBD implementation in the Linux kernel did not properly validate buffer sizes
    in certain operations, leading to an integer underflow and out-of-bounds read vulnerability. A remote
    attacker could use this to cause a denial of service (system crash) or possibly expose sensitive
    information. (CVE-2023-38427)

    Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel did not properly validate SMB
    request protocol IDs, leading to a out-of- bounds read vulnerability. A remote attacker could possibly use
    this to cause a denial of service (system crash). (CVE-2023-38430)

    Chih-Yen Chang discovered that the KSMBD implementation in the Linux kernel did not properly validate
    packet header sizes in certain situations, leading to an out-of-bounds read vulnerability. A remote
    attacker could use this to cause a denial of service (system crash) or possibly expose sensitive
    information. (CVE-2023-38431)

    It was discovered that the KSMBD implementation in the Linux kernel did not properly handle session setup
    requests, leading to an out-of-bounds read vulnerability. A remote attacker could use this to expose
    sensitive information. (CVE-2023-3867)

    Pratyush Yadav discovered that the Xen network backend implementation in the Linux kernel did not properly
    handle zero length data request, leading to a null pointer dereference vulnerability. An attacker in a
    guest VM could possibly use this to cause a denial of service (host domain crash). (CVE-2023-46838)

    It was discovered that the IPv6 implementation of the Linux kernel did not properly manage route cache
    memory usage. A remote attacker could use this to cause a denial of service (memory exhaustion).
    (CVE-2023-52340)

    It was discovered that the device mapper driver in the Linux kernel did not properly validate target size
    during certain memory allocations. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2023-52429, CVE-2024-23851)

    Yang Chaoming discovered that the KSMBD implementation in the Linux kernel did not properly validate
    request buffer sizes, leading to an out-of-bounds read vulnerability. An attacker could use this to cause
    a denial of service (system crash) or possibly expose sensitive information. (CVE-2024-22705)

    Chenyuan Yang discovered that the btrfs file system in the Linux kernel did not properly handle read
    operations on newly created subvolumes in certain conditions. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2024-23850)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel, leading to
    a null pointer dereference vulnerability. A privileged local attacker could use this to possibly cause a
    denial of service (system crash). (CVE-2024-24860)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - Architecture specifics;

    - Block layer;

    - Cryptographic API;

    - Android drivers;

    - EDAC drivers;

    - GPU drivers;

    - Media drivers;

    - Multifunction device drivers;

    - MTD block device drivers;

    - Network drivers;

    - NVME drivers;

    - TTY drivers;

    - Userspace I/O drivers;

    - EFI Variable file system;

    - F2FS file system;

    - GFS2 file system;

    - SMB network file system;

    - BPF subsystem;

    - IPv6 Networking;

    - Network Traffic Control;

    - AppArmor security module; (CVE-2023-52463, CVE-2023-52445, CVE-2023-52462, CVE-2023-52609,
    CVE-2023-52448, CVE-2023-52457, CVE-2023-52464, CVE-2023-52456, CVE-2023-52454, CVE-2023-52438,
    CVE-2023-52480, CVE-2023-52443, CVE-2023-52442, CVE-2024-26631, CVE-2023-52439, CVE-2023-52612,
    CVE-2024-26598, CVE-2024-26586, CVE-2024-26589, CVE-2023-52444, CVE-2023-52436, CVE-2024-26633,
    CVE-2024-26597, CVE-2023-52458, CVE-2024-26591, CVE-2023-52449, CVE-2023-52467, CVE-2023-52441,
    CVE-2023-52610, CVE-2023-52451, CVE-2023-52469, CVE-2023-52470)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6725-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38427");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-102-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-102-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-102-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-102-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-102-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1040-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1048-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1048-nvidia-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1050-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1050-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1052-intel-iotg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1054-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1055-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1060-azure-fde");
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
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.15.0': {
      'generic': '5.15.0-102',
      'generic-64k': '5.15.0-102',
      'generic-lpae': '5.15.0-102',
      'lowlatency': '5.15.0-102',
      'lowlatency-64k': '5.15.0-102',
      'gkeop': '5.15.0-1040',
      'ibm': '5.15.0-1050',
      'intel-iotg': '5.15.0-1052',
      'gcp': '5.15.0-1055',
      'azure-fde': '5.15.0-1060'
    }
  },
  '22.04': {
    '5.15.0': {
      'generic': '5.15.0-102',
      'generic-64k': '5.15.0-102',
      'generic-lpae': '5.15.0-102',
      'lowlatency': '5.15.0-102',
      'lowlatency-64k': '5.15.0-102',
      'gkeop': '5.15.0-1040',
      'nvidia': '5.15.0-1048',
      'nvidia-lowlatency': '5.15.0-1048',
      'ibm': '5.15.0-1050',
      'raspi': '5.15.0-1050',
      'intel-iotg': '5.15.0-1052',
      'gke': '5.15.0-1054',
      'kvm': '5.15.0-1054',
      'gcp': '5.15.0-1055',
      'azure-fde': '5.15.0-1060'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6725-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-1194', 'CVE-2023-3867', 'CVE-2023-32254', 'CVE-2023-32258', 'CVE-2023-38427', 'CVE-2023-38430', 'CVE-2023-38431', 'CVE-2023-46838', 'CVE-2023-52340', 'CVE-2023-52429', 'CVE-2023-52436', 'CVE-2023-52438', 'CVE-2023-52439', 'CVE-2023-52441', 'CVE-2023-52442', 'CVE-2023-52443', 'CVE-2023-52444', 'CVE-2023-52445', 'CVE-2023-52448', 'CVE-2023-52449', 'CVE-2023-52451', 'CVE-2023-52454', 'CVE-2023-52456', 'CVE-2023-52457', 'CVE-2023-52458', 'CVE-2023-52462', 'CVE-2023-52463', 'CVE-2023-52464', 'CVE-2023-52467', 'CVE-2023-52469', 'CVE-2023-52470', 'CVE-2023-52480', 'CVE-2023-52609', 'CVE-2023-52610', 'CVE-2023-52612', 'CVE-2024-22705', 'CVE-2024-23850', 'CVE-2024-23851', 'CVE-2024-24860', 'CVE-2024-26586', 'CVE-2024-26589', 'CVE-2024-26591', 'CVE-2024-26597', 'CVE-2024-26598', 'CVE-2024-26631', 'CVE-2024-26633');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6725-1');
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
