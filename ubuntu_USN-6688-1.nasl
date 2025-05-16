#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6688-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191796);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id(
    "CVE-2023-5633",
    "CVE-2023-6610",
    "CVE-2023-46838",
    "CVE-2023-50431",
    "CVE-2023-52436",
    "CVE-2023-52438",
    "CVE-2023-52439",
    "CVE-2023-52443",
    "CVE-2023-52444",
    "CVE-2023-52445",
    "CVE-2023-52447",
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
    "CVE-2023-52583",
    "CVE-2023-52584",
    "CVE-2023-52587",
    "CVE-2023-52588",
    "CVE-2023-52589",
    "CVE-2023-52593",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52599",
    "CVE-2023-52600",
    "CVE-2023-52601",
    "CVE-2023-52602",
    "CVE-2023-52603",
    "CVE-2023-52604",
    "CVE-2023-52605",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2024-0340",
    "CVE-2024-1085",
    "CVE-2024-1086",
    "CVE-2024-23849",
    "CVE-2024-24860",
    "CVE-2024-26581",
    "CVE-2024-26588",
    "CVE-2024-26589",
    "CVE-2024-26591",
    "CVE-2024-26592",
    "CVE-2024-26594",
    "CVE-2024-26597",
    "CVE-2024-26598",
    "CVE-2024-26599",
    "CVE-2024-26600",
    "CVE-2024-26601",
    "CVE-2024-26624",
    "CVE-2024-26625",
    "CVE-2024-26627",
    "CVE-2024-26628"
  );
  script_xref(name:"USN", value:"6688-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel (OEM) vulnerabilities (USN-6688-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6688-1 advisory.

    Pratyush Yadav discovered that the Xen network backend implementation in the Linux kernel did not properly
    handle zero length data request, leading to a null pointer dereference vulnerability. An attacker in a
    guest VM could possibly use this to cause a denial of service (host domain crash). (CVE-2023-46838)

    It was discovered that the Habana's AI Processors driver in the Linux kernel did not properly initialize
    certain data structures before passing them to user space. A local attacker could use this to expose
    sensitive information (kernel memory). (CVE-2023-50431)

    Murray McAllister discovered that the VMware Virtual GPU DRM driver in the Linux kernel did not properly
    handle memory objects when storing surfaces, leading to a use-after-free vulnerability. A local attacker
    in a guest VM could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2023-5633)

    It was discovered that the CIFS network file system implementation in the Linux kernel did not properly
    validate certain SMB messages, leading to an out-of-bounds read vulnerability. An attacker could use this
    to cause a denial of service (system crash) or possibly expose sensitive information. (CVE-2023-6610)

    It was discovered that the VirtIO subsystem in the Linux kernel did not properly initialize memory in some
    situations. A local attacker could use this to possibly expose sensitive information (kernel memory).
    (CVE-2024-0340)

    Lonial Con discovered that the netfilter subsystem in the Linux kernel did not properly handle element
    deactivation in certain cases, leading to a use-after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2024-1085)

    Notselwyn discovered that the netfilter subsystem in the Linux kernel did not properly handle verdict
    parameters in certain cases, leading to a use- after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2024-1086)

    Chenyuan Yang discovered that the RDS Protocol implementation in the Linux kernel contained an out-of-
    bounds read vulnerability. An attacker could use this to possibly cause a denial of service (system
    crash). (CVE-2024-23849)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel, leading to
    a null pointer dereference vulnerability. A privileged local attacker could use this to possibly cause a
    denial of service (system crash). (CVE-2024-24860)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - Architecture specifics;

    - Block layer;

    - ACPI drivers;

    - Android drivers;

    - EDAC drivers;

    - GPU drivers;

    - InfiniBand drivers;

    - Media drivers;

    - Multifunction device drivers;

    - MTD block device drivers;

    - Network drivers;

    - NVME drivers;

    - PHY drivers;

    - PWM drivers;

    - SCSI drivers;

    - SPMI drivers;

    - TTY drivers;

    - Userspace I/O drivers;

    - Ceph distributed file system;

    - EFI Variable file system;

    - Ext4 file system;

    - F2FS file system;

    - GFS2 file system;

    - JFS file system;

    - SMB network file system;

    - BPF subsystem;

    - Logical Link Layer;

    - Netfilter;

    - Unix domain sockets;

    - AppArmor security module; (CVE-2024-26599, CVE-2023-52604, CVE-2023-52439, CVE-2024-26627,
    CVE-2024-26601, CVE-2024-26628, CVE-2023-52607, CVE-2023-52456, CVE-2023-52602, CVE-2023-52443,
    CVE-2023-52599, CVE-2023-52603, CVE-2024-26588, CVE-2024-26581, CVE-2023-52600, CVE-2024-26624,
    CVE-2023-52584, CVE-2024-26625, CVE-2023-52606, CVE-2023-52463, CVE-2023-52464, CVE-2023-52597,
    CVE-2023-52595, CVE-2023-52458, CVE-2023-52457, CVE-2023-52438, CVE-2023-52469, CVE-2023-52462,
    CVE-2024-26589, CVE-2024-26592, CVE-2024-26594, CVE-2023-52601, CVE-2023-52593, CVE-2023-52436,
    CVE-2023-52447, CVE-2023-52587, CVE-2023-52445, CVE-2023-52454, CVE-2023-52451, CVE-2023-52605,
    CVE-2024-26597, CVE-2023-52448, CVE-2023-52598, CVE-2024-26591, CVE-2023-52449, CVE-2023-52444,
    CVE-2023-52583, CVE-2023-52589, CVE-2024-26598, CVE-2023-52470, CVE-2023-52594, CVE-2023-52588,
    CVE-2023-52467, CVE-2024-26600)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6688-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26625");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.1.0-1035-oem");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.1.0': {
      'oem': '6.1.0-1035'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6688-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-5633', 'CVE-2023-6610', 'CVE-2023-46838', 'CVE-2023-50431', 'CVE-2023-52436', 'CVE-2023-52438', 'CVE-2023-52439', 'CVE-2023-52443', 'CVE-2023-52444', 'CVE-2023-52445', 'CVE-2023-52447', 'CVE-2023-52448', 'CVE-2023-52449', 'CVE-2023-52451', 'CVE-2023-52454', 'CVE-2023-52456', 'CVE-2023-52457', 'CVE-2023-52458', 'CVE-2023-52462', 'CVE-2023-52463', 'CVE-2023-52464', 'CVE-2023-52467', 'CVE-2023-52469', 'CVE-2023-52470', 'CVE-2023-52583', 'CVE-2023-52584', 'CVE-2023-52587', 'CVE-2023-52588', 'CVE-2023-52589', 'CVE-2023-52593', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52597', 'CVE-2023-52598', 'CVE-2023-52599', 'CVE-2023-52600', 'CVE-2023-52601', 'CVE-2023-52602', 'CVE-2023-52603', 'CVE-2023-52604', 'CVE-2023-52605', 'CVE-2023-52606', 'CVE-2023-52607', 'CVE-2024-0340', 'CVE-2024-1085', 'CVE-2024-1086', 'CVE-2024-23849', 'CVE-2024-24860', 'CVE-2024-26581', 'CVE-2024-26588', 'CVE-2024-26589', 'CVE-2024-26591', 'CVE-2024-26592', 'CVE-2024-26594', 'CVE-2024-26597', 'CVE-2024-26598', 'CVE-2024-26599', 'CVE-2024-26600', 'CVE-2024-26601', 'CVE-2024-26624', 'CVE-2024-26625', 'CVE-2024-26627', 'CVE-2024-26628');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6688-1');
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
