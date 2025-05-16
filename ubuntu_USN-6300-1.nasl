#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6300-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179936);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/19");

  script_cve_id(
    "CVE-2022-4269",
    "CVE-2022-48502",
    "CVE-2023-0597",
    "CVE-2023-1611",
    "CVE-2023-1855",
    "CVE-2023-1990",
    "CVE-2023-2002",
    "CVE-2023-2124",
    "CVE-2023-2163",
    "CVE-2023-2194",
    "CVE-2023-2235",
    "CVE-2023-2269",
    "CVE-2023-3141",
    "CVE-2023-3268",
    "CVE-2023-23004",
    "CVE-2023-28466",
    "CVE-2023-30772",
    "CVE-2023-32248",
    "CVE-2023-33203",
    "CVE-2023-33288",
    "CVE-2023-35823",
    "CVE-2023-35824",
    "CVE-2023-35828",
    "CVE-2023-35829"
  );
  script_xref(name:"USN", value:"6300-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Linux kernel vulnerabilities (USN-6300-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6300-1 advisory.

    William Zhao discovered that the Traffic Control (TC) subsystem in the Linux kernel did not properly
    handle network packet retransmission in certain situations. A local attacker could use this to cause a
    denial of service (kernel deadlock). (CVE-2022-4269)

    It was discovered that the NTFS file system implementation in the Linux kernel did not properly check
    buffer indexes in certain situations, leading to an out-of-bounds read vulnerability. A local attacker
    could possibly use this to expose sensitive information (kernel memory). (CVE-2022-48502)

    Seth Jenkins discovered that the Linux kernel did not properly perform address randomization for a per-cpu
    memory management structure. A local attacker could use this to expose sensitive information (kernel
    memory) or in conjunction with another kernel vulnerability. (CVE-2023-0597)

    It was discovered that a race condition existed in the btrfs file system implementation in the Linux
    kernel, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly expose sensitive information. (CVE-2023-1611)

    It was discovered that the APM X-Gene SoC hardware monitoring driver in the Linux kernel contained a race
    condition, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or expose sensitive information (kernel memory). (CVE-2023-1855)

    It was discovered that the ST NCI NFC driver did not properly handle device removal events. A physically
    proximate attacker could use this to cause a denial of service (system crash). (CVE-2023-1990)

    Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did not properly perform permissions
    checks when handling HCI sockets. A physically proximate attacker could use this to cause a denial of
    service (bluetooth communication). (CVE-2023-2002)

    It was discovered that the XFS file system implementation in the Linux kernel did not properly perform
    metadata validation when mounting certain images. An attacker could use this to specially craft a file
    system image that, when mounted, could cause a denial of service (system crash). (CVE-2023-2124)

    Juan Jose Lopez Jaimez, Meador Inge, Simon Scannell, and Nenad Stojanovski discovered that the BPF
    verifier in the Linux kernel did not properly mark registers for precision tracking in certain situations,
    leading to an out- of-bounds access vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-2163)

    It was discovered that the SLIMpro I2C device driver in the Linux kernel did not properly validate user-
    supplied data in some situations, leading to an out-of-bounds write vulnerability. A privileged attacker
    could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2023-2194)

    It was discovered that the perf subsystem in the Linux kernel contained a use-after-free vulnerability. A
    privileged local attacker could possibly use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2023-2235)

    Zheng Zhang discovered that the device-mapper implementation in the Linux kernel did not properly handle
    locking during table_clear() operations. A local attacker could use this to cause a denial of service
    (kernel deadlock). (CVE-2023-2269)

    It was discovered that the ARM Mali Display Processor driver implementation in the Linux kernel did not
    properly handle certain error conditions. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2023-23004)

    It was discovered that a race condition existed in the TLS subsystem in the Linux kernel, leading to a
    use-after-free or a null pointer dereference vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-28466)

    It was discovered that the DA9150 charger driver in the Linux kernel did not properly handle device
    removal, leading to a user-after free vulnerability. A physically proximate attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-30772)

    It was discovered that the Ricoh R5C592 MemoryStick card reader driver in the Linux kernel contained a
    race condition during module unload, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-3141)

    Quentin Minster discovered that the KSMBD implementation in the Linux kernel did not properly validate
    pointers in some situations, leading to a null pointer dereference vulnerability. A remote attacker could
    use this to cause a denial of service (system crash). (CVE-2023-32248)

    It was discovered that the kernel->user space relay implementation in the Linux kernel did not properly
    perform certain buffer calculations, leading to an out-of-bounds read vulnerability. A local attacker
    could use this to cause a denial of service (system crash) or expose sensitive information (kernel
    memory). (CVE-2023-3268)

    It was discovered that the Qualcomm EMAC ethernet driver in the Linux kernel did not properly handle
    device removal, leading to a user-after free vulnerability. A physically proximate attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-33203)

    It was discovered that the BQ24190 charger driver in the Linux kernel did not properly handle device
    removal, leading to a user-after free vulnerability. A physically proximate attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-33288)

    It was discovered that the video4linux driver for Philips based TV cards in the Linux kernel contained a
    race condition during device removal, leading to a use-after-free vulnerability. A physically proximate
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2023-35823)

    It was discovered that the SDMC DM1105 PCI device driver in the Linux kernel contained a race condition
    during device removal, leading to a use- after-free vulnerability. A physically proximate attacker could
    use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-35824)

    It was discovered that the Renesas USB controller driver in the Linux kernel contained a race condition
    during device removal, leading to a use- after-free vulnerability. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-35828)

    It was discovered that the Rockchip Video Decoder IP driver in the Linux kernel contained a race condition
    during device removal, leading to a use- after-free vulnerability. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-35829)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6300-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2235");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2163");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-2002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1030-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1030-nvidia-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1035-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1035-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1037-intel-iotg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1039-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1040-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1041-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1042-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-79-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-79-lowlatency-64k");
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
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.15.0': {
      'lowlatency': '5.15.0-79',
      'lowlatency-64k': '5.15.0-79',
      'intel-iotg': '5.15.0-1037',
      'oracle': '5.15.0-1040',
      'aws': '5.15.0-1041'
    }
  },
  '22.04': {
    '5.15.0': {
      'lowlatency': '5.15.0-79',
      'lowlatency-64k': '5.15.0-79',
      'nvidia': '5.15.0-1030',
      'nvidia-lowlatency': '5.15.0-1030',
      'ibm': '5.15.0-1035',
      'raspi': '5.15.0-1035',
      'intel-iotg': '5.15.0-1037',
      'gcp': '5.15.0-1039',
      'oracle': '5.15.0-1040',
      'aws': '5.15.0-1042'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6300-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-4269', 'CVE-2022-48502', 'CVE-2023-0597', 'CVE-2023-1611', 'CVE-2023-1855', 'CVE-2023-1990', 'CVE-2023-2002', 'CVE-2023-2124', 'CVE-2023-2163', 'CVE-2023-2194', 'CVE-2023-2235', 'CVE-2023-2269', 'CVE-2023-3141', 'CVE-2023-3268', 'CVE-2023-23004', 'CVE-2023-28466', 'CVE-2023-30772', 'CVE-2023-32248', 'CVE-2023-33203', 'CVE-2023-33288', 'CVE-2023-35823', 'CVE-2023-35824', 'CVE-2023-35828', 'CVE-2023-35829');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6300-1');
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
