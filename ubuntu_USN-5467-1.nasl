##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5467-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161950);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-3772",
    "CVE-2021-4197",
    "CVE-2022-1011",
    "CVE-2022-1158",
    "CVE-2022-1198",
    "CVE-2022-1353",
    "CVE-2022-1516",
    "CVE-2022-21499",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23041",
    "CVE-2022-23042",
    "CVE-2022-24958",
    "CVE-2022-26966",
    "CVE-2022-28356",
    "CVE-2022-28389",
    "CVE-2022-28390"
  );
  script_xref(name:"USN", value:"5467-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5467-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5467-1 advisory.

    It was discovered that the Linux kernel did not properly restrict access to the kernel debugger when
    booted in secure boot environments. A privileged attacker could use this to bypass UEFI Secure Boot
    restrictions. (CVE-2022-21499)

    Aaron Adams discovered that the netfilter subsystem in the Linux kernel did not properly handle the
    removal of stateful expressions in some situations, leading to a use-after-free vulnerability. A local
    attacker could use this to cause a denial of service (system crash) or execute arbitrary code.
    (CVE-2022-1966)

    It was discovered that the SCTP protocol implementation in the Linux kernel did not properly verify VTAGs
    in some situations. A remote attacker could possibly use this to cause a denial of service (connection
    disassociation). (CVE-2021-3772)

    Eric Biederman discovered that the cgroup process migration implementation in the Linux kernel did not
    perform permission checks correctly in some situations. A local attacker could possibly use this to gain
    administrative privileges. (CVE-2021-4197)

    Jann Horn discovered that the FUSE file system in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2022-1011)

    Qiuhao Li, Gaoning Pan and Yongkang Jia discovered that the KVM implementation in the Linux kernel did not
    properly perform guest page table updates in some situations. An attacker in a guest vm could possibly use
    this to crash the host OS. (CVE-2022-1158)

    Duoming Zhou discovered that the 6pack protocol implementation in the Linux kernel did not handle detach
    events properly in some situations, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (system crash). (CVE-2022-1198)

    It was discovered that the PF_KEYv2 implementation in the Linux kernel did not properly initialize kernel
    memory in some situations. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2022-1353)

    It was discovered that the implementation of X.25 network protocols in the Linux kernel did not terminate
    link layer sessions properly. A local attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2022-1516)

    Demi Marie Obenour and Simon Gaiser discovered that several Xen para- virtualization device frontends did
    not properly restrict the access rights of device backends. An attacker could possibly use a malicious Xen
    backend to gain access to memory pages of a guest VM or cause a denial of service in the guest.
    (CVE-2022-23036, CVE-2022-23037, CVE-2022-23038, CVE-2022-23039, CVE-2022-23040, CVE-2022-23041,
    CVE-2022-23042)

    It was discovered that the USB Gadget file system interface in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2022-24958)

    It was discovered that the USB SR9700 ethernet device driver for the Linux kernel did not properly
    validate the length of requests from the device. A physically proximate attacker could possibly use this
    to expose sensitive information (kernel memory). (CVE-2022-26966)

     discovered that the 802.2 LLC type 2 driver in the Linux kernel did not properly perform
    reference counting in some error conditions. A local attacker could use this to cause a denial of service.
    (CVE-2022-28356)

    It was discovered that the Microchip CAN BUS Analyzer interface implementation in the Linux kernel did not
    properly handle certain error conditions, leading to a double-free. A local attacker could possibly use
    this to cause a denial of service (system crash). (CVE-2022-28389)

    It was discovered that the EMS CAN/USB interface implementation in the Linux kernel contained a double-
    free vulnerability when handling certain error conditions. A local attacker could use this to cause a
    denial of service (memory exhaustion). (CVE-2022-28390)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5467-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4197");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1026-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1046-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1065-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1068-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1074-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1076-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1078-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1078-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1083-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1083-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-117-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-117-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-117-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '18.04': {
    '5.4.0': {
      'generic': '5.4.0-117',
      'generic-lpae': '5.4.0-117',
      'lowlatency': '5.4.0-117',
      'ibm': '5.4.0-1026',
      'gkeop': '5.4.0-1046',
      'raspi': '5.4.0-1065',
      'gke': '5.4.0-1074',
      'oracle': '5.4.0-1076',
      'aws': '5.4.0-1078',
      'gcp': '5.4.0-1078',
      'azure': '5.4.0-1083'
    }
  },
  '20.04': {
    '5.4.0': {
      'generic': '5.4.0-117',
      'generic-lpae': '5.4.0-117',
      'lowlatency': '5.4.0-117',
      'ibm': '5.4.0-1026',
      'gkeop': '5.4.0-1046',
      'raspi': '5.4.0-1065',
      'kvm': '5.4.0-1068',
      'gke': '5.4.0-1074',
      'oracle': '5.4.0-1076',
      'aws': '5.4.0-1078',
      'gcp': '5.4.0-1078',
      'azure-fde': '5.4.0-1083'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5467-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-3772', 'CVE-2021-4197', 'CVE-2022-1011', 'CVE-2022-1158', 'CVE-2022-1198', 'CVE-2022-1353', 'CVE-2022-1516', 'CVE-2022-21499', 'CVE-2022-23036', 'CVE-2022-23037', 'CVE-2022-23038', 'CVE-2022-23039', 'CVE-2022-23040', 'CVE-2022-23041', 'CVE-2022-23042', 'CVE-2022-24958', 'CVE-2022-26966', 'CVE-2022-28356', 'CVE-2022-28389', 'CVE-2022-28390');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5467-1');
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
