##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5418-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161060);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-26401",
    "CVE-2022-23036",
    "CVE-2022-23037",
    "CVE-2022-23038",
    "CVE-2022-23039",
    "CVE-2022-23040",
    "CVE-2022-23042",
    "CVE-2022-24958",
    "CVE-2022-25258",
    "CVE-2022-25375",
    "CVE-2022-26490",
    "CVE-2022-26966",
    "CVE-2022-27223"
  );
  script_xref(name:"USN", value:"5418-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS : Linux kernel vulnerabilities (USN-5418-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5418-1 advisory.

    Ke Sun, Alyssa Milburn, Henrique Kawakami, Emma Benoit, Igor Chervatyuk, Lisa Aichele, and Thais Moreira
    Hamasaki discovered that the Spectre Variant 2 mitigations for AMD processors on Linux were insufficient
    in some situations. A local attacker could possibly use this to expose sensitive information.
    (CVE-2021-26401)

    Demi Marie Obenour and Simon Gaiser discovered that several Xen para- virtualization device frontends did
    not properly restrict the access rights of device backends. An attacker could possibly use a malicious Xen
    backend to gain access to memory pages of a guest VM or cause a denial of service in the guest.
    (CVE-2022-23036, CVE-2022-23037, CVE-2022-23038, CVE-2022-23039, CVE-2022-23040, CVE-2022-23042)

    It was discovered that the USB Gadget file system interface in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2022-24958)

    It was discovered that the USB gadget subsystem in the Linux kernel did not properly validate interface
    descriptor requests. An attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2022-25258)

    It was discovered that the Remote NDIS (RNDIS) USB gadget implementation in the Linux kernel did not
    properly validate the size of the RNDIS_MSG_SET command. An attacker could possibly use this to expose
    sensitive information (kernel memory). (CVE-2022-25375)

    It was discovered that the ST21NFCA NFC driver in the Linux kernel did not properly validate the size of
    certain data in EVT_TRANSACTION events. A physically proximate attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2022-26490)

    It was discovered that the USB SR9700 ethernet device driver for the Linux kernel did not properly
    validate the length of requests from the device. A physically proximate attacker could possibly use this
    to expose sensitive information (kernel memory). (CVE-2022-26966)

    It was discovered that the Xilinx USB2 device gadget driver in the Linux kernel did not properly validate
    endpoint indices from the host. A physically proximate attacker could possibly use this to cause a denial
    of service (system crash). (CVE-2022-27223)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5418-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1042-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1093-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1114-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1122-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1128-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1128-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1138-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-177-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-177-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-177-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
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
      'generic': '4.15.0-177',
      'lowlatency': '4.15.0-177',
      'oracle': '4.15.0-1093',
      'gcp': '4.15.0-1122',
      'aws': '4.15.0-1128',
      'aws-hwe': '4.15.0-1128',
      'azure': '4.15.0-1138'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-177',
      'generic-lpae': '4.15.0-177',
      'lowlatency': '4.15.0-177',
      'dell300x': '4.15.0-1042',
      'oracle': '4.15.0-1093',
      'kvm': '4.15.0-1114',
      'gcp': '4.15.0-1122',
      'snapdragon': '4.15.0-1127',
      'aws': '4.15.0-1128',
      'azure': '4.15.0-1138'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5418-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-26401', 'CVE-2022-23036', 'CVE-2022-23037', 'CVE-2022-23038', 'CVE-2022-23039', 'CVE-2022-23040', 'CVE-2022-23042', 'CVE-2022-24958', 'CVE-2022-25258', 'CVE-2022-25375', 'CVE-2022-26490', 'CVE-2022-26966', 'CVE-2022-27223');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5418-1');
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
