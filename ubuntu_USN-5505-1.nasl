##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5505-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162822);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2021-3609",
    "CVE-2021-3752",
    "CVE-2021-3760",
    "CVE-2021-4197",
    "CVE-2021-4202",
    "CVE-2021-39685",
    "CVE-2021-39714",
    "CVE-2022-0330",
    "CVE-2022-1353",
    "CVE-2022-1419",
    "CVE-2022-1652",
    "CVE-2022-1679",
    "CVE-2022-1734",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-24958",
    "CVE-2022-28356",
    "CVE-2022-28388"
  );
  script_xref(name:"USN", value:"5505-1");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel vulnerabilities (USN-5505-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5505-1 advisory.

    Norbert Slusarek discovered a race condition in the CAN BCM networking protocol of the Linux kernel
    leading to multiple use-after-free vulnerabilities. A local attacker could use this issue to execute
    arbitrary code. (CVE-2021-3609)

    Likang Luo discovered that a race condition existed in the Bluetooth subsystem of the Linux kernel,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2021-3752)

    It was discovered that the NFC subsystem in the Linux kernel contained a use-after-free vulnerability in
    its NFC Controller Interface (NCI) implementation. A local attacker could possibly use this to cause a
    denial of service (system crash) or execute arbitrary code. (CVE-2021-3760)

    Szymon Heidrich discovered that the USB Gadget subsystem in the Linux kernel did not properly restrict the
    size of control requests for certain gadget types, leading to possible out of bounds reads or writes. A
    local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2021-39685)

    It was discovered that the Ion Memory Manager subsystem in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could possibly use this to cause a denial of service (system crash) or
    execute arbitrary code. (CVE-2021-39714)

    Eric Biederman discovered that the cgroup process migration implementation in the Linux kernel did not
    perform permission checks correctly in some situations. A local attacker could possibly use this to gain
    administrative privileges. (CVE-2021-4197)

    Lin Ma discovered that the NFC Controller Interface (NCI) implementation in the Linux kernel contained a
    race condition, leading to a use-after-free vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2021-4202)

    Sushma Venkatesh Reddy discovered that the Intel i915 graphics driver in the Linux kernel did not perform
    a GPU TLB flush in some situations. A local attacker could use this to cause a denial of service or
    possibly execute arbitrary code. (CVE-2022-0330)

    It was discovered that the PF_KEYv2 implementation in the Linux kernel did not properly initialize kernel
    memory in some situations. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2022-1353)

    It was discovered that the virtual graphics memory manager implementation in the Linux kernel was subject
    to a race condition, potentially leading to an information leak. (CVE-2022-1419)

    Minh Yuan discovered that the floppy disk driver in the Linux kernel contained a race condition, leading
    to a use-after-free vulnerability. A local attacker could possibly use this to cause a denial of service
    (system crash) or execute arbitrary code. (CVE-2022-1652)

    It was discovered that the Atheros ath9k wireless device driver in the Linux kernel did not properly
    handle some error conditions, leading to a use-after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-1679)

    It was discovered that the Marvell NFC device driver implementation in the Linux kernel did not properly
    perform memory cleanup operations in some situations, leading to a use-after-free vulnerability. A local
    attacker could possibly use this to cause a denial of service (system crash) or execute arbitrary code.
    (CVE-2022-1734)

    It was discovered that some Intel processors did not completely perform cleanup actions on multi-core
    shared buffers. A local attacker could possibly use this to expose sensitive information. (CVE-2022-21123)

    It was discovered that some Intel processors did not completely perform cleanup actions on
    microarchitectural fill buffers. A local attacker could possibly use this to expose sensitive information.
    (CVE-2022-21125)

    It was discovered that some Intel processors did not properly perform cleanup during specific special
    register write operations. A local attacker could possibly use this to expose sensitive information.
    (CVE-2022-21166)

    It was discovered that the USB Gadget file system interface in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2022-24958)

     discovered that the 802.2 LLC type 2 driver in the Linux kernel did not properly perform
    reference counting in some error conditions. A local attacker could use this to cause a denial of service.
    (CVE-2022-28356)

    It was discovered that the 8 Devices USB2CAN interface implementation in the Linux kernel did not properly
    handle certain error conditions, leading to a double-free. A local attacker could possibly use this to
    cause a denial of service (system crash). (CVE-2022-28388)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5505-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24958");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1110-kvm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '16.04': {
    '4.4.0': {
      'kvm': '4.4.0-1110'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5505-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-3609', 'CVE-2021-3752', 'CVE-2021-3760', 'CVE-2021-4197', 'CVE-2021-4202', 'CVE-2021-39685', 'CVE-2021-39714', 'CVE-2022-0330', 'CVE-2022-1353', 'CVE-2022-1419', 'CVE-2022-1652', 'CVE-2022-1679', 'CVE-2022-1734', 'CVE-2022-21123', 'CVE-2022-21125', 'CVE-2022-21166', 'CVE-2022-24958', 'CVE-2022-28356', 'CVE-2022-28388');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5505-1');
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
