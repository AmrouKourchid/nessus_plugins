#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6626-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190518);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-6039",
    "CVE-2023-6176",
    "CVE-2023-6622",
    "CVE-2023-32250",
    "CVE-2023-32252",
    "CVE-2023-32257",
    "CVE-2023-34324",
    "CVE-2023-35827",
    "CVE-2023-46813",
    "CVE-2024-0641"
  );
  script_xref(name:"USN", value:"6626-2");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-6626-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6626-2 advisory.

    Quentin Minster discovered that a race condition existed in the KSMBD implementation in the Linux kernel
    when handling sessions operations. A remote attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2023-32250, CVE-2023-32252, CVE-2023-32257)

    Marek Marczykowski-Grecki discovered that the Xen event channel infrastructure implementation in the
    Linux kernel contained a race condition. An attacker in a guest VM could possibly use this to cause a
    denial of service (paravirtualized device unavailability). (CVE-2023-34324)

    Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver in the Linux kernel during
    device removal. A privileged attacker could use this to cause a denial of service (system crash).
    (CVE-2023-35827)

    Tom Dohrmann discovered that the Secure Encrypted Virtualization (SEV) implementation for AMD processors
    in the Linux kernel contained a race condition when accessing MMIO registers. A local attacker in a SEV
    guest VM could possibly use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2023-46813)

    It was discovered that the Microchip USB Ethernet driver in the Linux kernel contained a race condition
    during device removal, leading to a use- after-free vulnerability. A physically proximate attacker could
    use this to cause a denial of service (system crash). (CVE-2023-6039)

    It was discovered that the TLS subsystem in the Linux kernel did not properly perform cryptographic
    operations in some situations, leading to a null pointer dereference vulnerability. A local attacker could
    use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-6176)

    Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did not properly handle dynset
    expressions passed from userspace, leading to a null pointer dereference vulnerability. A local attacker
    could use this to cause a denial of service (system crash). (CVE-2023-6622)

    It was discovered that the TIPC protocol implementation in the Linux kernel did not properly handle
    locking during tipc_crypto_key_revoke() operations. A local attacker could use this to cause a denial of
    service (kernel deadlock). (CVE-2024-0641)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6626-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1046-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-94-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-94-lowlatency-64k");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '5.15.0': {
      'lowlatency': '5.15.0-94',
      'lowlatency-64k': '5.15.0-94',
      'raspi': '5.15.0-1046'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6626-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-6039', 'CVE-2023-6176', 'CVE-2023-6622', 'CVE-2023-32250', 'CVE-2023-32252', 'CVE-2023-32257', 'CVE-2023-34324', 'CVE-2023-35827', 'CVE-2023-46813', 'CVE-2024-0641');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6626-2');
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
