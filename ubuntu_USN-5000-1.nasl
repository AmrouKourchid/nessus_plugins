#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5000-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150957);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26141",
    "CVE-2020-26145",
    "CVE-2020-26147",
    "CVE-2021-3506",
    "CVE-2021-3609",
    "CVE-2021-23133",
    "CVE-2021-23134",
    "CVE-2021-31829",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33200"
  );
  script_xref(name:"USN", value:"5000-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5000-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5000-1 advisory.

    Norbert Slusarek discovered a race condition in the CAN BCM networking protocol of the Linux kernel
    leading to multiple use-after-free vulnerabilities. A local attacker could use this issue to execute
    arbitrary code. (CVE-2021-3609)

    Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel did not properly enforce limits
    for pointer operations. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2021-33200)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation did not properly clear received
    fragments from memory in some situations. A physically proximate attacker could possibly use this issue to
    inject packets or expose sensitive information. (CVE-2020-24586)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation incorrectly handled encrypted
    fragments. A physically proximate attacker could possibly use this issue to decrypt fragments.
    (CVE-2020-24587)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation incorrectly handled certain
    malformed frames. If a user were tricked into connecting to a malicious server, a physically proximate
    attacker could use this issue to inject packets. (CVE-2020-24588)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation incorrectly handled EAPOL frames
    from unauthenticated senders. A physically proximate attacker could inject malicious packets to cause a
    denial of service (system crash). (CVE-2020-26139)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation did not properly verify certain
    fragmented frames. A physically proximate attacker could possibly use this issue to inject or decrypt
    packets. (CVE-2020-26141)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation accepted plaintext fragments in
    certain situations. A physically proximate attacker could use this issue to inject packets.
    (CVE-2020-26145)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation could reassemble mixed encrypted
    and plaintext fragments. A physically proximate attacker could possibly use this issue to inject packets
    or exfiltrate selected fragments. (CVE-2020-26147)

    Or Cohen discovered that the SCTP implementation in the Linux kernel contained a race condition in some
    situations, leading to a use-after-free condition. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2021-23133)

    Or Cohen and Nadav Markus discovered a use-after-free vulnerability in the nfc implementation in the Linux
    kernel. A privileged local attacker could use this issue to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2021-23134)

    Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel did not properly prevent
    speculative loads in certain situations. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2021-31829)

    It was discovered that a race condition in the kernel Bluetooth subsystem could lead to use-after-free of
    slab objects. An attacker could use this issue to possibly execute arbitrary code. (CVE-2021-32399)

    It was discovered that a use-after-free existed in the Bluetooth HCI driver of the Linux kernel. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-33034)

    It was discovered that an out-of-bounds (OOB) memory access flaw existed in the f2fs module of the Linux
    kernel. A local attacker could use this issue to cause a denial of service (system crash). (CVE-2021-3506)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5000-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33200");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1018-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1038-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1046-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1048-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1051-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1051-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-77-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-77-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-77-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '5.4.0-77',
      'generic-lpae': '5.4.0-77',
      'lowlatency': '5.4.0-77',
      'gkeop': '5.4.0-1018',
      'raspi': '5.4.0-1038',
      'gcp': '5.4.0-1046',
      'oracle': '5.4.0-1048',
      'aws': '5.4.0-1051',
      'azure': '5.4.0-1051'
    }
  },
  '20.04': {
    '5.4.0': {
      'generic': '5.4.0-77',
      'generic-lpae': '5.4.0-77',
      'lowlatency': '5.4.0-77',
      'gkeop': '5.4.0-1018',
      'raspi': '5.4.0-1038',
      'gcp': '5.4.0-1046',
      'oracle': '5.4.0-1048',
      'aws': '5.4.0-1051',
      'azure': '5.4.0-1051'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5000-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-24586', 'CVE-2020-24587', 'CVE-2020-24588', 'CVE-2020-26139', 'CVE-2020-26141', 'CVE-2020-26145', 'CVE-2020-26147', 'CVE-2021-3506', 'CVE-2021-3609', 'CVE-2021-23133', 'CVE-2021-23134', 'CVE-2021-31829', 'CVE-2021-32399', 'CVE-2021-33034', 'CVE-2021-33200');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5000-1');
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
