#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6440-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183888);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-0597",
    "CVE-2023-1206",
    "CVE-2023-3772",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-4881",
    "CVE-2023-4921",
    "CVE-2023-31083",
    "CVE-2023-34319",
    "CVE-2023-42752",
    "CVE-2023-42753",
    "CVE-2023-42755"
  );
  script_xref(name:"USN", value:"6440-3");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel (HWE) vulnerabilities (USN-6440-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6440-3 advisory.

    Seth Jenkins discovered that the Linux kernel did not properly perform address randomization for a per-cpu
    memory management structure. A local attacker could use this to expose sensitive information (kernel
    memory) or in conjunction with another kernel vulnerability. (CVE-2023-0597)

    It was discovered that the IPv6 implementation in the Linux kernel contained a high rate of hash
    collisions in connection lookup table. A remote attacker could use this to cause a denial of service
    (excessive CPU consumption). (CVE-2023-1206)

    Yu Hao and Weiteng Chen discovered that the Bluetooth HCI UART driver in the Linux kernel contained a race
    condition, leading to a null pointer dereference vulnerability. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2023-31083)

    Ross Lagerwall discovered that the Xen netback backend driver in the Linux kernel did not properly handle
    certain unusual packets from a paravirtualized network frontend, leading to a buffer overflow. An attacker
    in a guest VM could use this to cause a denial of service (host system crash) or possibly execute
    arbitrary code. (CVE-2023-34319)

    Lin Ma discovered that the Netlink Transformation (XFRM) subsystem in the Linux kernel contained a null
    pointer dereference vulnerability in some situations. A local privileged attacker could use this to cause
    a denial of service (system crash). (CVE-2023-3772)

    Kyle Zeng discovered that the networking stack implementation in the Linux kernel did not properly
    validate skb object size in certain conditions. An attacker could use this cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2023-42752)

    Kyle Zeng discovered that the netfiler subsystem in the Linux kernel did not properly calculate array
    offsets, leading to a out-of-bounds write vulnerability. A local user could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-42753)

    Kyle Zeng discovered that the IPv4 Resource Reservation Protocol (RSVP) classifier implementation in the
    Linux kernel contained an out-of-bounds read vulnerability. A local attacker could use this to cause a
    denial of service (system crash). Please note that kernel packet classifier support for RSVP has been
    removed to resolve this vulnerability. (CVE-2023-42755)

    Bing-Jhong Billy Jheng discovered that the Unix domain socket implementation in the Linux kernel contained
    a race condition in certain situations, leading to a use-after-free vulnerability. A local attacker could
    use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-4622)

    Budimir Markovic discovered that the qdisc implementation in the Linux kernel did not properly validate
    inner classes, leading to a use-after-free vulnerability. A local user could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-4623)

    Alex Birnberg discovered that the netfilter subsystem in the Linux kernel did not properly validate
    register length, leading to an out-of- bounds write vulnerability. A local attacker could possibly use
    this to cause a denial of service (system crash). (CVE-2023-4881)

    It was discovered that the Quick Fair Queueing scheduler implementation in the Linux kernel did not
    properly handle network packets in certain conditions, leading to a use after free vulnerability. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2023-4921)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6440-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4921");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1162-aws");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '4.15.0': {
      'aws': '4.15.0-1162'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6440-3');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-0597', 'CVE-2023-1206', 'CVE-2023-3772', 'CVE-2023-4622', 'CVE-2023-4623', 'CVE-2023-4881', 'CVE-2023-4921', 'CVE-2023-31083', 'CVE-2023-34319', 'CVE-2023-42752', 'CVE-2023-42753', 'CVE-2023-42755');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6440-3');
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
