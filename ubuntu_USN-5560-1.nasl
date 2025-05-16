##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5560-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164013);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-0494",
    "CVE-2022-1048",
    "CVE-2022-1195",
    "CVE-2022-1652",
    "CVE-2022-1679",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-33981",
    "CVE-2022-34918"
  );
  script_xref(name:"USN", value:"5560-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-5560-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5560-1 advisory.

    Zhenpeng Lin discovered that the network packet scheduler implementation in the Linux kernel did not
    properly remove all references to a route filter before freeing it in some situations. A local attacker
    could use this to cause a denial of service (system crash) or execute arbitrary code. (CVE-2022-2588)

    It was discovered that the netfilter subsystem of the Linux kernel did not prevent one nft object from
    referencing an nft set in another nft table, leading to a use-after-free vulnerability. A local attacker
    could use this to cause a denial of service (system crash) or execute arbitrary code. (CVE-2022-2586)

    It was discovered that the block layer subsystem in the Linux kernel did not properly initialize memory in
    some situations. A privileged local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2022-0494)

    Hu Jiahui discovered that multiple race conditions existed in the Advanced Linux Sound Architecture (ALSA)
    framework, leading to use-after-free vulnerabilities. A local attacker could use these to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2022-1048)

    It was discovered that the implementation of the 6pack and mkiss protocols in the Linux kernel did not
    handle detach events properly in some situations, leading to a use-after-free vulnerability. A local
    attacker could possibly use this to cause a denial of service (system crash). (CVE-2022-1195)

    Minh Yuan discovered that the floppy disk driver in the Linux kernel contained a race condition, leading
    to a use-after-free vulnerability. A local attacker could possibly use this to cause a denial of service
    (system crash) or execute arbitrary code. (CVE-2022-1652)

    It was discovered that the Atheros ath9k wireless device driver in the Linux kernel did not properly
    handle some error conditions, leading to a use-after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-1679)

    Norbert Slusarek discovered that a race condition existed in the perf subsystem in the Linux kernel,
    resulting in a use-after-free vulnerability. A privileged local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2022-1729)

    It was discovered that the Marvell NFC device driver implementation in the Linux kernel did not properly
    perform memory cleanup operations in some situations, leading to a use-after-free vulnerability. A local
    attacker could possibly use this to cause a denial of service (system crash) or execute arbitrary code.
    (CVE-2022-1734)

    Duoming Zhou discovered a race condition in the NFC subsystem in the Linux kernel, leading to a use-after-
    free vulnerability. A privileged local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2022-1974)

    Duoming Zhou discovered that the NFC subsystem in the Linux kernel did not properly prevent context
    switches from occurring during certain atomic context operations. A privileged local attacker could use
    this to cause a denial of service (system crash). (CVE-2022-1975)

    Minh Yuan discovered that the floppy driver in the Linux kernel contained a race condition in some
    situations, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2022-33981)

    Arthur Mongodin discovered that the netfilter subsystem in the Linux kernel did not properly perform data
    validation. A local attacker could use this to escalate privileges in certain situations. (CVE-2022-34918)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5560-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1051-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1104-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1117-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1125-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1134-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1135-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1139-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1149-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-191-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-191-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-191-lowlatency");
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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-191',
      'generic-lpae': '4.15.0-191',
      'lowlatency': '4.15.0-191',
      'dell300x': '4.15.0-1051',
      'oracle': '4.15.0-1104',
      'raspi2': '4.15.0-1117',
      'kvm': '4.15.0-1125',
      'gcp': '4.15.0-1134',
      'snapdragon': '4.15.0-1135',
      'aws': '4.15.0-1139',
      'azure': '4.15.0-1149'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5560-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-0494', 'CVE-2022-1048', 'CVE-2022-1195', 'CVE-2022-1652', 'CVE-2022-1679', 'CVE-2022-1729', 'CVE-2022-1734', 'CVE-2022-1974', 'CVE-2022-1975', 'CVE-2022-2586', 'CVE-2022-2588', 'CVE-2022-33981', 'CVE-2022-34918');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5560-1');
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
