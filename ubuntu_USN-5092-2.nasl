#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5092-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153799);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-3679",
    "CVE-2021-33624",
    "CVE-2021-34556",
    "CVE-2021-35477",
    "CVE-2021-37159",
    "CVE-2021-37576",
    "CVE-2021-38160",
    "CVE-2021-38199",
    "CVE-2021-38201",
    "CVE-2021-38204",
    "CVE-2021-38205",
    "CVE-2021-41073"
  );
  script_xref(name:"USN", value:"5092-2");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-5092-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5092-2 advisory.

    Valentina Palmiotti discovered that the io_uring subsystem in the Linux kernel could be coerced to free
    adjacent memory. A local attacker could use this to execute arbitrary code. (CVE-2021-41073)

    Ofek Kirzner, Adam Morrison, Benedict Schlueter, and Piotr Krysiuk discovered that the BPF verifier in the
    Linux kernel missed possible mispredicted branches due to type confusion, allowing a side-channel attack.
    An attacker could use this to expose sensitive information. (CVE-2021-33624)

    Benedict Schlueter discovered that the BPF subsystem in the Linux kernel did not properly protect against
    Speculative Store Bypass (SSB) side- channel attacks in some situations. A local attacker could possibly
    use this to expose sensitive information. (CVE-2021-34556)

    Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not properly protect against
    Speculative Store Bypass (SSB) side-channel attacks in some situations. A local attacker could possibly
    use this to expose sensitive information. (CVE-2021-35477)

    It was discovered that the tracing subsystem in the Linux kernel did not properly keep track of per-cpu
    ring buffer state. A privileged attacker could use this to cause a denial of service. (CVE-2021-3679)

    It was discovered that the Option USB High Speed Mobile device driver in the Linux kernel did not properly
    handle error conditions. A physically proximate attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2021-37159)

    Alexey Kardashevskiy discovered that the KVM implementation for PowerPC systems in the Linux kernel did
    not properly validate RTAS arguments in some situations. An attacker in a guest vm could use this to cause
    a denial of service (host OS crash) or possibly execute arbitrary code. (CVE-2021-37576)

    It was discovered that the Virtio console implementation in the Linux kernel did not properly validate
    input lengths in some situations. A local attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2021-38160)

    Michael Wakabayashi discovered that the NFSv4 client implementation in the Linux kernel did not properly
    order connection setup operations. An attacker controlling a remote NFS server could use this to cause a
    denial of service on the client. (CVE-2021-38199)

    It was discovered that the Sun RPC implementation in the Linux kernel contained an out-of-bounds access
    error. A remote attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2021-38201)

    It was discovered that the MAX-3421 host USB device driver in the Linux kernel did not properly handle
    device removal events. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2021-38204)

    It was discovered that the Xilinx 10/100 Ethernet Lite device driver in the Linux kernel could report
    pointer addresses in some situations. An attacker could use this information to ease the exploitation of
    another vulnerability. (CVE-2021-38205)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5092-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41073");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1017-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1019-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-37-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-37-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-37-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-37-lowlatency");
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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.11.0': {
      'generic': '5.11.0-37',
      'generic-64k': '5.11.0-37',
      'generic-lpae': '5.11.0-37',
      'lowlatency': '5.11.0-37',
      'azure': '5.11.0-1017',
      'oracle': '5.11.0-1019'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5092-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-3679', 'CVE-2021-33624', 'CVE-2021-34556', 'CVE-2021-35477', 'CVE-2021-37159', 'CVE-2021-37576', 'CVE-2021-38160', 'CVE-2021-38199', 'CVE-2021-38201', 'CVE-2021-38204', 'CVE-2021-38205', 'CVE-2021-41073');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5092-2');
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
