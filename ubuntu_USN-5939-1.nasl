#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5939-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172362);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2022-3169",
    "CVE-2022-3424",
    "CVE-2022-3435",
    "CVE-2022-3521",
    "CVE-2022-3545",
    "CVE-2022-3623",
    "CVE-2022-4139",
    "CVE-2022-36280",
    "CVE-2022-41218",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-47520",
    "CVE-2022-47929",
    "CVE-2023-0045",
    "CVE-2023-0266",
    "CVE-2023-0394",
    "CVE-2023-0461",
    "CVE-2023-20938",
    "CVE-2023-23454",
    "CVE-2023-23455"
  );
  script_xref(name:"USN", value:"5939-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel (GCP) vulnerabilities (USN-5939-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5939-1 advisory.

    It was discovered that the Upper Level Protocol (ULP) subsystem in the Linux kernel did not properly
    handle sockets entering the LISTEN state in certain protocols, leading to a use-after-free vulnerability.
    A local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2023-0461)

    It was discovered that the NVMe driver in the Linux kernel did not properly handle reset events in some
    situations. A local attacker could use this to cause a denial of service (system crash). (CVE-2022-3169)

    It was discovered that a use-after-free vulnerability existed in the SGI GRU driver in the Linux kernel. A
    local attacker could possibly use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2022-3424)

    Gwangun Jung discovered a race condition in the IPv4 implementation in the Linux kernel when deleting
    multipath routes, resulting in an out-of-bounds read. An attacker could use this to cause a denial of
    service (system crash) or possibly expose sensitive information (kernel memory). (CVE-2022-3435)

    It was discovered that a race condition existed in the Kernel Connection Multiplexor (KCM) socket
    implementation in the Linux kernel when releasing sockets in certain situations. A local attacker could
    use this to cause a denial of service (system crash). (CVE-2022-3521)

    It was discovered that the Netronome Ethernet driver in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2022-3545)

    It was discovered that the hugetlb implementation in the Linux kernel contained a race condition in some
    situations. A local attacker could use this to cause a denial of service (system crash) or expose
    sensitive information (kernel memory). (CVE-2022-3623)

    Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux kernel contained an out-of-
    bounds write vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-36280)

    Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel did not properly perform reference
    counting in some situations, leading to a use- after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-41218)

    It was discovered that the Intel i915 graphics driver in the Linux kernel did not perform a GPU TLB flush
    in some situations. A local attacker could use this to cause a denial of service or possibly execute
    arbitrary code. (CVE-2022-4139)

    It was discovered that a race condition existed in the Xen network backend driver in the Linux kernel when
    handling dropped packets in certain circumstances. An attacker could use this to cause a denial of service
    (kernel deadlock). (CVE-2022-42328, CVE-2022-42329)

    It was discovered that the Atmel WILC1000 driver in the Linux kernel did not properly validate offsets,
    leading to an out-of-bounds read vulnerability. An attacker could use this to cause a denial of service
    (system crash). (CVE-2022-47520)

    It was discovered that the network queuing discipline implementation in the Linux kernel contained a null
    pointer dereference in some situations. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2022-47929)

    Jos Oliveira and Rodrigo Branco discovered that the prctl syscall implementation in the Linux kernel did
    not properly protect against indirect branch prediction attacks in some situations. A local attacker could
    possibly use this to expose sensitive information. (CVE-2023-0045)

    It was discovered that a use-after-free vulnerability existed in the Advanced Linux Sound Architecture
    (ALSA) subsystem. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2023-0266)

    Kyle Zeng discovered that the IPv6 implementation in the Linux kernel contained a NULL pointer dereference
    vulnerability in certain situations. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2023-0394)

    It was discovered that the Android Binder IPC subsystem in the Linux kernel did not properly validate
    inputs in some situations, leading to a use- after-free vulnerability. A local attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-20938)

    Kyle Zeng discovered that the class-based queuing discipline implementation in the Linux kernel contained
    a type confusion vulnerability in some situations. An attacker could use this to cause a denial of service
    (system crash). (CVE-2023-23454)

    Kyle Zeng discovered that the ATM VC queuing discipline implementation in the Linux kernel contained a
    type confusion vulnerability in some situations. An attacker could use this to cause a denial of service
    (system crash). (CVE-2023-23455)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5939-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-20938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1101-gcp");
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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '18.04': {
    '5.4.0': {
      'gcp': '5.4.0-1101'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5939-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3169', 'CVE-2022-3424', 'CVE-2022-3435', 'CVE-2022-3521', 'CVE-2022-3545', 'CVE-2022-3623', 'CVE-2022-4139', 'CVE-2022-36280', 'CVE-2022-41218', 'CVE-2022-42328', 'CVE-2022-42329', 'CVE-2022-47520', 'CVE-2022-47929', 'CVE-2023-0045', 'CVE-2023-0266', 'CVE-2023-0394', 'CVE-2023-0461', 'CVE-2023-20938', 'CVE-2023-23454', 'CVE-2023-23455');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5939-1');
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
