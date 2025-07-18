#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5648-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165600);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2021-33655",
    "CVE-2022-2318",
    "CVE-2022-26365",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-33743",
    "CVE-2022-33744",
    "CVE-2022-34494",
    "CVE-2022-34495",
    "CVE-2022-36946"
  );
  script_xref(name:"USN", value:"5648-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (GKE) vulnerabilities (USN-5648-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5648-1 advisory.

    It was discovered that the framebuffer driver on the Linux kernel did not verify size limits when changing
    font or screen size, leading to an out-of- bounds write. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2021-33655)

    Duoming Zhou discovered that race conditions existed in the timer handling implementation of the Linux
    kernel's Rose X.25 protocol layer, resulting in use-after-free vulnerabilities. A local attacker could use
    this to cause a denial of service (system crash). (CVE-2022-2318)

    Roger Pau Monn discovered that the Xen virtual block driver in the Linux kernel did not properly
    initialize memory pages to be used for shared communication with the backend. A local attacker could use
    this to expose sensitive information (guest kernel memory). (CVE-2022-26365)

    Roger Pau Monn discovered that the Xen paravirtualization frontend in the Linux kernel did not properly
    initialize memory pages to be used for shared communication with the backend. A local attacker could use
    this to expose sensitive information (guest kernel memory). (CVE-2022-33740)

    It was discovered that the Xen paravirtualization frontend in the Linux kernel incorrectly shared
    unrelated data when communicating with certain backends. A local attacker could use this to cause a denial
    of service (guest crash) or expose sensitive information (guest kernel memory). (CVE-2022-33741,
    CVE-2022-33742)

    Jan Beulich discovered that the Xen network device frontend driver in the Linux kernel incorrectly handled
    socket buffers (skb) references when communicating with certain backends. A local attacker could use this
    to cause a denial of service (guest crash). (CVE-2022-33743)

    Oleksandr Tyshchenko discovered that the Xen paravirtualization platform in the Linux kernel on ARM
    platforms contained a race condition in certain situations. An attacker in a guest VM could use this to
    cause a denial of service in the host OS. (CVE-2022-33744)

    It was discovered that the virtio RPMSG bus driver in the Linux kernel contained a double-free
    vulnerability in certain error conditions. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2022-34494, CVE-2022-34495)

    Domingo Dirutigliano and Nicola Guerrera discovered that the netfilter subsystem in the Linux kernel did
    not properly handle rules that truncated packets below the packet header size. When such rules are in
    place, a remote attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2022-36946)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5648-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1016-gke");
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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.15.0': {
      'gke': '5.15.0-1016'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5648-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-33655', 'CVE-2022-2318', 'CVE-2022-26365', 'CVE-2022-33740', 'CVE-2022-33741', 'CVE-2022-33742', 'CVE-2022-33743', 'CVE-2022-33744', 'CVE-2022-34494', 'CVE-2022-34495', 'CVE-2022-36946');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5648-1');
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
