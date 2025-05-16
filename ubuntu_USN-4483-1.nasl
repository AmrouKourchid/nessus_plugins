#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4483-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140181);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-20810",
    "CVE-2020-10757",
    "CVE-2020-10766",
    "CVE-2020-10767",
    "CVE-2020-10768",
    "CVE-2020-10781",
    "CVE-2020-12655",
    "CVE-2020-12656",
    "CVE-2020-12771",
    "CVE-2020-13974",
    "CVE-2020-14356",
    "CVE-2020-15393",
    "CVE-2020-24394"
  );
  script_xref(name:"USN", value:"4483-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-4483-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-4483-1 advisory.

    Chuhong Yuan discovered that go7007 USB audio device driver in the Linux kernel did not properly
    deallocate memory in some failure conditions. A physically proximate attacker could use this to cause a
    denial of service (memory exhaustion). (CVE-2019-20810)

    Fan Yang discovered that the mremap implementation in the Linux kernel did not properly handle DAX Huge
    Pages. A local attacker with access to DAX storage could use this to gain administrative privileges.
    (CVE-2020-10757)

    It was discovered that the Linux kernel did not correctly apply Speculative Store Bypass Disable (SSBD)
    mitigations in certain situations. A local attacker could possibly use this to expose sensitive
    information. (CVE-2020-10766)

    It was discovered that the Linux kernel did not correctly apply Indirect Branch Predictor Barrier (IBPB)
    mitigations in certain situations. A local attacker could possibly use this to expose sensitive
    information. (CVE-2020-10767)

    It was discovered that the Linux kernel could incorrectly enable Indirect Branch Speculation after it has
    been disabled for a process via a prctl() call. A local attacker could possibly use this to expose
    sensitive information. (CVE-2020-10768)

    Luca Bruno discovered that the zram module in the Linux kernel did not properly restrict unprivileged
    users from accessing the hot_add sysfs file. A local attacker could use this to cause a denial of service
    (memory exhaustion). (CVE-2020-10781)

    It was discovered that the XFS file system implementation in the Linux kernel did not properly validate
    meta data in some circumstances. An attacker could use this to construct a malicious XFS image that, when
    mounted, could cause a denial of service. (CVE-2020-12655)

    It was discovered that the bcache subsystem in the Linux kernel did not properly release a lock in some
    error conditions. A local attacker could possibly use this to cause a denial of service. (CVE-2020-12771)

    It was discovered that the Virtual Terminal keyboard driver in the Linux kernel contained an integer
    overflow. A local attacker could possibly use this to have an unspecified impact. (CVE-2020-13974)

    It was discovered that the cgroup v2 subsystem in the Linux kernel did not properly perform reference
    counting in some situations, leading to a NULL pointer dereference. A local attacker could use this to
    cause a denial of service or possibly gain administrative privileges. (CVE-2020-14356)

    Kyungtae Kim discovered that the USB testing driver in the Linux kernel did not properly deallocate memory
    on disconnect events. A physically proximate attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2020-15393)

    It was discovered that the NFS server implementation in the Linux kernel did not properly honor umask
    settings when setting permissions while creating file system objects if the underlying file system did not
    support ACLs. An attacker could possibly use this to expose sensitive information or violate system
    integrity. (CVE-2020-24394)

    It was discovered that the Kerberos SUNRPC GSS implementation in the Linux kernel did not properly
    deallocate memory on module unload. A local privileged attacker could possibly use this to cause a denial
    of service (memory exhaustion). (CVE-2020-12656)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4483-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14356");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1016-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1023-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-45-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-45-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-45-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '5.4.0-45',
      'generic-lpae': '5.4.0-45',
      'lowlatency': '5.4.0-45',
      'raspi': '5.4.0-1016',
      'aws': '5.4.0-1022',
      'gcp': '5.4.0-1022',
      'oracle': '5.4.0-1022',
      'azure': '5.4.0-1023'
    }
  },
  '20.04': {
    '5.4.0': {
      'generic': '5.4.0-45',
      'generic-lpae': '5.4.0-45',
      'lowlatency': '5.4.0-45',
      'raspi': '5.4.0-1016',
      'aws': '5.4.0-1022',
      'gcp': '5.4.0-1022',
      'oracle': '5.4.0-1022',
      'azure': '5.4.0-1023'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4483-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2019-20810', 'CVE-2020-10757', 'CVE-2020-10766', 'CVE-2020-10767', 'CVE-2020-10768', 'CVE-2020-10781', 'CVE-2020-12655', 'CVE-2020-12656', 'CVE-2020-12771', 'CVE-2020-13974', 'CVE-2020-14356', 'CVE-2020-15393', 'CVE-2020-24394');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4483-1');
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
