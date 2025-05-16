#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3485-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104735);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-15265",
    "CVE-2017-15299",
    "CVE-2017-15649",
    "CVE-2017-15951",
    "CVE-2017-16525",
    "CVE-2017-16526",
    "CVE-2017-16527",
    "CVE-2017-16529",
    "CVE-2017-16530",
    "CVE-2017-16531",
    "CVE-2017-16533",
    "CVE-2017-16534",
    "CVE-2017-16535"
  );
  script_xref(name:"USN", value:"3485-3");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (AWS) vulnerabilities (USN-3485-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3485-3 advisory.

    It was discovered that a race condition existed in the ALSA subsystem of the Linux kernel when creating
    and deleting a port via ioctl(). A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2017-15265)

    Eric Biggers discovered that the key management subsystem in the Linux kernel did not properly restrict
    adding a key that already exists but is uninstantiated. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2017-15299)

    It was discovered that a race condition existed in the packet fanout implementation in the Linux kernel. A
    local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2017-15649)

    Eric Biggers discovered a race condition in the key management subsystem of the Linux kernel around keys
    in a negative state. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2017-15951)

    Andrey Konovalov discovered a use-after-free vulnerability in the USB serial console driver in the Linux
    kernel. A physically proximate attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2017-16525)

    Andrey Konovalov discovered that the Ultra Wide Band driver in the Linux kernel did not properly check for
    an error condition. A physically proximate attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2017-16526)

    Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2017-16527)

    Andrey Konovalov discovered that the ALSA subsystem in the Linux kernel did not properly validate USB
    audio buffer descriptors. A physically proximate attacker could use this cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2017-16529)

    Andrey Konovalov discovered that the USB unattached storage driver in the Linux kernel contained out-of-
    bounds error when handling alternative settings. A physically proximate attacker could use to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2017-16530)

    Andrey Konovalov discovered that the USB subsystem in the Linux kernel did not properly validate USB
    interface association descriptors. A physically proximate attacker could use this to cause a denial of
    service (system crash). (CVE-2017-16531)

    Andrey Konovalov discovered that the USB subsystem in the Linux kernel did not properly validate USB HID
    descriptors. A physically proximate attacker could use this to cause a denial of service (system crash).
    (CVE-2017-16533)

    Andrey Konovalov discovered that the USB subsystem in the Linux kernel did not properly validate CDC
    metadata. A physically proximate attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2017-16534)

    Andrey Konovalov discovered that the USB subsystem in the Linux kernel did not properly validate USB BOS
    metadata. A physically proximate attacker could use this to cause a denial of service (system crash).
    (CVE-2017-16535)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3485-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16535");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16526");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1003-aws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '14.04': {
    '4.4.0': {
      'aws': '4.4.0-1003'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3485-3');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-15265', 'CVE-2017-15299', 'CVE-2017-15649', 'CVE-2017-15951', 'CVE-2017-16525', 'CVE-2017-16526', 'CVE-2017-16527', 'CVE-2017-16529', 'CVE-2017-16530', 'CVE-2017-16531', 'CVE-2017-16533', 'CVE-2017-16534', 'CVE-2017-16535');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3485-3');
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
