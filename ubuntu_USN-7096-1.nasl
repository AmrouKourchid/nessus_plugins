#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7096-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210735);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id(
    "CVE-2024-20918",
    "CVE-2024-20919",
    "CVE-2024-20921",
    "CVE-2024-20926",
    "CVE-2024-20945",
    "CVE-2024-20952",
    "CVE-2024-21011",
    "CVE-2024-21068",
    "CVE-2024-21085",
    "CVE-2024-21094",
    "CVE-2024-21131",
    "CVE-2024-21138",
    "CVE-2024-21140",
    "CVE-2024-21144",
    "CVE-2024-21145",
    "CVE-2024-21147",
    "CVE-2024-21208",
    "CVE-2024-21210",
    "CVE-2024-21217",
    "CVE-2024-21235"
  );
  script_xref(name:"USN", value:"7096-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : OpenJDK 8 vulnerabilities (USN-7096-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-7096-1 advisory.

    Andy Boothe discovered that the Networking component of OpenJDK 8 did not properly handle access under
    certain circumstances. An unauthenticated

    attacker could possibly use this issue to cause a denial of service.

    (CVE-2024-21208)

    It was discovered that the Hotspot component of OpenJDK 8 did not properly handle vectorization under
    certain circumstances. An unauthenticated

    attacker could possibly use this issue to access unauthorized resources

    and expose sensitive information. (CVE-2024-21210, CVE-2024-21235)

    It was discovered that the Serialization component of OpenJDK 8 did not

    properly handle deserialization under certain circumstances. An

    unauthenticated attacker could possibly use this issue to cause a denial of service. (CVE-2024-21217)

    It was discovered that the Hotspot component of OpenJDK 8 was not properly bounding certain UTF-8 strings,
    which could lead to a buffer overflow. An attacker could possibly use this issue to cause a denial of
    service or execute arbitrary code. This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-21131)

    It was discovered that the Hotspot component of OpenJDK 8 could be made to run into an infinite loop. If
    an automated system were tricked into processing excessively large symbols, an attacker could possibly use
    this issue to cause a denial of service. This issue was only addressed in Ubuntu 16.04 LTS.
    (CVE-2024-21138)

    It was discovered that the Hotspot component of OpenJDK 8 did not properly perform range check
    elimination. An attacker could possibly use this issue to cause a denial of service, execute arbitrary
    code or bypass Java sandbox restrictions. This issue was only addressed in Ubuntu 16.04 LTS.

    (CVE-2024-21140)

    Yakov Shafranovich discovered that the Concurrency component of OpenJDK 8 incorrectly performed header
    validation in the Pack200 archive format. An attacker could possibly use this issue to cause a denial of
    service. This

    issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-21144)

    Sergey Bylokhov discovered that OpenJDK 8 did not properly manage memory when handling 2D images. An
    attacker could possibly use this issue to obtain sensitive information. This issue was only addressed in
    Ubuntu

    16.04 LTS. (CVE-2024-21145)

    It was discovered that the Hotspot component of OpenJDK 8 incorrectly handled memory when performing range
    check elimination under certain circumstances. An attacker could possibly use this issue to cause a denial
    of service, execute arbitrary code or bypass Java sandbox restrictions. This issue was only addressed in
    Ubuntu 16.04 LTS.

    (CVE-2024-21147)

    It was discovered that the Hotspot component of OpenJDK 8 incorrectly handled certain exceptions with
    specially crafted long messages. An attacker could possibly use this issue to cause a denial of service.
    This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-21011)

    Vladimir Kondratyev discovered that the Hotspot component of OpenJDK 8 incorrectly handled address offset
    calculations in the C1 compiler. An attacker could possibly use this issue to cause a denial of service or
    execute arbitrary code. This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-21068)

    Yakov Shafranovich discovered that OpenJDK 8 did not properly manage memory in the Pack200 archive format.
    An attacker could possibly use this issue to cause a denial of service. This issue was only addressed in
    Ubuntu 16.04 LTS. (CVE-2024-21085)

    It was discovered that the Hotspot component of OpenJDK 8 incorrectly handled array accesses in the C2
    compiler. An attacker could possibly use this issue to cause a denial of service or execute arbitrary
    code. This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-21094)

    Yi Yang discovered that the Hotspot component of OpenJDK 8 incorrectly handled array accesses in the C1
    compiler. An attacker could possibly use this issue to cause a denial of service, execute arbitrary code
    or bypass Java sandbox restrictions. This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-20918)

    It was discovered that the Hotspot component of OpenJDK 8 did not properly verify bytecode in certain
    situations. An attacker could possibly use this issue to bypass Java sandbox restrictions. This

    issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-20919)

    It was discovered that the Hotspot component of OpenJDK 8 had an optimization flaw when generating range
    check loop predicates. An attacker could possibly use this issue to cause a denial of service, execute
    arbitrary code or bypass Java sandbox restrictions. This issue was only

    addressed in Ubuntu 16.04 LTS. (CVE-2024-20921)

    Valentin Eudeline discovered that OpenJDK 8 incorrectly handled certain options in the Nashorn JavaScript
    subcomponent. An attacker could possibly use this issue to execute arbitrary code. This issue was only

    addressed in Ubuntu 16.04 LTS. (CVE-2024-20926)

    It was discovered that OpenJDK 8 could produce debug logs that contained private keys used for digital
    signatures. An attacker could possibly use this issue to obtain sensitive information. This issue was only
    addressed in Ubuntu 16.04 LTS. (CVE-2024-20945)

    Hubert Kario discovered that the TLS implementation in OpenJDK 8 had a timing side-channel and incorrectly
    handled RSA padding. A remote attacker could possibly use this issue to recover sensitive information.
    This

    issue was only addressed in Ubuntu 16.04 LTS. (CVE-2024-20952)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7096-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u432-ga~us1-0ubuntu2~16.04.4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u432-ga~us1-0ubuntu2~18.04', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u432-ga~us1-0ubuntu2~20.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u432-ga~us1-0ubuntu2~22.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u432-ga~us1-0ubuntu2~24.04', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'openjdk-8-source', 'pkgver': '8u432-ga~us1-0ubuntu2~24.10', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-8-demo / openjdk-8-jdk / openjdk-8-jdk-headless / etc');
}
