#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7165-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213099);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2022-22965");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");
  script_xref(name:"USN", value:"7165-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : Spring Framework vulnerability (USN-7165-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by
a vulnerability as referenced in the USN-7165-1 advisory.

    It was discovered that the Spring Framework incorrectly handled web requests via data binding. An attacker
    could possibly use this issue to achieve remote code execution and obtain sensitive information.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7165-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Spring Framework Class property RCE (Spring4Shell)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-aop-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-beans-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-context-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-context-support-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-core-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-expression-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-instrument-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-jdbc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-jms-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-messaging-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-orm-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-oxm-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-test-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-transaction-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-web-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-web-portlet-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspring-web-servlet-java");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libspring-aop-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-beans-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-context-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-context-support-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-core-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-expression-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-instrument-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-jdbc-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-jms-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-messaging-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-orm-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-oxm-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-test-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-transaction-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-web-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-web-portlet-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libspring-web-servlet-java', 'pkgver': '4.3.22-1~18.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-aop-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-beans-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-context-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-context-support-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-core-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-expression-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-instrument-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-jdbc-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-jms-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-messaging-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-orm-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-oxm-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-test-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-transaction-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-web-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-web-portlet-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libspring-web-servlet-java', 'pkgver': '4.3.22-4ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-aop-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-beans-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-context-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-context-support-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-core-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-expression-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-instrument-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-jdbc-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-jms-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-messaging-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-orm-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-oxm-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-test-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-transaction-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-web-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-web-portlet-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libspring-web-servlet-java', 'pkgver': '4.3.30-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-aop-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-beans-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-context-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-context-support-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-core-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-expression-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-instrument-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-jdbc-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-jms-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-messaging-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-orm-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-oxm-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-test-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-transaction-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-web-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-web-portlet-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'libspring-web-servlet-java', 'pkgver': '4.3.30-2ubuntu0.24.04.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.10', 'pkgname': 'libspring-aop-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-beans-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-context-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-context-support-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-core-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-expression-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-instrument-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-jdbc-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-jms-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-messaging-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-orm-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-oxm-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-test-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-transaction-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-web-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-web-portlet-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libspring-web-servlet-java', 'pkgver': '4.3.30-2ubuntu0.24.10.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libspring-aop-java / libspring-beans-java / libspring-context-java / etc');
}
