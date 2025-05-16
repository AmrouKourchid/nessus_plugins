#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7146-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212215);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/10");

  script_cve_id("CVE-2017-7537", "CVE-2020-25715", "CVE-2022-2414");
  script_xref(name:"USN", value:"7146-1");

  script_name(english:"Ubuntu 16.04 LTS / 22.04 LTS : Dogtag PKI vulnerabilities (USN-7146-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-7146-1 advisory.

    Christina Fu discovered that Dogtag PKI accidentally enabled a mock authentication plugin by default. An
    attacker could potentially use this flaw to bypass the regular authentication process and trick the CA
    server into issuing certificates. This issue only affected Ubuntu 16.04 LTS. (CVE-2017-7537)

    It was discovered that Dogtag PKI did not properly sanitize user input. An attacker could possibly use
    this issue to perform cross site scripting and obtain sensitive information. This issue only affected
    Ubuntu 22.04 LTS. (CVE-2020-25715)

    It was discovered that the XML parser did not properly handle entity expansion. A remote attacker could
    potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests. This issue
    only affected Ubuntu 16.04 LTS. (CVE-2022-2414)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7146-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7537");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2414");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dogtag-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dogtag-pki-console-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dogtag-pki-server-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsymkey-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsymkey-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-ocsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-tks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-tps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pki-tps-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pki-base");
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
if (! ('16.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'dogtag-pki', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'dogtag-pki-console-theme', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'dogtag-pki-server-theme', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libsymkey-java', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libsymkey-jni', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-base', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-ca', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-console', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-javadoc', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-kra', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-ocsp', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-server', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-tks', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-tools', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-tps', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'pki-tps-client', 'pkgver': '10.2.6+git20160317-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'dogtag-pki', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'dogtag-pki-console-theme', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'dogtag-pki-server-theme', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libsymkey-java', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libsymkey-jni', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-base', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-base-java', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-ca', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-console', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-javadoc', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-kra', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-ocsp', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-server', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-tks', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-tools', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-tps', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'pki-tps-client', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3-pki-base', 'pkgver': '11.0.0-1ubuntu0.1~esm1', 'ubuntu_pro': TRUE}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dogtag-pki / dogtag-pki-console-theme / dogtag-pki-server-theme / etc');
}
