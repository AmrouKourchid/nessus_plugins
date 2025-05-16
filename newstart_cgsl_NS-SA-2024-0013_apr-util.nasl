#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0013. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193545);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2022-25147");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : apr-util Vulnerability (NS-SA-2024-0013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has apr-util packages installed that are affected
by a vulnerability:

  - Integer Overflow or Wraparound vulnerability in apr_base64 functions of Apache Portable Runtime Utility
    (APR-util) allows an attacker to write beyond bounds of a buffer. This issue affects Apache Portable
    Runtime Utility (APR-util) 1.6.1 and prior versions. (CVE-2022-25147)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0013");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-25147");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL apr-util packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'apr-util-1.5.2-6.el7_9.1',
    'apr-util-debuginfo-1.5.2-6.el7_9.1',
    'apr-util-devel-1.5.2-6.el7_9.1',
    'apr-util-ldap-1.5.2-6.el7_9.1',
    'apr-util-mysql-1.5.2-6.el7_9.1',
    'apr-util-nss-1.5.2-6.el7_9.1',
    'apr-util-odbc-1.5.2-6.el7_9.1',
    'apr-util-openssl-1.5.2-6.el7_9.1',
    'apr-util-pgsql-1.5.2-6.el7_9.1',
    'apr-util-sqlite-1.5.2-6.el7_9.1'
  ],
  'CGSL MAIN 5.04': [
    'apr-util-1.5.2-6.el7_9.1',
    'apr-util-debuginfo-1.5.2-6.el7_9.1',
    'apr-util-devel-1.5.2-6.el7_9.1',
    'apr-util-ldap-1.5.2-6.el7_9.1',
    'apr-util-mysql-1.5.2-6.el7_9.1',
    'apr-util-nss-1.5.2-6.el7_9.1',
    'apr-util-odbc-1.5.2-6.el7_9.1',
    'apr-util-openssl-1.5.2-6.el7_9.1',
    'apr-util-pgsql-1.5.2-6.el7_9.1',
    'apr-util-sqlite-1.5.2-6.el7_9.1'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apr-util');
}
