#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0351-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210463);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2024-21272");

  script_name(english:"openSUSE 15 Security Update : python-mysql-connector-python (openSUSE-SU-2024:0351-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by a vulnerability as referenced in the openSUSE-
SU-2024:0351-1 advisory.

    - Update to 9.1.0 (boo#1231740, CVE-2024-21272)
      - WL#16452: Bundle all installable authentication plugins when building the C-extension
      - WL#16444: Drop build support for DEB packages
      - WL#16442: Upgrade gssapi version to 1.8.3
      - WL#16411: Improve wheel metadata information for Classic and XDevAPI connectors
      - WL#16341: OpenID Connect (Oauth2 - JWT) Authentication Support
      - WL#16307: Remove Python 3.8 support
      - WL#16306: Add support for Python 3.13
      - BUG#37055435: Connection fails during the TLS negotiation when specifying TLSv1.3 ciphers
      - BUG#37013057: mysql-connector-python Parameterized query SQL injection
      - BUG#36765200: python mysql connector 8.3.0 raise %-.100s:%u when input a wrong host
      - BUG#36577957: Update charset/collation description indicate this is 16 bits
    - 9.0.0:
      - WL#16350: Update dnspython version
      - WL#16318: Deprecate Cursors Prepared Raw and Named Tuple
      - WL#16284: Update the Python Protobuf version
      - WL#16283: Remove OpenTelemetry Bundled Installation
      - BUG#36664998: Packets out of order error is raised while changing user in aio
      - BUG#36611371: Update dnspython required versions to allow latest 2.6.1
      - BUG#36570707: Collation set on connect using C-Extension is ignored
      - BUG#36476195: Incorrect escaping in pure Python mode if sql_mode includes NO_BACKSLASH_ESCAPES
      - BUG#36289767: MySQLCursorBufferedRaw does not skip conversion
    - 8.4.0
      - WL#16203: GPL License Exception Update
      - WL#16173: Update allowed cipher and cipher-suite lists
      - WL#16164: Implement support for new vector data type
      - WL#16127: Remove the FIDO authentication mechanism
      - WL#16053: Support GSSAPI/Kerberos authentication on Windows using authentication_ldap_sasl_client
    plug-in for C-extension
      - BUG#36227964: Improve OpenTelemetry span coverage
      - BUG#36167880: Massive memory leak mysqlx native Protobuf adding to collection
    - 8.3.0
      - WL#16015: Remove use of removed COM_ commands
      - WL#15985: Support GSSAPI/Kerberos authentication on Windows using authentication_ldap_sasl_client
    plug-in for Pure Python
      - WL#15983: Stop using mysql_ssl_set api
      - WL#15982: Remove use of mysql_shutdown
      - WL#15950: Support query parameters for prepared statements
      - WL#15942: Improve type hints and standardize byte type handling
      - WL#15836: Split mysql and mysqlx into different packages
      - WL#15523: Support Python DB API asynchronous execution
      - BUG#35912790: Binary strings are converted when using prepared statements
      - BUG#35832148: Fix Django timezone.utc deprecation warning
      - BUG#35710145: Bad MySQLCursor.statement and result when query text contains code comments
      - BUG#21390859: STATEMENTS GET OUT OF SYNCH WITH RESULT SETS

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231740");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A4QYWY7IAP4RFAA3R6QMK3Q6FFAY4UOZ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dcdd012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21272");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-mysql-connector-python package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-mysql-connector-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'python3-mysql-connector-python-9.1.0-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-mysql-connector-python');
}
