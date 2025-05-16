#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2025:1671.
##

include('compat.inc');

if (description)
{
  script_id(216621);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2024-5535",
    "CVE-2024-7264",
    "CVE-2024-11053",
    "CVE-2024-21193",
    "CVE-2024-21194",
    "CVE-2024-21196",
    "CVE-2024-21197",
    "CVE-2024-21198",
    "CVE-2024-21199",
    "CVE-2024-21201",
    "CVE-2024-21203",
    "CVE-2024-21212",
    "CVE-2024-21213",
    "CVE-2024-21218",
    "CVE-2024-21219",
    "CVE-2024-21230",
    "CVE-2024-21231",
    "CVE-2024-21236",
    "CVE-2024-21237",
    "CVE-2024-21238",
    "CVE-2024-21239",
    "CVE-2024-21241",
    "CVE-2024-21247",
    "CVE-2024-37371",
    "CVE-2025-21490",
    "CVE-2025-21491",
    "CVE-2025-21494",
    "CVE-2025-21497",
    "CVE-2025-21500",
    "CVE-2025-21501",
    "CVE-2025-21503",
    "CVE-2025-21504",
    "CVE-2025-21505",
    "CVE-2025-21518",
    "CVE-2025-21519",
    "CVE-2025-21520",
    "CVE-2025-21521",
    "CVE-2025-21522",
    "CVE-2025-21523",
    "CVE-2025-21525",
    "CVE-2025-21529",
    "CVE-2025-21531",
    "CVE-2025-21534",
    "CVE-2025-21536",
    "CVE-2025-21540",
    "CVE-2025-21543",
    "CVE-2025-21546",
    "CVE-2025-21555",
    "CVE-2025-21559"
  );
  script_xref(name:"ALSA", value:"2025:1671");
  script_xref(name:"IAVA", value:"2024-A-0731");
  script_xref(name:"RHSA", value:"2025:1671");
  script_xref(name:"IAVA", value:"2025-A-0272");

  script_name(english:"AlmaLinux 9 : mysql (ALSA-2025:1671)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2025:1671 advisory.

    * openssl: SSL_select_next_proto buffer overread (CVE-2024-5535)
      * krb5: GSS message token handling (CVE-2024-37371)
      * curl: libcurl: ASN.1 date parser overread (CVE-2024-7264)
      * mysql: Thread Pooling unspecified vulnerability (CPU Oct 2024) (CVE-2024-21238)
      * mysql: X Plugin unspecified vulnerability (CPU Oct 2024) (CVE-2024-21196)
      * mysql: Optimizer unspecified vulnerability (CPU Oct 2024) (CVE-2024-21241)
      * mysql: Client programs unspecified vulnerability (CPU Oct 2024) (CVE-2024-21231)
      * mysql: Information Schema unspecified vulnerability (CPU Oct 2024) (CVE-2024-21197)
      * mysql: InnoDB unspecified vulnerability (CPU Oct 2024) (CVE-2024-21218)
      * mysql: Optimizer unspecified vulnerability (CPU Oct 2024) (CVE-2024-21201)
      * mysql: InnoDB unspecified vulnerability (CPU Oct 2024) (CVE-2024-21236)
      * mysql: Group Replication GCS unspecified vulnerability (CPU Oct 2024) (CVE-2024-21237)
      * mysql: FTS unspecified vulnerability (CPU Oct 2024) (CVE-2024-21203)
      * mysql: Health Monitor unspecified vulnerability (CPU Oct 2024) (CVE-2024-21212)
      * mysql: DML unspecified vulnerability (CPU Oct 2024) (CVE-2024-21219)
      * mysql: Optimizer unspecified vulnerability (CPU Oct 2024) (CVE-2024-21230)
      * mysql: InnoDB unspecified vulnerability (CPU Oct 2024) (CVE-2024-21213)
      * mysql: InnoDB unspecified vulnerability (CPU Oct 2024) (CVE-2024-21194)
      * mysql: InnoDB unspecified vulnerability (CPU Oct 2024) (CVE-2024-21199)
      * mysql: PS unspecified vulnerability (CPU Oct 2024) (CVE-2024-21193)
      * mysql: DDL unspecified vulnerability (CPU Oct 2024) (CVE-2024-21198)
      * mysql: mysqldump unspecified vulnerability (CPU Oct 2024) (CVE-2024-21247)
      * mysql: InnoDB unspecified vulnerability (CPU Oct 2024) (CVE-2024-21239)
      * curl: curl netrc password leak (CVE-2024-11053)
      * mysql: InnoDB unspecified vulnerability (CPU Jan 2025) (CVE-2025-21497)
      * mysql: MySQL Server Options Vulnerability (CVE-2025-21520)
      * mysql: High Privilege Denial of Service Vulnerability in MySQL Server (CVE-2025-21490)
      * mysql: Information Schema unspecified vulnerability (CPU Jan 2025) (CVE-2025-21529)
      * mysql: InnoDB unspecified vulnerability (CPU Jan 2025) (CVE-2025-21531)
      * mysql: Optimizer unspecified vulnerability (CPU Jan 2025) (CVE-2025-21504)
      * mysql: Privileges unspecified vulnerability (CPU Jan 2025) (CVE-2025-21540)
      * mysql: MySQL Server InnoDB Denial of Service and Unauthorized Data Modification Vulnerability
    (CVE-2025-21555)
      * mysql: Packaging unspecified vulnerability (CPU Jan 2025) (CVE-2025-21543)
      * mysql: MySQL Server InnoDB Denial of Service and Unauthorized Data Modification Vulnerability
    (CVE-2025-21491)
      * mysql: DDL unspecified vulnerability (CPU Jan 2025) (CVE-2025-21525)
      * mysql: Optimizer unspecified vulnerability (CPU Jan 2025) (CVE-2025-21536)
      * mysql: Thread Pooling unspecified vulnerability (CPU Jan 2025) (CVE-2025-21521)
      * mysql: Optimizer unspecified vulnerability (CPU Jan 2025) (CVE-2025-21501)
      * mysql: Performance Schema unspecified vulnerability (CPU Jan 2025) (CVE-2025-21534)
      * mysql: Privileges unspecified vulnerability (CPU Jan 2025) (CVE-2025-21494)
      * mysql: Privileges unspecified vulnerability (CPU Jan 2025) (CVE-2025-21519)
      * mysql: Parser unspecified vulnerability (CPU Jan 2025) (CVE-2025-21522)
      * mysql: InnoDB unspecified vulnerability (CPU Jan 2025) (CVE-2025-21503)
      * mysql: Optimizer unspecified vulnerability (CPU Jan 2025) (CVE-2025-21518)
      * mysql: MySQL Server InnoDB Denial of Service and Unauthorized Data Modification Vulnerability
    (CVE-2025-21559)
      * mysql: Privilege Misuse in MySQL Server Security Component (CVE-2025-21546)
      * mysql: Optimizer unspecified vulnerability (CPU Jan 2025) (CVE-2025-21500)
      * mysql: InnoDB unspecified vulnerability (CPU Jan 2025) (CVE-2025-21523)
      * mysql: Components Services unspecified vulnerability (CPU Jan 2025) (CVE-2025-21505)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2025-1671.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:1671");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37371");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(125, 200, 269, 285, 404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'mysql-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-common-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-common-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-common-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-common-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-devel-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-devel-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-devel-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-devel-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-errmsg-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-errmsg-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-errmsg-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-errmsg-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-libs-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-libs-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-libs-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-libs-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-server-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-server-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-server-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-server-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-test-8.0.41-2.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-test-8.0.41-2.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-test-8.0.41-2.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'mysql-test-8.0.41-2.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mysql / mysql-common / mysql-devel / mysql-errmsg / mysql-libs / etc');
}
