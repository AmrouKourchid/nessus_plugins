#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:3087.
##

include('compat.inc');

if (description)
{
  script_id(176120);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id(
    "CVE-2022-21594",
    "CVE-2022-21599",
    "CVE-2022-21604",
    "CVE-2022-21608",
    "CVE-2022-21611",
    "CVE-2022-21617",
    "CVE-2022-21625",
    "CVE-2022-21632",
    "CVE-2022-21633",
    "CVE-2022-21637",
    "CVE-2022-21640",
    "CVE-2022-39400",
    "CVE-2022-39408",
    "CVE-2022-39410",
    "CVE-2023-21836",
    "CVE-2023-21863",
    "CVE-2023-21864",
    "CVE-2023-21865",
    "CVE-2023-21867",
    "CVE-2023-21868",
    "CVE-2023-21869",
    "CVE-2023-21870",
    "CVE-2023-21871",
    "CVE-2023-21873",
    "CVE-2023-21874",
    "CVE-2023-21875",
    "CVE-2023-21876",
    "CVE-2023-21877",
    "CVE-2023-21878",
    "CVE-2023-21879",
    "CVE-2023-21880",
    "CVE-2023-21881",
    "CVE-2023-21882",
    "CVE-2023-21883",
    "CVE-2023-21887",
    "CVE-2023-21912",
    "CVE-2023-21917"
  );
  script_xref(name:"ALSA", value:"2023:3087");
  script_xref(name:"IAVA", value:"2023-A-0212-S");
  script_xref(name:"IAVA", value:"2023-A-0043-S");
  script_xref(name:"IAVA", value:"2022-A-0432-S");

  script_name(english:"AlmaLinux 8 : mysql:8.0 (ALSA-2023:3087)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:3087 advisory.

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2023) (CVE-2023-21912)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21594)
    * mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2022) (CVE-2022-21599)
    * mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21604)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21608)
    * mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21611)
    * mysql: Server: Connection Handling unspecified vulnerability (CPU Oct 2022) (CVE-2022-21617)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21625)
    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2022) (CVE-2022-21632)
    * mysql: Server: Replication unspecified vulnerability (CPU Oct 2022) (CVE-2022-21633)
    * mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21637)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21640)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-39400)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-39408)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-39410)
    * mysql: Server: DML unspecified vulnerability (CPU Jan 2023) (CVE-2023-21836)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21863)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21864)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21865)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21867)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21868)
    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21869)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21870)
    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21871)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21873)
    * mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2023) (CVE-2023-21875)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21876)
    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21877)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21878)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21879)
    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21880)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21881)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21883)
    * mysql: Server: GIS unspecified vulnerability (CPU Jan 2023) (CVE-2023-21887)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2023) (CVE-2023-21917)
    * mysql: Server: Thread Pooling unspecified vulnerability (CPU Jan 2023) (CVE-2023-21874)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21882)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-3087.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21880");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21875");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var appstreams = {
    'mysql:8.0': [
      {'reference':'mecab-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.32-1.module_el8.8.0+3567+56a616e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-ipadic / mecab-ipadic-EUCJP / mysql / mysql-common / etc');
}
