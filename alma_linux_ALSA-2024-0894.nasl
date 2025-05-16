#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:0894.
##

include('compat.inc');

if (description)
{
  script_id(190901);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id(
    "CVE-2022-4899",
    "CVE-2023-21911",
    "CVE-2023-21919",
    "CVE-2023-21920",
    "CVE-2023-21929",
    "CVE-2023-21933",
    "CVE-2023-21935",
    "CVE-2023-21940",
    "CVE-2023-21945",
    "CVE-2023-21946",
    "CVE-2023-21947",
    "CVE-2023-21953",
    "CVE-2023-21955",
    "CVE-2023-21962",
    "CVE-2023-21966",
    "CVE-2023-21972",
    "CVE-2023-21976",
    "CVE-2023-21977",
    "CVE-2023-21980",
    "CVE-2023-21982",
    "CVE-2023-22005",
    "CVE-2023-22007",
    "CVE-2023-22008",
    "CVE-2023-22032",
    "CVE-2023-22033",
    "CVE-2023-22038",
    "CVE-2023-22046",
    "CVE-2023-22048",
    "CVE-2023-22053",
    "CVE-2023-22054",
    "CVE-2023-22056",
    "CVE-2023-22057",
    "CVE-2023-22058",
    "CVE-2023-22059",
    "CVE-2023-22064",
    "CVE-2023-22065",
    "CVE-2023-22066",
    "CVE-2023-22068",
    "CVE-2023-22070",
    "CVE-2023-22078",
    "CVE-2023-22079",
    "CVE-2023-22084",
    "CVE-2023-22092",
    "CVE-2023-22097",
    "CVE-2023-22103",
    "CVE-2023-22104",
    "CVE-2023-22110",
    "CVE-2023-22111",
    "CVE-2023-22112",
    "CVE-2023-22113",
    "CVE-2023-22114",
    "CVE-2023-22115",
    "CVE-2024-20960",
    "CVE-2024-20961",
    "CVE-2024-20962",
    "CVE-2024-20963",
    "CVE-2024-20964",
    "CVE-2024-20965",
    "CVE-2024-20966",
    "CVE-2024-20967",
    "CVE-2024-20968",
    "CVE-2024-20969",
    "CVE-2024-20970",
    "CVE-2024-20971",
    "CVE-2024-20972",
    "CVE-2024-20973",
    "CVE-2024-20974",
    "CVE-2024-20976",
    "CVE-2024-20977",
    "CVE-2024-20978",
    "CVE-2024-20981",
    "CVE-2024-20982",
    "CVE-2024-20983",
    "CVE-2024-20984",
    "CVE-2024-20985"
  );
  script_xref(name:"ALSA", value:"2024:0894");

  script_name(english:"AlmaLinux 8 : mysql:8.0 (ALSA-2024:0894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:0894 advisory.

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2023) (CVE-2023-21911)
    * mysql: Server: DDL unspecified vulnerability (CPU Apr 2023) (CVE-2023-21919, CVE-2023-21929,
    CVE-2023-21933)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2023) (CVE-2023-21920, CVE-2023-21935,
    CVE-2023-21945, CVE-2023-21946, CVE-2023-21976, CVE-2023-21977, CVE-2023-21982)
    * mysql: Server: Components Services unspecified vulnerability (CPU Apr 2023) (CVE-2023-21940,
    CVE-2023-21947, CVE-2023-21962)
    * mysql: Server: Partition unspecified vulnerability (CPU Apr 2023) (CVE-2023-21953, CVE-2023-21955)
    * mysql: Server: JSON unspecified vulnerability (CPU Apr 2023) (CVE-2023-21966)
    * mysql: Server: DML unspecified vulnerability (CPU Apr 2023) (CVE-2023-21972)
    * mysql: Client programs unspecified vulnerability (CPU Apr 2023) (CVE-2023-21980)
    * mysql: Server: Replication unspecified vulnerability (CPU Jul 2023) (CVE-2023-22005, CVE-2023-22007,
    CVE-2023-22057)
    * mysql: InnoDB unspecified vulnerability (CPU Jul 2023) (CVE-2023-22008)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2023) (CVE-2023-22032, CVE-2023-22059,
    CVE-2023-22064, CVE-2023-22065, CVE-2023-22070, CVE-2023-22078, CVE-2023-22079, CVE-2023-22092,
    CVE-2023-22103, CVE-2023-22110, CVE-2023-22112)
    * mysql: InnoDB unspecified vulnerability (CPU Jul 2023) (CVE-2023-22033)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2023) (CVE-2023-22046, CVE-2023-22054,
    CVE-2023-22056)
    * mysql: Client programs unspecified vulnerability (CPU Jul 2023) (CVE-2023-22053)
    * mysql: Server: DDL unspecified vulnerability (CPU Jul 2023) (CVE-2023-22058)
    * mysql: InnoDB unspecified vulnerability (CPU Oct 2023) (CVE-2023-22066, CVE-2023-22068, CVE-2023-22084,
    CVE-2023-22097, CVE-2023-22104, CVE-2023-22114)
    * mysql: Server: UDF unspecified vulnerability (CPU Oct 2023) (CVE-2023-22111)
    * mysql: Server: DML unspecified vulnerability (CPU Oct 2023) (CVE-2023-22115)
    * mysql: Server: RAPID unspecified vulnerability (CPU Jan 2024) (CVE-2024-20960)
    * mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2024) (CVE-2024-20963)
    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2024) (CVE-2024-20964)
    * mysql: Server: Replication unspecified vulnerability (CPU Jan 2024) (CVE-2024-20967)
    * mysql: Server: Options unspecified vulnerability (CPU Jan 2024) (CVE-2024-20968)
    * mysql: Server: DDL unspecified vulnerability (CPU Jan 2024) (CVE-2024-20969)
    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2024) (CVE-2024-20961, CVE-2024-20962,
    CVE-2024-20965, CVE-2024-20966, CVE-2024-20970, CVE-2024-20971, CVE-2024-20972, CVE-2024-20973,
    CVE-2024-20974, CVE-2024-20976, CVE-2024-20977, CVE-2024-20978, CVE-2024-20982)
    * mysql: Server: DDL unspecified vulnerability (CPU Jan 2024) (CVE-2024-20981)
    * mysql: Server: DML unspecified vulnerability (CPU Jan 2024) (CVE-2024-20983)
    * mysql: Server : Security : Firewall unspecified vulnerability (CPU Jan 2024) (CVE-2024-20984)
    * mysql: Server: UDF unspecified vulnerability (CPU Jan 2024) (CVE-2024-20985)
    * zstd: mysql: buffer overrun in util.c (CVE-2022-4899)
    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2023) (CVE-2023-22038)
    * mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2023) (CVE-2023-22048)
    * mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2023) (CVE-2023-22113)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-0894.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mecab-devel");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'mecab-devel-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-devel-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-devel-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-devel-0.996-2.module_el8.6.0+3340+d764b636', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module_el8.6.0+3340+d764b636', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-common-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-errmsg-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-8.0.36-1.module_el8.9.0+3735+82bd6c11', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-devel / mecab-ipadic / mecab-ipadic-EUCJP / mysql / etc');
}
