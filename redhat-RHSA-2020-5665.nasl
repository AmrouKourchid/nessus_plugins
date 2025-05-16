##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5665. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144550);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-2938",
    "CVE-2019-2974",
    "CVE-2020-2574",
    "CVE-2020-2752",
    "CVE-2020-2760",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-13249",
    "CVE-2020-14765",
    "CVE-2020-14776",
    "CVE-2020-14789",
    "CVE-2020-14812",
    "CVE-2020-15180",
    "CVE-2021-2022",
    "CVE-2021-2144",
    "CVE-2021-2194"
  );
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2019-A-0383-S");
  script_xref(name:"IAVA", value:"2020-A-0021-S");
  script_xref(name:"RHSA", value:"2020:5665");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"IAVA", value:"2021-A-0193-S");
  script_xref(name:"IAVA", value:"2021-A-0038-S");
  script_xref(name:"IAVA", value:"2020-A-0143-S");

  script_name(english:"RHEL 8 : mariadb:10.3 (RHSA-2020:5665)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:5665 advisory.

    MariaDB is a multi-user, multi-threaded SQL database server that is binary compatible with MySQL.

    The following packages have been upgraded to a later upstream version: mariadb (10.3.27), galera
    (25.3.31). (BZ#1899084, BZ#1899088)

    Security Fix(es):

    * mariadb: Insufficient SST method name check leading to code injection in mysql-wsrep (CVE-2020-15180)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2019) (CVE-2019-2938)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2019) (CVE-2019-2974)

    * mysql: C API unspecified vulnerability (CPU Apr 2020) (CVE-2020-2752)

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2020) (CVE-2020-2760)

    * mysql: Server: DML unspecified vulnerability (CPU Apr 2020) (CVE-2020-2780)

    * mysql: Server: Stored Procedure unspecified vulnerability (CPU Apr 2020) (CVE-2020-2812)

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2020) (CVE-2020-2814)

    * mariadb-connector-c: Improper validation of content in a OK packet received from server (CVE-2020-13249)

    * mysql: Server: FTS unspecified vulnerability (CPU Oct 2020) (CVE-2020-14765)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2020) (CVE-2020-14776)

    * mysql: Server: FTS unspecified vulnerability (CPU Oct 2020) (CVE-2020-14789)

    * mysql: Server: Locking unspecified vulnerability (CPU Oct 2020) (CVE-2020-14812)

    * mysql: C API unspecified vulnerability (CPU Jan 2020) (CVE-2020-2574)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * FTBFS: -D_GLIBCXX_ASSERTIONS (BZ#1899011)

    * Queries with entity_id IN ('1', '2', , '70000') run much slower in MariaDB 10.3 than on MariaDB 10.1
    (BZ#1899019)

    * Cleanup race with wsrep_rsync_sst_tunnel may prevent full galera cluster bootstrap (BZ#1899024)

    * There are undeclared file conflicts in several mariadb and mysql packages (BZ#1899079)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_5665.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0760c4de");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1764680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1764691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1798587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1835849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1839827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1894919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899088");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15180");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 96, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Judy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mariadb:10.3': [
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.1/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.1/ppc64le/appstream/os',
        'content/e4s/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/appstream/debug',
        'content/e4s/rhel8/8.1/x86_64/appstream/os',
        'content/e4s/rhel8/8.1/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/aarch64/appstream/debug',
        'content/eus/rhel8/8.1/aarch64/appstream/os',
        'content/eus/rhel8/8.1/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/ppc64le/appstream/debug',
        'content/eus/rhel8/8.1/ppc64le/appstream/os',
        'content/eus/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/s390x/appstream/debug',
        'content/eus/rhel8/8.1/s390x/appstream/os',
        'content/eus/rhel8/8.1/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.1/x86_64/appstream/debug',
        'content/eus/rhel8/8.1/x86_64/appstream/os',
        'content/eus/rhel8/8.1/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'galera-25.3.31-1.module+el8.1.0+8860+1543d51b', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mariadb-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-backup-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-common-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-devel-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-devel-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-errmsg-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-gssapi-server-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-oqgraph-engine-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-galera-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-utils-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-test-10.3.27-3.module+el8.1.0+9159+f0191ef0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/mariadb');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.3');
if ('10.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mariadb:' + module_ver);

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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb:10.3');

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / galera / mariadb / mariadb-backup / mariadb-common / etc');
}
