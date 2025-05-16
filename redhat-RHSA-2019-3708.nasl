#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:3708. The text
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130575);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-2510",
    "CVE-2019-2537",
    "CVE-2019-2614",
    "CVE-2019-2627",
    "CVE-2019-2628",
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2758",
    "CVE-2019-2805",
    "CVE-2020-2922",
    "CVE-2021-2007"
  );
  script_xref(name:"RHSA", value:"2019:3708");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 8 : mariadb:10.3 (RHSA-2019:3708)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for mariadb:10.3.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:3708 advisory.

    MariaDB is a multi-user, multi-threaded SQL database server that is binary compatible with MySQL.

    The following packages have been upgraded to a later upstream version: mariadb (10.3.17), galera
    (25.3.26). (BZ#1701687, BZ#1711265, BZ#1741358)

    Security Fix(es):

    * mysql: InnoDB unspecified vulnerability (CPU Jan 2019) (CVE-2019-2510)

    * mysql: Server: DDL unspecified vulnerability (CPU Jan 2019) (CVE-2019-2537)

    * mysql: Server: Replication unspecified vulnerability (CPU Apr 2019) (CVE-2019-2614)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2019) (CVE-2019-2627)

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2019) (CVE-2019-2628)

    * mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2019) (CVE-2019-2737)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2019) (CVE-2019-2739)

    * mysql: Server: XML unspecified vulnerability (CPU Jul 2019) (CVE-2019-2740)

    * mysql: InnoDB unspecified vulnerability (CPU Jul 2019) (CVE-2019-2758)

    * mysql: Server: Parser unspecified vulnerability (CPU Jul 2019) (CVE-2019-2805)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.1 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.1_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8d3b26b");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_3708.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beb8c246");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3708");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1657220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1659920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1666751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1666763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1686818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1687879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1693245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732025");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL mariadb:10.3 package based on the guidance in RHSA-2019:3708.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Judy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Judy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:asio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:asio-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mariadb-devel:10.3': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'asio-devel-1.10.8-7.module+el8+2765+cfa4f87b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'galera-25.3.26-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'Judy-devel-1.0.5-18.module+el8+2765+cfa4f87b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mariadb-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-backup-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-common-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-errmsg-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-gssapi-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-oqgraph-engine-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-galera-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-utils-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-test-10.3.17-1.module+el8.1.0+3974+90eded84', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
      ]
    }
  ],
  'mariadb:10.3': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/x86_64/appstream/debug',
        'content/dist/rhel8/8.10/x86_64/appstream/os',
        'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/appstream/debug',
        'content/dist/rhel8/8.6/x86_64/appstream/os',
        'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/appstream/debug',
        'content/dist/rhel8/8.8/x86_64/appstream/os',
        'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/appstream/debug',
        'content/dist/rhel8/8.9/x86_64/appstream/os',
        'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'galera-25.3.26-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mariadb-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-backup-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-common-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-devel-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-errmsg-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-gssapi-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-oqgraph-engine-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-galera-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-utils-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-test-10.3.17-1.module+el8.1.0+3974+90eded84', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mariadb-devel:10.3 / mariadb:10.3');

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / Judy-devel / asio-devel / galera / mariadb / mariadb-backup / etc');
}
