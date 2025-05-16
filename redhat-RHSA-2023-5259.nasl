#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5259. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181616);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-32084",
    "CVE-2022-32091",
    "CVE-2022-38791",
    "CVE-2022-47015"
  );
  script_xref(name:"RHSA", value:"2023:5259");

  script_name(english:"RHEL 8 : mariadb:10.3 (RHSA-2023:5259)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5259 advisory.

    MariaDB is a multi-user, multi-threaded SQL database server that is binary compatible with MySQL.

    The following packages have been upgraded to a later upstream version: mariadb (10.3). (BZ#2223572,
    BZ#2223574, BZ#2223962, BZ#2223965)

    Security Fix(es):

    * mariadb: segmentation fault via the component sub_select (CVE-2022-32084)

    * mariadb: server crash in JOIN_CACHE::free or in copy_fields (CVE-2022-32091)

    * mariadb: compress_write() fails to release mutex on failure (CVE-2022-38791)

    * mariadb: NULL pointer dereference in spider_db_mbase::print_warnings() (CVE-2022-47015)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * [MariaDB 10.3.32] socat: E Failed to set SNI host  (SST failure) (BZ#2223961)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5259.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3ab8e49");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2106034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2106042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2130105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223962");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5259");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32091");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(229, 476, 667);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.8'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mariadb:10.3': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/aarch64/appstream/debug',
        'content/dist/rhel8/8.10/aarch64/appstream/os',
        'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/ppc64le/appstream/debug',
        'content/dist/rhel8/8.10/ppc64le/appstream/os',
        'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/s390x/appstream/debug',
        'content/dist/rhel8/8.10/s390x/appstream/os',
        'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/x86_64/appstream/debug',
        'content/dist/rhel8/8.10/x86_64/appstream/os',
        'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/aarch64/appstream/debug',
        'content/dist/rhel8/8.6/aarch64/appstream/os',
        'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/ppc64le/appstream/debug',
        'content/dist/rhel8/8.6/ppc64le/appstream/os',
        'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/s390x/appstream/debug',
        'content/dist/rhel8/8.6/s390x/appstream/os',
        'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/appstream/debug',
        'content/dist/rhel8/8.6/x86_64/appstream/os',
        'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/aarch64/appstream/debug',
        'content/dist/rhel8/8.8/aarch64/appstream/os',
        'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/ppc64le/appstream/debug',
        'content/dist/rhel8/8.8/ppc64le/appstream/os',
        'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/s390x/appstream/debug',
        'content/dist/rhel8/8.8/s390x/appstream/os',
        'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/appstream/debug',
        'content/dist/rhel8/8.8/x86_64/appstream/os',
        'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/aarch64/appstream/debug',
        'content/dist/rhel8/8.9/aarch64/appstream/os',
        'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/ppc64le/appstream/debug',
        'content/dist/rhel8/8.9/ppc64le/appstream/os',
        'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/s390x/appstream/debug',
        'content/dist/rhel8/8.9/s390x/appstream/os',
        'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/appstream/debug',
        'content/dist/rhel8/8.9/x86_64/appstream/os',
        'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'galera-25.3.37-1.module+el8.8.0+19444+aac3c36b', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mariadb-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-backup-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-common-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-devel-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-devel-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-errmsg-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-gssapi-server-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-oqgraph-engine-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-galera-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-utils-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-test-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
      ]
    },
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.8/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.8/ppc64le/appstream/os',
        'content/e4s/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.8/x86_64/appstream/debug',
        'content/e4s/rhel8/8.8/x86_64/appstream/os',
        'content/e4s/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/aarch64/appstream/debug',
        'content/eus/rhel8/8.8/aarch64/appstream/os',
        'content/eus/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/ppc64le/appstream/debug',
        'content/eus/rhel8/8.8/ppc64le/appstream/os',
        'content/eus/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/s390x/appstream/debug',
        'content/eus/rhel8/8.8/s390x/appstream/os',
        'content/eus/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/x86_64/appstream/debug',
        'content/eus/rhel8/8.8/x86_64/appstream/os',
        'content/eus/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.8/x86_64/appstream/debug',
        'content/tus/rhel8/8.8/x86_64/appstream/os',
        'content/tus/rhel8/8.8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'galera-25.3.37-1.module+el8.8.0+19444+aac3c36b', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'Judy-1.0.5-18.module+el8+2765+cfa4f87b', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mariadb-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-backup-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-common-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-devel-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-embedded-devel-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-errmsg-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-gssapi-server-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-oqgraph-engine-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-galera-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-server-utils-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
        {'reference':'mariadb-test-10.3.39-1.module+el8.8.0+19673+72b0d35f', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Judy / galera / mariadb / mariadb-backup / mariadb-common / etc');
}
