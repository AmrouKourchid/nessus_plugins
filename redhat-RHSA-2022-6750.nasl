#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6750. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165628);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2022-3100");
  script_xref(name:"RHSA", value:"2022:6750");

  script_name(english:"RHEL 7 / 8 / 9 : Red Hat OpenStack Platform (openstack-barbican) (RHSA-2022:6750)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat OpenStack Platform (openstack-barbican).");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 / 9 host has packages installed that are affected by a vulnerability as
referenced in the RHSA-2022:6750 advisory.

    Barbican is a ReST API designed for the secure storage, provisioning and
    management of secrets, including in OpenStack environments.

    Security Fix(es):

    * openstack-barbican: access policy bypass via query string injection (CVE-2022-3100)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE
    page listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_6750.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4f09c47");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2125404");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat OpenStack Platform (openstack-barbican) package based on the guidance in RHSA-2022:6750.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(305);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-barbican");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-barbican-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-barbican-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-barbican");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.1/debug',
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.1/os',
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.1/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.1/debug',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.1/os',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.1/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/openstack/16.1/debug',
      'content/dist/layered/rhel8/ppc64le/openstack/16.1/os',
      'content/dist/layered/rhel8/ppc64le/openstack/16.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.1/debug',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.1/os',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.1/debug',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.1/os',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/debug',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/os',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack/16.1/debug',
      'content/dist/layered/rhel8/x86_64/openstack/16.1/os',
      'content/dist/layered/rhel8/x86_64/openstack/16.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-barbican-9.0.1-1.20220112203416.07be198.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-api-9.0.1-1.20220112203416.07be198.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-common-9.0.1-1.20220112203416.07be198.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'python3-barbican-9.0.1-1.20220112203416.07be198.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.2/debug',
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.2/os',
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.2/debug',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.2/os',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/openstack/16.2/debug',
      'content/dist/layered/rhel8/ppc64le/openstack/16.2/os',
      'content/dist/layered/rhel8/ppc64le/openstack/16.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.2/debug',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.2/os',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.2/debug',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.2/os',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/debug',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/os',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack/16.2/debug',
      'content/dist/layered/rhel8/x86_64/openstack/16.2/os',
      'content/dist/layered/rhel8/x86_64/openstack/16.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-barbican-9.0.2-2.20220122185349.c718783.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-api-9.0.2-2.20220122185349.c718783.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-common-9.0.2-2.20220122185349.c718783.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'python3-barbican-9.0.2-2.20220122185349.c718783.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/openstack-cinderlib/17/debug',
      'content/dist/layered/rhel9/x86_64/openstack-cinderlib/17/os',
      'content/dist/layered/rhel9/x86_64/openstack-cinderlib/17/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/openstack-deployment-tools/17/debug',
      'content/dist/layered/rhel9/x86_64/openstack-deployment-tools/17/os',
      'content/dist/layered/rhel9/x86_64/openstack-deployment-tools/17/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/openstack-tools/17/debug',
      'content/dist/layered/rhel9/x86_64/openstack-tools/17/os',
      'content/dist/layered/rhel9/x86_64/openstack-tools/17/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/openstack/17/debug',
      'content/dist/layered/rhel9/x86_64/openstack/17/os',
      'content/dist/layered/rhel9/x86_64/openstack/17/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-barbican-12.0.1-0.20220614210405.486e607.el9ost', 'release':'9', 'el_string':'el9ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-api-12.0.1-0.20220614210405.486e607.el9ost', 'release':'9', 'el_string':'el9ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-common-12.0.1-0.20220614210405.486e607.el9ost', 'release':'9', 'el_string':'el9ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'python3-barbican-12.0.1-0.20220614210405.486e607.el9ost', 'release':'9', 'el_string':'el9ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/debug',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/os',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/source/SRPMS',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/debug',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/os',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/debug',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/os',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/debug',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/os',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-barbican-6.0.1-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-api-6.0.1-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'openstack-barbican-common-6.0.1-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-barbican / openstack-barbican-api / etc');
}
