#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3156. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194259);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-2088");
  script_xref(name:"RHSA", value:"2023:3156");

  script_name(english:"RHEL 8 : Red Hat OpenStack Platform 16.1 (RHSA-2023:3156)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat OpenStack Platform 16.1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2023:3156 advisory.

    Security Fix(es):

    * EMBARGOED CVE-2023-2088 openstack-cinder: silently access other user's
    volumes (CVE-2023-2088)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE
    page listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_3156.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b515079c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2179587");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3156");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat OpenStack Platform 16.1 package based on the guidance in RHSA-2023:3156.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-spicehtml5proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-glance-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-os-brick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-glance-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-os-brick");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

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
      {'reference':'openstack-cinder-15.4.0-1.20230510003501.58f0e73.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-api-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-common-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-compute-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-conductor-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-console-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-migration-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-novncproxy-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-scheduler-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-serialproxy-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-spicehtml5proxy-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python3-cinder-15.4.0-1.20230510003501.58f0e73.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python3-glance-store-1.0.2-1.20220219073735.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'python3-nova-20.4.1-1.20221005193232.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python3-os-brick-2.10.5-1.20220112193420.634fb4a.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-cinder / openstack-nova / openstack-nova-api / etc');
}
