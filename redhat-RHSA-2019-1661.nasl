#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1661. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126520);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2019-10136");
  script_xref(name:"RHSA", value:"2019:1661");

  script_name(english:"RHEL 6 : spacewalk-backend (RHSA-2019:1661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for spacewalk-backend.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2019:1661 advisory.

    Spacewalk is an Open Source systems management solution that provides system provisioning, configuration
    and patching capabilities.

    Security Fix(es):

    * spacewalk: Insecure computation of authentication signatures during user authentication (CVE-2019-10136)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_1661.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6021c36f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1708696");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL spacewalk-backend package based on the guidance in RHSA-2019:1661.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-cdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.8/debug',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.8/os',
      'content/dist/rhel/server/6/6Server/x86_64/satellite/5.8/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.8/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.8/os',
      'content/dist/rhel/system-z/6/6Server/s390x/satellite/5.8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'spacewalk-backend-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-app-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-applet-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-cdn-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-common-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-config-files-tool-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-iss-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-iss-export-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-libs-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-package-push-server-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-server-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-sql-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-sql-oracle-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-sql-postgresql-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-tools-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xml-export-libs-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'spacewalk-backend-xmlrpc-2.5.3-177.el6sat', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spacewalk-backend / spacewalk-backend-app / etc');
}
