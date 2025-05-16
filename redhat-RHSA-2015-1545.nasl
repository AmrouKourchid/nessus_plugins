#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1545. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119358);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2014-3566");
  script_xref(name:"RHSA", value:"2015:1545");

  script_name(english:"RHEL 6 : node.js (RHSA-2015:1545)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for node.js.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has a package installed that is affected by a vulnerability as referenced in
the RHSA-2015:1545 advisory.

    OpenShift Enterprise by Red Hat is the company's cloud computing
    Platform-as-a-Service (PaaS) solution designed for on-premise or private
    cloud deployments.

    Node.js is a software development platform for building fast and scalable
    network applications in the JavaScript programming language.

    A flaw was found in the way SSL 3.0 handled padding bytes when decrypting
    messages encrypted using block ciphers in cipher block chaining (CBC) mode.
    This flaw allows a man-in-the-middle (MITM) attacker to decrypt a selected
    byte of a cipher text in as few as 256 tries if they are able to force a
    victim application to repeatedly send the same data over newly created SSL
    3.0 connections. (CVE-2014-3566)

    All OpenShift Enterprise users are advised to upgrade to these updated
    packages, which correct this issue.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2015/rhsa-2015_1545.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba7b5f71");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:1545");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152789");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL node.js package based on the guidance in RHSA-2015:1545.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(757);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openshift-origin-node-proxy-1.22.3.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openshift-origin-node-proxy');
}
