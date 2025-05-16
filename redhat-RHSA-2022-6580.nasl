#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6580. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(169721);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2022-2553");
  script_xref(name:"RHSA", value:"2022:6580");

  script_name(english:"RHEL 9 : booth (RHSA-2022:6580)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for booth.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:6580 advisory.

    The Booth cluster ticket manager is a component to bridge high availability clusters spanning multiple
    sites, in particular, to provide decision inputs to local Pacemaker cluster resource managers. It operates
    as a distributed consensus-based service, presumably on a separate physical network. Tickets facilitated
    by a Booth formation are the units of authorization that can be bound to certain resources. This will
    ensure that the resources are run at only one (granted) site at a time.

    Security Fix(es):

    * booth: authfile directive in booth config file is completely ignored. (CVE-2022-2553)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_6580.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22e0ac5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2109251");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL booth package based on the guidance in RHSA-2022:6580.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2553");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:booth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:booth-arbitrator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:booth-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:booth-site");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:booth-test");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['9','9.0'])) audit(AUDIT_OS_NOT, 'Red Hat 9.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/aarch64/highavailability/debug',
      'content/dist/rhel9/9.1/aarch64/highavailability/os',
      'content/dist/rhel9/9.1/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.1/ppc64le/highavailability/os',
      'content/dist/rhel9/9.1/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/highavailability/debug',
      'content/dist/rhel9/9.1/s390x/highavailability/os',
      'content/dist/rhel9/9.1/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.1/s390x/resilientstorage/os',
      'content/dist/rhel9/9.1/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/highavailability/debug',
      'content/dist/rhel9/9.1/x86_64/highavailability/os',
      'content/dist/rhel9/9.1/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/highavailability/debug',
      'content/dist/rhel9/9.2/aarch64/highavailability/os',
      'content/dist/rhel9/9.2/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.2/ppc64le/highavailability/os',
      'content/dist/rhel9/9.2/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/highavailability/debug',
      'content/dist/rhel9/9.2/s390x/highavailability/os',
      'content/dist/rhel9/9.2/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.2/s390x/resilientstorage/os',
      'content/dist/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/highavailability/debug',
      'content/dist/rhel9/9.2/x86_64/highavailability/os',
      'content/dist/rhel9/9.2/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/highavailability/debug',
      'content/dist/rhel9/9.3/aarch64/highavailability/os',
      'content/dist/rhel9/9.3/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.3/ppc64le/highavailability/os',
      'content/dist/rhel9/9.3/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/highavailability/debug',
      'content/dist/rhel9/9.3/s390x/highavailability/os',
      'content/dist/rhel9/9.3/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.3/s390x/resilientstorage/os',
      'content/dist/rhel9/9.3/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/highavailability/debug',
      'content/dist/rhel9/9.3/x86_64/highavailability/os',
      'content/dist/rhel9/9.3/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/highavailability/debug',
      'content/dist/rhel9/9.4/aarch64/highavailability/os',
      'content/dist/rhel9/9.4/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.4/ppc64le/highavailability/os',
      'content/dist/rhel9/9.4/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/highavailability/debug',
      'content/dist/rhel9/9.4/s390x/highavailability/os',
      'content/dist/rhel9/9.4/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.4/s390x/resilientstorage/os',
      'content/dist/rhel9/9.4/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/highavailability/debug',
      'content/dist/rhel9/9.4/x86_64/highavailability/os',
      'content/dist/rhel9/9.4/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/highavailability/debug',
      'content/dist/rhel9/9.5/aarch64/highavailability/os',
      'content/dist/rhel9/9.5/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/highavailability/debug',
      'content/dist/rhel9/9.5/ppc64le/highavailability/os',
      'content/dist/rhel9/9.5/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/highavailability/debug',
      'content/dist/rhel9/9.5/s390x/highavailability/os',
      'content/dist/rhel9/9.5/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.5/s390x/resilientstorage/os',
      'content/dist/rhel9/9.5/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/highavailability/debug',
      'content/dist/rhel9/9.5/x86_64/highavailability/os',
      'content/dist/rhel9/9.5/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/aarch64/highavailability/debug',
      'content/dist/rhel9/9/aarch64/highavailability/os',
      'content/dist/rhel9/9/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/highavailability/debug',
      'content/dist/rhel9/9/ppc64le/highavailability/os',
      'content/dist/rhel9/9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/s390x/highavailability/debug',
      'content/dist/rhel9/9/s390x/highavailability/os',
      'content/dist/rhel9/9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9/s390x/resilientstorage/debug',
      'content/dist/rhel9/9/s390x/resilientstorage/os',
      'content/dist/rhel9/9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/x86_64/highavailability/debug',
      'content/dist/rhel9/9/x86_64/highavailability/os',
      'content/dist/rhel9/9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9/x86_64/resilientstorage/os',
      'content/dist/rhel9/9/x86_64/resilientstorage/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'booth-1.0-251.3.bfb2f92.git.el9_0.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-arbitrator-1.0-251.3.bfb2f92.git.el9_0.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-core-1.0-251.3.bfb2f92.git.el9_0.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-site-1.0-251.3.bfb2f92.git.el9_0.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-test-1.0-251.3.bfb2f92.git.el9_0.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/aarch64/highavailability/debug',
      'content/e4s/rhel9/9.0/aarch64/highavailability/os',
      'content/e4s/rhel9/9.0/aarch64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/highavailability/debug',
      'content/e4s/rhel9/9.0/ppc64le/highavailability/os',
      'content/e4s/rhel9/9.0/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/resilientstorage/debug',
      'content/e4s/rhel9/9.0/ppc64le/resilientstorage/os',
      'content/e4s/rhel9/9.0/ppc64le/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/highavailability/debug',
      'content/e4s/rhel9/9.0/s390x/highavailability/os',
      'content/e4s/rhel9/9.0/s390x/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/resilientstorage/debug',
      'content/e4s/rhel9/9.0/s390x/resilientstorage/os',
      'content/e4s/rhel9/9.0/s390x/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/highavailability/debug',
      'content/e4s/rhel9/9.0/x86_64/highavailability/os',
      'content/e4s/rhel9/9.0/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/resilientstorage/debug',
      'content/e4s/rhel9/9.0/x86_64/resilientstorage/os',
      'content/e4s/rhel9/9.0/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/highavailability/debug',
      'content/eus/rhel9/9.0/aarch64/highavailability/os',
      'content/eus/rhel9/9.0/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/highavailability/debug',
      'content/eus/rhel9/9.0/ppc64le/highavailability/os',
      'content/eus/rhel9/9.0/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/resilientstorage/debug',
      'content/eus/rhel9/9.0/ppc64le/resilientstorage/os',
      'content/eus/rhel9/9.0/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.0/s390x/highavailability/debug',
      'content/eus/rhel9/9.0/s390x/highavailability/os',
      'content/eus/rhel9/9.0/s390x/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/s390x/resilientstorage/debug',
      'content/eus/rhel9/9.0/s390x/resilientstorage/os',
      'content/eus/rhel9/9.0/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/highavailability/debug',
      'content/eus/rhel9/9.0/x86_64/highavailability/os',
      'content/eus/rhel9/9.0/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/resilientstorage/debug',
      'content/eus/rhel9/9.0/x86_64/resilientstorage/os',
      'content/eus/rhel9/9.0/x86_64/resilientstorage/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'booth-1.0-251.3.bfb2f92.git.el9_0.1', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-arbitrator-1.0-251.3.bfb2f92.git.el9_0.1', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-core-1.0-251.3.bfb2f92.git.el9_0.1', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-site-1.0-251.3.bfb2f92.git.el9_0.1', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'booth-test-1.0-251.3.bfb2f92.git.el9_0.1', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'booth / booth-arbitrator / booth-core / booth-site / booth-test');
}
