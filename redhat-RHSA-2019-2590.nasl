#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2590. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128449);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2019-11772",
    "CVE-2019-11775",
    "CVE-2019-2762",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-7317"
  );
  script_xref(name:"RHSA", value:"2019:2590");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : java-1.8.0-ibm (RHSA-2019:2590)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-1.8.0-ibm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:2590 advisory.

    IBM Java SE version 8 includes the IBM Java Runtime Environment and the IBM Java Software Development Kit.

    This update upgrades IBM Java SE 8 to version 8 SR5-FP40.

    Security Fix(es):

    * IBM JDK: Out-of-bounds access in the String.getBytes method (CVE-2019-11772)

    * IBM JDK: Failure to privatize a value pulled out of the loop by versioning (CVE-2019-11775)

    * OpenJDK: Insufficient checks of suppressed exceptions in deserialization (Utilities, 8212328)
    (CVE-2019-2762)

    * OpenJDK: Unbounded memory allocation during deserialization in Collections (Utilities, 8213432)
    (CVE-2019-2769)

    * OpenJDK: Missing URL format validation (Networking, 8221518) (CVE-2019-2816)

    * OpenJDK: Insufficient restriction of privileges in AccessController (Security, 8216381) (CVE-2019-2786)

    * libpng: use-after-free in png_image_free in png.c (CVE-2019-7317)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_2590.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e161d83b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2590");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1672409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1730056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1730099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1730255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1730415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1738547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1738549");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-1.8.0-ibm package based on the guidance in RHSA-2019:2590.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11772");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 20, 400, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-webstart");
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

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/ppc64le/supplementary/debug',
      'content/dist/rhel8/8.10/ppc64le/supplementary/os',
      'content/dist/rhel8/8.10/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/supplementary/debug',
      'content/dist/rhel8/8.10/s390x/supplementary/os',
      'content/dist/rhel8/8.10/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/supplementary/debug',
      'content/dist/rhel8/8.10/x86_64/supplementary/os',
      'content/dist/rhel8/8.10/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/supplementary/debug',
      'content/dist/rhel8/8.6/ppc64le/supplementary/os',
      'content/dist/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/supplementary/debug',
      'content/dist/rhel8/8.6/s390x/supplementary/os',
      'content/dist/rhel8/8.6/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/supplementary/debug',
      'content/dist/rhel8/8.6/x86_64/supplementary/os',
      'content/dist/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8.8/ppc64le/supplementary/os',
      'content/dist/rhel8/8.8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/supplementary/debug',
      'content/dist/rhel8/8.8/s390x/supplementary/os',
      'content/dist/rhel8/8.8/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/supplementary/debug',
      'content/dist/rhel8/8.8/x86_64/supplementary/os',
      'content/dist/rhel8/8.8/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/supplementary/debug',
      'content/dist/rhel8/8.9/ppc64le/supplementary/os',
      'content/dist/rhel8/8.9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/supplementary/debug',
      'content/dist/rhel8/8.9/s390x/supplementary/os',
      'content/dist/rhel8/8.9/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/supplementary/debug',
      'content/dist/rhel8/8.9/x86_64/supplementary/os',
      'content/dist/rhel8/8.9/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/s390x/supplementary/debug',
      'content/dist/rhel8/8/s390x/supplementary/os',
      'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-1.8.0-ibm-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-1.8.0.5.40-3.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-demo-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-demo-1.8.0.5.40-3.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-demo-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-devel-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-devel-1.8.0.5.40-3.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-devel-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-headless-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-headless-1.8.0.5.40-3.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-headless-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-jdbc-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-jdbc-1.8.0.5.40-3.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-jdbc-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-plugin-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-plugin-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-src-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-src-1.8.0.5.40-3.el8_0', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-src-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-webstart-1.8.0.5.40-3.el8_0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-1.8.0-ibm-webstart-1.8.0.5.40-3.el8_0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-ibm / java-1.8.0-ibm-demo / java-1.8.0-ibm-devel / etc');
}
