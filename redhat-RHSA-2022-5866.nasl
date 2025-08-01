##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5866. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163709);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-28131",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148"
  );
  script_xref(name:"RHSA", value:"2022:5866");
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"RHEL 7 : go-toolset-1.17 and go-toolset-1.17-golang (RHSA-2022:5866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for go-toolset-1.17 / go-toolset-1.17-golang.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5866 advisory.

    Go Toolset provides the Go programming language tools and libraries. Go is
    alternatively known as golang.

    Security Fix(es):

    * golang: compress/gzip: stack exhaustion in Reader.Read (CVE-2022-30631)

    * golang: net/http: improper sanitization of Transfer-Encoding header (CVE-2022-1705)

    * golang: go/parser: stack exhaustion in all Parse* functions (CVE-2022-1962)

    * golang: encoding/xml: stack exhaustion in Decoder.Skip (CVE-2022-28131)

    * golang: io/fs: stack exhaustion in Glob (CVE-2022-30630)

    * golang: path/filepath: stack exhaustion in Glob (CVE-2022-30632)

    * golang: encoding/xml: stack exhaustion in Unmarshal (CVE-2022-30633)

    * golang: encoding/gob: stack exhaustion in Decoder.Decode (CVE-2022-30635)

    * golang: net/http/httputil: NewSingleHostReverseProxy - omit X-Forwarded-For not working (CVE-2022-32148)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Clean up dist-git patches (BZ#2109172)

    * Update Go to version 1.17.12 (BZ#2109184)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_5866.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc941843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107392");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL go-toolset-1.17 / go-toolset-1.17-golang packages based on the guidance in RHSA-2022:5866.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32148");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 331, 444, 1325);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-golang-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:go-toolset-1.17-scldevel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/power-le/7/7Server/ppc64le/devtools/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/devtools/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/devtools/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/devtools/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/devtools/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/devtools/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/devtools/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/devtools/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/devtools/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'go-toolset-1.17-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-build-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-build-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-build-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-golang-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-bin-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-bin-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-bin-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-docs-1.17.12-1.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-misc-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-misc-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-misc-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-race-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-src-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-src-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-src-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-tests-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-tests-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-golang-tests-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1705', 'CVE-2022-1962', 'CVE-2022-28131', 'CVE-2022-30629', 'CVE-2022-30630', 'CVE-2022-30631', 'CVE-2022-30632', 'CVE-2022-30633', 'CVE-2022-30635', 'CVE-2022-32148']},
      {'reference':'go-toolset-1.17-runtime-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-runtime-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-runtime-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-scldevel-1.17.12-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-scldevel-1.17.12-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']},
      {'reference':'go-toolset-1.17-scldevel-1.17.12-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-30629']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go-toolset-1.17 / go-toolset-1.17-build / go-toolset-1.17-golang / etc');
}
