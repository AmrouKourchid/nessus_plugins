#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:0778. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194435);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2020-7692",
    "CVE-2021-26291",
    "CVE-2022-1962",
    "CVE-2022-25857",
    "CVE-2022-29599",
    "CVE-2022-42889",
    "CVE-2023-2976",
    "CVE-2023-20861",
    "CVE-2023-20862",
    "CVE-2023-24422",
    "CVE-2023-25761",
    "CVE-2023-25762",
    "CVE-2023-26048",
    "CVE-2023-26049",
    "CVE-2023-27903",
    "CVE-2023-27904",
    "CVE-2023-37947",
    "CVE-2023-40167",
    "CVE-2023-40337",
    "CVE-2023-40338",
    "CVE-2023-40339",
    "CVE-2023-40341",
    "CVE-2024-23897",
    "CVE-2024-23898"
  );
  script_xref(name:"RHSA", value:"2024:0778");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/09");

  script_name(english:"RHEL 8 : Jenkins and Jenkins-2-plugins (RHSA-2024:0778)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Jenkins / Jenkins-2-plugins.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:0778 advisory.

    Jenkins is a continuous integration server that monitors executions of repeated jobs, such as building a
    software project or jobs run by cron.

    Security Fix(es):

    * apache-commons-text: variable interpolation RCE (CVE-2022-42889)

    * google-oauth-client: missing PKCE support in accordance with the RFC for OAuth 2.0 for Native Apps can
    lead to improper authorization (CVE-2020-7692)

    * maven: Block repositories using http by default (CVE-2021-26291)

    * snakeyaml: Denial of Service due to missing nested depth limitation for collections (CVE-2022-25857)

    * maven-shared-utils: Command injection via Commandline class (CVE-2022-29599)

    * jenkins-2-plugins/script-security: Sandbox bypass vulnerability in Script Security Plugin
    (CVE-2023-24422)

    * jenkins: Arbitrary file read vulnerability through the CLI can lead to RCE (CVE-2024-23897)

    * jenkins: cross-site WebSocket hijacking (CVE-2024-23898)

    * golang: go/parser: stack exhaustion in all Parse* functions (CVE-2022-1962)

    * guava: insecure temporary directory creation (CVE-2023-2976)

    * springframework: Spring Expression DoS Vulnerability (CVE-2023-20861)

    * spring-security: Empty SecurityContext Is Not Properly Saved Upon Logout (CVE-2023-20862)

    * jenkins-2-plugins/JUnit: Stored XSS vulnerability in JUnit Plugin (CVE-2023-25761)

    * jenkins-2-plugins/pipeline-build-step: Stored XSS vulnerability in Pipeline: Build Step Plugin
    (CVE-2023-25762)

    * jetty-server: OutOfMemoryError for large multipart without filename read via request.getParameter()
    (CVE-2023-26048)

    * jetty-server: Cookie parsing of quoted values can exfiltrate values from other cookies (CVE-2023-26049)

    * Jenkins: Open redirect vulnerability in OpenShift Login Plugin (CVE-2023-37947)

    * jetty: Improper validation of HTTP/1 content-length (CVE-2023-40167)

    * jenkins-plugins: cloudbees-folder: CSRF vulnerability in Folders Plugin (CVE-2023-40337)

    * jenkins-plugins: cloudbees-folder: Information disclosure in Folders Plugin (CVE-2023-40338)

    * jenkins-plugins: config-file-provider: Improper masking of credentials in Config File Provider Plugin
    (CVE-2023-40339)

    * jenkins-plugins: blueocean: CSRF vulnerability in Blue Ocean Plugin allows capturing credentials
    (CVE-2023-40341)

    * Jenkins: Temporary file parameter created with insecure permissions (CVE-2023-27903)

    * Jenkins: Information disclosure through error stack traces related to agents (CVE-2023-27904)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0778.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?710d36ce");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1955739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2066479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2126789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2170039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2170041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2180530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260182");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JKNS-271");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JKNS-289");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-10976");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-11158");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-11348");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-1357");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-13652");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-13901");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-14113");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-14393");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-14642");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-15648");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-1709");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-1942");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-2099");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-2184");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-2318");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-27391");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-3692");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-4819");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-4833");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-655");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-6632");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-6982");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-7016");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-7050");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-710");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-8420");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPBUGS-8497");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/OCPTOOLS-246");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:0778");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Jenkins / Jenkins-2-plugins packages based on the guidance in RHSA-2024:0778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29599");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Commons Text RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 77, 79, 88, 130, 200, 266, 352, 358, 400, 459, 552, 601, 770, 1188, 1286, 1325);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
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
      'content/dist/layered/rhel8/aarch64/ocp-tools/4.12/debug',
      'content/dist/layered/rhel8/aarch64/ocp-tools/4.12/os',
      'content/dist/layered/rhel8/aarch64/ocp-tools/4.12/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ocp-tools/4.12/debug',
      'content/dist/layered/rhel8/ppc64le/ocp-tools/4.12/os',
      'content/dist/layered/rhel8/ppc64le/ocp-tools/4.12/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ocp-tools/4.12/debug',
      'content/dist/layered/rhel8/s390x/ocp-tools/4.12/os',
      'content/dist/layered/rhel8/s390x/ocp-tools/4.12/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ocp-tools/4.12/debug',
      'content/dist/layered/rhel8/x86_64/ocp-tools/4.12/os',
      'content/dist/layered/rhel8/x86_64/ocp-tools/4.12/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2-plugins-4.12.1706515741-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-7692', 'CVE-2021-26291', 'CVE-2022-25857', 'CVE-2022-29599', 'CVE-2022-42889', 'CVE-2023-2976', 'CVE-2023-24422', 'CVE-2023-25761', 'CVE-2023-25762', 'CVE-2023-37947', 'CVE-2023-40337', 'CVE-2023-40338', 'CVE-2023-40339', 'CVE-2023-40341']},
      {'reference':'jenkins-2.426.3.1706515686-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-1962', 'CVE-2023-2976', 'CVE-2023-20861', 'CVE-2023-20862', 'CVE-2023-26048', 'CVE-2023-26049', 'CVE-2023-27903', 'CVE-2023-27904', 'CVE-2023-40167', 'CVE-2024-23897', 'CVE-2024-23898']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / jenkins-2-plugins');
}
