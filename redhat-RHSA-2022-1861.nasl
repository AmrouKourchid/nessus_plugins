##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1861. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161018);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id("CVE-2020-13956");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"RHSA", value:"2022:1861");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : maven:3.5 (RHSA-2022:1861)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for maven:3.5.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:1861 advisory.

    Maven is a software project management and comprehension tool. Based on the concept of a project object
    model (POM), Maven can manage a project's build, reporting and documentation from a central piece of
    information.

    Security Fix(es):

    * apache-httpclient: incorrect handling of malformed authority component in request URIs (CVE-2020-13956)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.6 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_1861.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c76ce3a");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.6_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9341665d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886587");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL maven:3.5 package based on the guidance in RHSA-2022:1861.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:geronimo-annotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-el-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hawtjni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hawtjni-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-interceptors-1.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver-connector-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver-transport-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-shared-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon-http-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon-provider-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-cipher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-classworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-containers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-containers-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-interpolation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-sec-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sisu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sisu-inject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sisu-plexus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var appstreams = {
  'maven:3.5': [
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
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/debug',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/os',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/debug',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/os',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/debug',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/os',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/debug',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/os',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-17.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-4.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.11-3.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-3.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.7-3.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-logging-1.2-13.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-28.20100611svn86.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'cdi-api-1.2-8.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-23.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'glassfish-el-api-3.0.1-0.7.b08.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.1-11.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava20-20.0-8.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'hawtjni-runtime-1.16-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.5-5.module+el8.6.0+13298+7b5243c0', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.10-3.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.17.1-1.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-native-1.7-7.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jboss-interceptors-1.2-api-1.0.0-8.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.25-4.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.11.3-3.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.5.4-5.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.5.4-5.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-api-1.1.1-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-connector-basic-1.1.1-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-impl-1.1.1-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-spi-1.1.1-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-transport-wagon-1.1.1-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-util-1.1.1-2.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-shared-utils-3.2.1-0.1.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-file-3.1.0-1.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-http-3.1.0-1.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-http-shared-3.1.0-1.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-provider-api-3.1.0-1.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-14.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.5.2-9.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-1.7.1-8.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.22-9.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-26.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.1.0-3.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-inject-0.3.3-6.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'sisu-plexus-0.3.3-6.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'slf4j-1.7.25-4.module+el8+2452+b359bfcd', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/maven');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.5');
if ('3.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module maven:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aopalliance / apache-commons-cli / apache-commons-codec / etc');
}
