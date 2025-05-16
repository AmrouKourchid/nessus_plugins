#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0017. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189418);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id(
    "CVE-2022-2048",
    "CVE-2022-29047",
    "CVE-2022-30945",
    "CVE-2022-30946",
    "CVE-2022-30948",
    "CVE-2022-30952",
    "CVE-2022-30953",
    "CVE-2022-30954",
    "CVE-2022-34174",
    "CVE-2022-34176",
    "CVE-2022-34177",
    "CVE-2022-36881",
    "CVE-2022-36882",
    "CVE-2022-36883",
    "CVE-2022-36884",
    "CVE-2022-36885"
  );
  script_xref(name:"RHSA", value:"2023:0017");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.8.56 (RHSA-2023:0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.8.56.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2023:0017 advisory.

  - In Eclipse Jetty HTTP/2 server implementation, when encountering an invalid HTTP/2 request, the error
    handling has a bug that can wind up not properly cleaning up the active connections and associated
    resources. This can lead to a Denial of Service scenario where there are no enough resources left to
    process good requests. (CVE-2022-2048)

  - Jenkins Pipeline: Shared Groovy Libraries Plugin 564.ve62a_4eb_b_e039 and earlier, except 2.21.3, allows
    attackers able to submit pull requests (or equivalent), but not able to commit directly to the configured
    SCM, to effectively change the Pipeline behavior by changing the definition of a dynamically retrieved
    library in their pull request, even if the Pipeline is configured to not trust them. (CVE-2022-29047)

  - Jenkins Pipeline: Groovy Plugin 2689.v434009a_31b_f1 and earlier allows loading any Groovy source files on
    the classpath of Jenkins and Jenkins plugins in sandboxed pipelines. (CVE-2022-30945)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Script Security Plugin 1158.v7c1b_73a_69a_08
    and earlier allows attackers to have Jenkins send an HTTP request to an attacker-specified webserver.
    (CVE-2022-30946)

  - Jenkins Mercurial Plugin 2.16 and earlier allows attackers able to configure pipelines to check out some
    SCM repositories stored on the Jenkins controller's file system using local paths as SCM URLs, obtaining
    limited information about other projects' SCM contents. (CVE-2022-30948)

  - Jenkins Pipeline SCM API for Blue Ocean Plugin 1.25.3 and earlier allows attackers with Job/Configure
    permission to access credentials with attacker-specified IDs stored in the private per-user credentials
    stores of any attacker-specified user in Jenkins. (CVE-2022-30952)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Blue Ocean Plugin 1.25.3 and earlier allows
    attackers to connect to an attacker-specified HTTP server. (CVE-2022-30953)

  - Jenkins Blue Ocean Plugin 1.25.3 and earlier does not perform a permission check in several HTTP
    endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified HTTP
    server. (CVE-2022-30954)

  - In Jenkins 2.355 and earlier, LTS 2.332.3 and earlier, an observable timing discrepancy on the login form
    allows distinguishing between login attempts with an invalid username, and login attempts with a valid
    username and wrong password, when using the Jenkins user database security realm. (CVE-2022-34174)

  - Jenkins JUnit Plugin 1119.va_a_5e9068da_d7 and earlier does not escape descriptions of test results,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Run/Update
    permission. (CVE-2022-34176)

  - Jenkins Pipeline: Input Step Plugin 448.v37cea_9a_10a_70 and earlier archives files uploaded for `file`
    parameters for Pipeline `input` steps on the controller as part of build metadata, using the parameter
    name without sanitization as a relative path inside a build-related directory, allowing attackers able to
    configure Pipelines to create or replace arbitrary files on the Jenkins controller file system with
    attacker-specified content. (CVE-2022-34177)

  - jenkins-plugin: Man-in-the-Middle (MitM) in org.jenkins-ci.plugins:git-client (CVE-2022-36881)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Git Plugin 4.11.3 and earlier allows
    attackers to trigger builds of jobs configured to use an attacker-specified Git repository and to cause
    them to check out an attacker-specified commit. (CVE-2022-36882)

  - A missing permission check in Jenkins Git Plugin 4.11.3 and earlier allows unauthenticated attackers to
    trigger builds of jobs configured to use an attacker-specified Git repository and to cause them to check
    out an attacker-specified commit. (CVE-2022-36883)

  - The webhook endpoint in Jenkins Git Plugin 4.11.3 and earlier provide unauthenticated attackers
    information about the existence of jobs configured to use an attacker-specified Git repository.
    (CVE-2022-36884)

  - Jenkins GitHub Plugin 1.34.4 and earlier uses a non-constant time comparison function when checking
    whether the provided and computed webhook signatures are equal, allowing attackers to use statistical
    methods to obtain a valid webhook signature. (CVE-2022-36885)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30945");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30946");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30948");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30952");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30953");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30954");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-34174");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-34176");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-34177");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36881");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36882");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36883");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36884");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2114755");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.8.56 packages based on the guidance in RHSA-2023:0017.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30945");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-36882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79, 200, 203, 208, 288, 322, 352, 410, 435, 552, 668, 693, 862);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat CoreOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.8')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.8', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'jenkins-2-plugins-4.8.1672842762-1.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'jenkins-2.361.1.1672840472-1.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'RHCOS' + package_array['release'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (reference &&
      _release &&
      (!exists_check || rpm_exists(release:_release, rpm:exists_check)) &&
      rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / jenkins-2-plugins');
}
