#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:7987. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208713);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/10");

  script_cve_id(
    "CVE-2024-1135",
    "CVE-2024-24790",
    "CVE-2024-26130",
    "CVE-2024-41991"
  );
  script_xref(name:"RHSA", value:"2024:7987");

  script_name(english:"RHEL 8 : Satellite 6.15.4 Security Update (Moderate) (RHSA-2024:7987)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:7987 advisory.

    Red Hat Satellite is a system management solution that allows organizations
    to configure and maintain their systems without the necessity to provide
    public Internet access to their servers or other client systems. It
    performs provisioning and configuration management of predefined standard
    operating environments.
    Security Fix(es):

    * python-gunicorn: HTTP Request Smuggling due to improper validation of Transfer-Encoding headers
    (CVE-2024-1135)
    * golang: net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses (CVE-2024-24790)
    * python-cryptography: NULL pointer dereference with pkcs12.serialize_key_and_certificates when called
    with a non-matching certificate and private key and an hmac_hash override (CVE-2024-26130)
    * python-django: Potential denial-of-service vulnerability in django.utils.html.urlize() and
    AdminURLFieldWidget (CVE-2024-41991)

    Users of Red Hat Satellite are advised to upgrade to these updated
    packages, which fix these bugs.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.15/html/updating_red_hat_satellite/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0670c292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302435");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25848");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27294");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27295");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27296");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27299");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27950");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_7987.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?244431e9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:7987");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(115, 400, 444, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yggdrasil-worker-forwarder");
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
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.15/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.15/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.15/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.15/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.15/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.15/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3.11-cryptography-42.0.8-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-26130']},
      {'reference':'python3.11-django-4.2.15-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-41991']},
      {'reference':'python3.11-gunicorn-22.0.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-1135']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/satellite/6.15/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.15/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.15/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-foreman_theme_satellite-13.3.0-0.1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-26130']},
      {'reference':'yggdrasil-worker-forwarder-0.0.3-2.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-24790']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3.11-cryptography / python3.11-django / python3.11-gunicorn / etc');
}
