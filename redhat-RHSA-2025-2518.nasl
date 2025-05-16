#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:2518. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232781);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/15");

  script_cve_id("CVE-2025-26791");
  script_xref(name:"RHSA", value:"2025:2518");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.5 Product Security and Bug Fix Update (Moderate) (RHSA-2025:2518)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has a package installed that is affected by a vulnerability as referenced
in the RHSA-2025:2518 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * automation-gateway: Mutation XSS in DOMPurify Due to Improper Template Literal Handling (CVE-2025-26791)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes included:

    Automation Platform
    * Fixed an issue that would prevent some types of resources from getting synced if there was a naming
    conflict (AAP-41241)
    * Fixed an issue where login would fail for users who were members of a team or organization that had a
    naming conflict (AAP-41240)
    * Fixed an issue in the user collection module where running with state: present would cause a stack trace
    (AAP-40887)
    * Fixed an issue preventing the controller admin password to get set for the gateway admin account during
    upgrades (AAP-40839)
    * Fixed an issue that caused updates to SAML authenticators to ignore an updated public certificate
    provided via UI or API and then fail with the message The certificate and private key do not match
    (AAP-40767)
    * Allow services to request cloud.redhat.com settings from gateway using ServiceTokenAuth (AAP-39649)
    * Fixed ServiceAuthToken destroy method to allow HTTP delete via ServiceAuth to work properly (AAP-37630)
    * automation-gateway has been updated to 2.5.20250312
    * python3.11-django-ansible-base has been updated to 2.5.20250312

    Automation controller
    * Fixed the indirect host counting name to not record the hostname, but from the query result instead
    (AAP-41033)
    * Fixed OpaClient to initialize properly after timeouts and retries (AAP-40997)
    * Added service account credentials for Analytics in controller (AAP-40769)
    * Added a helper method in the API for fetching the service account token from sso.redhat.com (AAP-39637)
    * automation-controller has been updated to 4.6.9

    Event-Driven Ansible
    * Fixed ansible-rulebook support for third party python libraries (AAP-41341)
    * Modified the behavior of the ansible-rulebook and Event-Driven Ansible to help with issues when the
    activation correctly started was considered unresponsive and scheduled for restarting (AAP-41070)
    * Added support for editing and copying of rulebook activations in the API (AAP-40254)
    * Rulebook activations' log message field is separated into timestamps and message fields (AAP-39743)
    * Fixed a bug where the activation was incorrectly restarted with the error message Missing container for
    running activation (AAP-39545)
    * Event streams now connect to PostgreSQL by using the certificates configured at the installation
    (AAP-39294)
    * User is now required to give a user defined name when copying a credential. The new credential name must
    be unique (AAP-39079)
    * Enhanced error messages related to Decision Environments (AAP-38941)
    * Decision environment urls are now validated against OCI specification to ensure successful
    authentication to the container registry when pulling the image (AAP-38822)
    * ansible-rulebook has been updated to 1.1.3
    * automation-eda-controller has been updated to 1.1.6

    Receptor:
    * Fixed an issue where receptor was creating too many inotify processes, and where the user would
    encounter a too many open files error (AAP-22605)
    * receptor has been updated to 1.5.3

    Container-based Ansible Automation Platform
    * Corrected the URL in the postinstall code for automation hub to use the gateway proxy URL (AAP-41306)
    * Deprecated the variables eda_main_url and hub_main_url in favor of the gateway proxy URL (AAP-41306)
    * Receptor mesh connections are now created between all automation controller nodes (AAP-41102)
    * Fixed receptor configuration related to the container group instances type (AAP-40431)
    * Fixed behavior that would hide the errors during EDA status validation (AAP-40021)
    * Ensure the polkit RPM package is installed in order to enable user lingering (AAP-39860)
    * containerized installer setup has been updated to 2.5-11

    RPM-based Ansible Automation Platform
    * Fixed an issue where SELinux relabeling didn't happen when fcontext rules were changed (AAP-40489)
    * Fixed an issue where the credentials for execution environments and decision environments hosted in
    automation hub were incorrectly configured (AAP-40419)
    * Fixed an issue where projects failed to sync due to incorrectly configured credentials for ansible
    collections hosted in automation hub (AAP-40418)
    * Managed CA will now correctly assign eligible groups during discovery during installation, backup and
    restore (AAP-40277)
    * Implemented argument to collect sosreport using the setup script (AAP-40085)
    * EDA Activation logging is now provided via the journald driver (AAP-39745)
    * ansible-automation-platform-installer and installer setup have been updated to 2.5-9

    Additional changes:
    * ansible-creator has been updated to 25.0.0
    * ansible-dev-environment has been updated to 25.1.0
    * ansible-dev-tools has been updated to 25.2.0
    * ansible-lint has been updated to 25.1.2
    * ansible-navigator has been updated to 25.1.0
    * automation-hub has been updated to 4.10.2
    * molecule has been updated to 25.2.0
    * python3.11-ansible-compat has been updated to 25.1.2
    * python3.11-galaxy-importer has been updated to 0.4.28
    * python3.11-galaxy-ng has been updated to 4.10.2
    * python3.11-jsonschema-path has been updated to 0.3.4
    * python3.11-podman has been updated to 5.2.0
    * python3.11-pytest-ansible has been updated to 25.1.0
    * python3.11-referencing has been updated to 0.36.2
    * python3.11-tox-ansible has been updated to 25.1.0
    * python3.11-typing-extensions has been updated to 4.9.0

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2345695");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_2518.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54804c74");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:2518");
  script_set_attribute(attribute:"solution", value:
"Update the affected automation-gateway-server package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-gateway-server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-gateway-server-2.5.20250312-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-gateway-server-2.5.20250312-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5'}
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
      severity   : SECURITY_NOTE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-gateway-server');
}
