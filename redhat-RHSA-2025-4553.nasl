#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:4553. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235381);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2025-26699");
  script_xref(name:"RHSA", value:"2025:4553");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.5 Product Security and Bug Fix Update (Moderate) (RHSA-2025:4553)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has a package installed that is affected by a vulnerability as referenced
in the RHSA-2025:4553 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * automation-controller: Potential denial-of-service vulnerability in django.utils.text.wrap()
    (CVE-2025-26699)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes included:

    Automation Platform
    * Refactored the authenticate() method inside the AuthenticatorPlugin class in legacy_password.py and
    legacy_sso.py to their common parent LegacyMixin. Added comments to classes and their methods for code
    clarity (AAP-44460)
    * Allow gateway to be installed with a different name for the admin user (AAP-44180)
    * Added a grpc_defaults.py file which can contain override information for the GRPC server settings
    (AAP-44176)
    * Changed anchor tag on api html view to button tag so that it doesn't violate semantic rules (AAP-43802)
    * Fixed how exceptions are handled on SSO login allowing for error messages to be properly captured
    (AAP-43369)
    * LDAP Authenticator field USER_SEARCH field now properly supports LDAP Unions (AAP-42883)
    * Logging level was changed to eliminate X-DAB-JW-TOKEN header messages when logging level is info
    (AAP-38169)
    * Job event streaming is now supported without a websocket connection (AAP-43894)
    * Implemented a throttled session refresh mechanism triggered by mouse pointer movements (AAP-43622)
    * Resolved occasional flickering in Execution Environment Select dropdown (AAP-43546)
    * Added toolbar to search Rulebook Activation History logs (AAP-43338)
    * Added an enhanced log viewer for Rulebook Activation Instances similar to the Job Output logger
    (AAP-43337)
    * Fixed an issue where the job output was slow and making it hard to read due to missing parts of the
    output (AAP-41434)
    * Added a notice for users who are waiting on a running job to start its playbook execution (AAP-41399)
    * Performance improvements were made to authentication method mappings UI (AAP-40963)
    * Fix that now allows customers to view output details for filtered job outputs (AAP-38925)
    * Added ability to edit an existing rulebook activation (AAP-37299)
    * automation-gateway has been updated to 2.5.20250507
    * automation-gateway-proxy has been updated to 2.5.10
    * python3.11-django-ansible-base has been updated to 2.5.20250507

    Automation controller
    * Fixed incorrect deprecation warning for awx.awx.schedule_rrule (AAP-43474)
    * Fixed usage of Django password validator UserAttributeSimilarityValidator (AAP-43046)
    * Fixed facts so they are no longer unintentionally deleted when the inventory is modified during a Job
    execution (AAP-39365)
    * Implemented GitHub App credential type (AAP-38589)
    * automation-controller has been updated to 4.6.12
    * receptor has been updated to 1.5.5

    Event-Driven Ansible
    * Fixed an issue where the drools rule engine used in ansible-rulebook was keeping events that do not
    match in memory for the default_events_ttl of two hours causing a memory leak (AAP-44899)
    * Fixed a bug where the activation fails with message It will attempt to restart (1/5) in 60 seconds
    according to the restart policy always but it does not restart (AAP-43969)
    * Fixed a bug special characters such as [] were not allowed in the activation name on OCP deployment
    (AAP-43742)
    * Enhanced the AAP injectors for eda-server to include common platform variables as extra_vars or
    environment variables if they are specified (AAP-43029)
    * Fixed a bug where sometimes the container was not deleted correctly or it misses the last output entries
    in VM based installations (AAP-42935)
    * Added the support for restarting the activation in the rulebook activation module in the eda collection
    (AAP-42542)
    * Allows for AAP aliases to be used to specify eda collections variables to ensure common platform env
    variables and module variables can be used in the eda collection (AAP-42280)
    * Added log tracking id to each log messages labelled as [tid: uuid-pattern] (AAP-42270)
    * Added x-request-id to each log message labelled as [rid:uuid-pattern] (AAP-42269)
    * EDA Decision Environment validation errors now display under the decision environment text box in the
    decision environment UI page (AAP-42147)
    * If a source plugin terminates we should now be able to see the stack trace with the source file name,
    the function name and line number (AAP-41774)
    * Addressed the cascading delete so that rulebook activations and event streams remain, after the user who
    created them is deleted (AAP-41769)
    * Passed Controller URL is correctly validated (AAP-41575)
    * Enables decision environment image to authenticate and pull successfully when using an image registry
    with a custom port (AAP-41281)
    * Relevant settings and versions are emitted in logs when the ansible-rulebook starts in worker mode
    (AAP-40781)
    * ansible-rulebook has been updated to 1.1.6
    * automation-eda-controller has been updated to 1.1.8
    * python3.11-drools-jpy has been updated to 0.3.10
    * python3.11-drools-jpy-jar has been updated to 1.0.7
    * python3.11-podman has been updated to 5.4.0

    Automation hub
    * automation-hub has been updated to 4.10.4
    * python3.11-galaxy-importer has been updated to 0.4.29
    * python3.11-galaxy-ng has been updated to 4.10.4

    Container-based Ansible Automation Platform
    * Updated the installer to use ansible.platform collection (AAP-44230)
    * Fixed an issue where the automation hub would fail to upload collections due to a missing worker
    temporary directory (AAP-44166)
    * Implemented a playbook to collect sos reports using the inventory file (AAP-42606)
    * Added new variable use_archive_compression with default value: true (AAP-41242)
    * Added new variables componentName_use_archive_compression for each component with the default value:
    true (AAP-41242)
    * containerized installer setup has been updated to 2.5-13

    RPM-based Ansible Automation Platform
    * Fixed issue where gateway services were not aligned after restore with the target environment
    (AAP-44231)
    * Updated the installer to use ansible.platform collection (AAP-43465)
    * Fixed an issue activating rulebooks caused by missing Authorization header (AAP-44700)
    * Added compression for archive and database artifacts used in backup/restore (AAP-42055)
    * ansible-automation-platform-installer and installer setup have been updated to 2.5-12

    Additional changes:
    * aap-metrics-utility has been updated to 0.5.0
    * ansible-runner has been updated to 2.4.1
    * python3.11-dynaconf has been updated to 3.2.10
    * python3.11-sqlparse has been updated to 0.5.3

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348993");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_4553.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce545329");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:4553");
  script_set_attribute(attribute:"solution", value:
"Update the affected automation-controller-venv-tower package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-controller-venv-tower");
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
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-controller-venv-tower-4.6.12-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-controller-venv-tower-4.6.12-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-controller-venv-tower');
}
