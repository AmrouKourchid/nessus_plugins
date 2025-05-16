#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:11145. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213128);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/18");

  script_cve_id("CVE-2024-11079", "CVE-2024-11483");
  script_xref(name:"RHSA", value:"2024:11145");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.5 Product Security and Bug Fix Update (Moderate) (RHSA-2024:11145)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:11145 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * ansible-core: Unsafe Tagging Bypass via hostvars Object in Ansible-Core (CVE-2024-11079)
    * automation-gateway: Improper Scope Handling in OAuth2 Tokens for AAP 2.5 (CVE-2024-11483)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE page(s)
    listed in the References section.

    Updates and fixes included:

    Automation Platform UI
    * Added support for filtering job templates, jobs, and inventories by labels (AAP-36540)
    * Fixed an issue where it was not possible to open a job template after removing the user which created
    the template (AAP-35820)
    * Fixed an issue where the inventory source update failed, and did not allow selection of the inventory
    file (AAP-35246)
    * Fixed an issue where the Login Redirect Override setting was missing and not functioning as expected
    (AAP-33295)
    * Disabled auto complete for secret credential fields (AAP-33188)
    * Fixed an issue where users were able to select a credential that required a password when defining a
    schedule (AAP-32821)
    * Fixed the navigation Team -> roles -> eda to the created team role page, where it did not work after
    adding a new team role.(AAP-31873)
    * When configuring an Ansible Remote to sync collections from other servers, a requirements file is only
    required for syncs from Galaxy, and optional otherwise. Without a requirements file, all collections get
    synced (AAP-31238)
    * Fixed an issue where the job output did not show unless you switched tabs (AAP-31125)
    * Fixed an issue where the bulk removal of selected role permissions disappeared when more than 4
    permissions were selected (AAP-28030)

    Event-Driven Ansible
    * Fixed an issue where the project sync would not fail on an empty or unstructured git repository
    (AAP-35777)
    * Fixed an issue in the collection where the activation module failed with a misleading error message if
    the rulebook, project, decision environment, or organization could not be found (AAP-35360)
    * Fixed an issue where rulebook validation import/sync fails when a rulebook has a duplicated rule name
    (AAP-35164)
    * Added validation that a host specified as part of a container registry credential conforms to container
    registry standards (AAP-34969)
    * Fixed an issue where the Event Driven Ansible API allowed a credentials type to be changed
    (AAP-34968)
    * Fixed an issue where a previously failed project could be accidentally changed to completed after a
    resync (AAP-34744)
    * Fixed an issue where no message was recorded when a project did not contain any rulebooks (AAP-34555)
    * Fixed an issue whereby multiple Red Hat Ansible Automation Platform credentials were being attached to
    activations (AAP-34025)
    * Fixed an issue where the url field of the event stream was not updated if EDA_EVENT_STREAM_BASE_URL
    setting changed (AAP-33819)
    * Extended the scope of the log_level and debug settings (AAP-33669)
    * Fixed an issue where there was an erroneous dependency on the existence of an organization named Default
    (AAP-33551)
    * A project can now be synced with the Event Driven Ansible collection modules (AAP-32264)
    * Fixed an issue where occasionally an activation is reported as running, before it is ready to receive
    events (AAP-31225)
    * Fixed an issue where Enabled options had its own scrollbar on the Rulebook Activation Details page
    (AAP-31130)
    * Added 'purge_log_records' to aap-eda-manage to clean up outdated database records (AAP-30684)
    * Fixed an issue where the status of an activation was occasionally inconsistent with the status of the
    latest instance after a restart (AAP-29755)
    * Fixed an issue where the user could not edit auto-generated injector vars while creating Event Driven
    Ansible custom credentials (AAP-29752)
    * Fixed an issue where importing a project from a non-existing branch resulted in the completed state
    instead of a Failed status (AAP-29144)
    * Fixed an issue where in some cases the file_watch source plugin in an Event Driven Ansible collection
    raised the QueueFull exception (AAP-29139)
    * In the Rulebook activation create form, selecting a project is now required before selecting a rulebook
    (AAP-28082)
    * The Create Credentials button is now visible irrespective of whether there are any existing credentials
    or not (AAP-23707)
    * automation-eda-controller has been updated to 1.1.3
    * ansible-rulebook has been updated to 1.1.2

    Container-based Ansible Automation Platform
    * Fixed an issue that allowed Automation controller nodes to override the receptor_peers variable
    (AAP-37085)
    * Fixed an issue where the containerized installer ignored receptor_type for automation controller hosts
    and always installed them as hybrid (AAP-37012)
    * Fixed an issue where Podman was not present in the task container, and the cleanup image task failed
    (AAP-37011)
    * Fixed an issue where receptor_type and receptor_protocol variables validation checks were skipped during
    the preflight role execution (AAP-36857)
    * Fixed an issue where only one Automation controller node was configured with Execution/Hop node peers
    rather than all Automation controller nodes (AAP-36851)
    * Fixed an issue when the Automation Controller services loose connection to the database then containers
    are stopped and never started back automatically (AAP-36850)
    * containerized installer setup has been updated to 2.5-7

    Additional changes:
    * Added help text to all missing fields in AAP API gateway and django-ansible-base (AAP-37068)
    * Consistently formatted sentence structure for help_text, and provided more context in the help text
    where it was vagueConsistently formatted sentence structure for help_text, and provided more context in
    the help text where it was vague (AAP-37016)
    * Fixed an issue where migration was missing (AAP-37015)
    * Fixed an issue where django-ansible-base fallback cache kept creating a tmp file even if the LOCATION
    was set to another path (AAP-36869)
    * Fixed an issue where the OIDC authenticator was not allowed to use the JSON key to extract user groups,
    or for a user to be modified via the new GROUPS_CLAIM configuration setting (AAP-36716)
    * Fixed an issue where the gateway oauth token was not encrypted at rest (AAP-36715)
    * Added more user input validation around http_ports in gateway (AAP-36714)
    * Fixed an issue where the Gateway did not properly interpret SAML attributes for mappings (AAP-36713)
    * Added setting 'trusted_header_timeout_in_ns' to timegate X_TRUSTED_PROXY_HEADER validation in djanbo-
    ansible-base libraries (AAP-36712)
    * Added dynamic preferences for usage by automation analytics (AAP-36710)
    * Added an 'enabled' flag for turning authenticator maps on or off (AAP-36709)
    * Allow non-self-signed certificate+key pairs to be used in SAML authenticator configurations (AAP-36707)
    * Make login page redirect to /api/gateway/v1 if already logged in (AAP-36638)
    * aap-metrics-utility has been updated to 0.4.1 (AAP-36393)
    * ansible-core has been updated to 2.16.14
    * automation-gateway has been updated to 2.5.20241218
    * python3.11-django-ansible-base has been updated to 2.5.20241218

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327579");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_11145.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8949240d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:11145");
  script_set_attribute(attribute:"solution", value:
"Update the affected ansible-core and / or automation-gateway-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11079");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 284);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-gateway-server");
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
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.3/debug',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.3/os',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.3/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.3/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.3/os',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.3/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.3/debug',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.3/os',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.3/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.2/debug',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.2/os',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.3/debug',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.3/os',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-core-2.16.14-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-11079']}
    ]
  },
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
      {'reference':'automation-gateway-server-2.5.20241218-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-11483']}
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
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.3/debug',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.3/os',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.3/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.3/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.3/os',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.3/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.3/debug',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.3/os',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.3/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.5/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.2/debug',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.2/os',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.2/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.3/debug',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.3/os',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-core-2.16.14-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-11079']}
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
      {'reference':'automation-gateway-server-2.5.20241218-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-11483']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-core / automation-gateway-server');
}
