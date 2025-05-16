#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:3637. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234265);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/13");

  script_cve_id("CVE-2025-2877");
  script_xref(name:"RHSA", value:"2025:3637");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.5 Product Security and Bug Fix Update (Important) (RHSA-2025:3637)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has a package installed that is affected by a vulnerability as referenced
in the RHSA-2025:3637 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * ansible-rulebook: exposure inventory passwords in plain text when starting a rulebook activation with
    verbosity set to debug in EDA (CVE-2025-2877)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes included:

    Automation Platform
    * Authentication configuration for AzureAD/EntraId now have configurable name for groups claim to allow
    customization of the claim name (AAP-42890)
    * Fixed an issue where there was non-viable information disclosure (AAP-39977)
    * automation-gateway has been updated to 2.5.20250409
    * python3.11-django-ansible-base has been updated to 2.5.20250409

    Event-Driven Ansible
    * Fixed a bug where activations attached with some event stream could not be created in deployments
    configured with postgresql with mTLS (AAP-42268)
    * ansible-rulebook has been updated to 1.1.4
    * automation-eda-controller has been updated to 1.1.7

    Container-based Ansible Automation Platform
    * Implemented variables for applying extra_settings for controller, eda, gateway and hub during the
    installation (AAP-42932)
    * Ensure remote user is part of the systemd-journal group to be able to access container logs (AAP-42755)
    * Implemented exclusions to the restore rules (AAP-42781)
    * Implemented validation and cleanup for service nodes on a restore to a new cluster (AAP-42781)
    * containerized installer setup has been updated to 2.5-12

    RPM-based Ansible Automation Platform
    * When upgrading from an earlier 2.5, you must use the latest installer 2.5-11. If you use an earlier
    installer, the installation might fail.
    * Fixed issue preventing EDA worker nodes re-authenticating tokens (AAP-42981)
    * Fixed an issue where bundle installer has failed to updatie automation-controller and aap-metrics-
    utility in the same run (AAP-42632)
    * Fixed an issue where envoy failed to run on certain RHEL9 machines (AAP-39211)
    * Fixed an issue where Platform UI wasn't loading when gateway was on FIPS enabled RHEL 9 (AAP-39146)
    * ansible-automation-platform-installer and installer setup have been updated to 2.5-11

    Additional changes:
    * automation-controller has been updated to 4.6.11
    * automation-gateway-proxy has been updated to 2.5.9
    * automation-gateway-proxy-openssl30 2.6.6 has been added
    * automation-gateway-proxy-openssl32 2.6.6 has been added

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355540");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_3637.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce5eabff");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:3637");
  script_set_attribute(attribute:"solution", value:
"Update the affected ansible-rulebook package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1295);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-rulebook");
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
      {'reference':'ansible-rulebook-1.1.4-2.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5'}
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
      {'reference':'ansible-rulebook-1.1.4-2.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-rulebook');
}
