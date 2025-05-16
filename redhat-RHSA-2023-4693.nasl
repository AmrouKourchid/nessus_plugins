#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4693. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194297);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-4380",
    "CVE-2023-23931",
    "CVE-2023-32681",
    "CVE-2023-36053"
  );
  script_xref(name:"IAVA", value:"2024-A-0126");
  script_xref(name:"RHSA", value:"2023:4693");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.4 Product Security and Bug Fix Update (Moderate) (RHSA-2023:4693)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:4693 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):
    * automation-eda-controller: token exposed at importing project (CVE-2023-4380)
    * python3-cryptography/python39-cryptography: memory corruption via immutable objects (CVE-2023-23931)
    * python3-django/python39-django: Potential regular expression denial of service vulnerability in
    EmailValidator/URLValidator (CVE-2023-36053)
    * python3-requests/python39-requests: Unintended leak of Proxy-Authorization header (CVE-2023-32681)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional changes for Event-Driven Ansible:
    * automation-eda-controller has been updated to 1.0.1
    * Contributor and editor roles now have permissions to access users and set the AWX token. (AAP-11573)
    * The onboarding wizard now requests controller token creation. (AAP-11907)
    * Corrected the filtering capability of the Rule Audit screens so that a search yields results with the
    starts with function. (AAP-11987)
    * Enabling or disabling rulebook activation no longer increases the restarts counter by 1. (AAP-12042)
    * Filtering by a text string now displays all applicable items in the UI, including those that are not
    visible in the list at that time. (AAP-12446)
    * Audit records are no longer missing when running activations with multiple jobs. (AAP-12522)
    * The event payload is no longer missing key attributes when a job template fails. (AAP-12529)
    * Fixed the Git token leak that occurs when importing a project fails. (AAP-12767)
    * The restart policy in Kubernetes (k8s) now restarts successful activation that is incorrectly marked as
    failed. (AAP-12862)
    * Activation statuses are now reported correctly, whether you are disabling or enabling them. (AAP-12896)
    * When run_job_template action fails now, ansible-rulebook prints an error log in the activation output
    and creates an entry in rule audit so that the user is alerted that the rule has failed. (AAP-12909)
    * When a user tries to bulk delete rulebook activations from the list, the request now completes
    successfully and consistently. (AAP-13093)
    * The Rulebook Activation link now functions correctly in the Rule Audit Detail UI. (AAP-13182)
    * Fixed a bug where ansible-rulebook prevented the execution, if the connection with the controller was
    not successful when controller was not required by the rulebook. (AAP-13209)
    * Fixed a bug where some audit rule records had the wrong rulebook link. (AAP-13844)
    * Fixed a bug where only the first 10 audit rules had the right link. (AAP-13845)
    * Previously project credentials could not be updated if there was a change to the credential used in the
    project. Now credentials can be updated in a project with a new or different credential. (AAP-13983)
    * The User Access section of the navigation panel no longer disappears after creating a decision
    environment. (AAP-14273)
    * Fixed a bug where filtering for audit rules didn't work properly on OpenShift Container Platform.
    (AAP-14512)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_4693.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?810944f6");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232324");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4693");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4380");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23931");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-32681");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(402, 532, 754, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-eda-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-eda-controller-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-eda-controller-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-requests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python39-cryptography-38.0.4-2.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-23931']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-eda-controller-1.0.1-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-4380']},
      {'reference':'automation-eda-controller-server-1.0.1-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-4380']},
      {'reference':'automation-eda-controller-ui-1.0.1-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-4380']},
      {'reference':'python39-django-3.2.20-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-36053']},
      {'reference':'python39-requests-2.31.0-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-32681']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3-cryptography-38.0.4-2.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-23931']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-eda-controller-1.0.1-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-4380']},
      {'reference':'automation-eda-controller-server-1.0.1-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-4380']},
      {'reference':'automation-eda-controller-ui-1.0.1-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-4380']},
      {'reference':'python3-django-3.2.20-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-36053']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-eda-controller / automation-eda-controller-server / etc');
}
