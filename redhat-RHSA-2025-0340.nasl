#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:0340. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214232);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_cve_id(
    "CVE-2024-11407",
    "CVE-2024-52304",
    "CVE-2024-53907",
    "CVE-2024-53908",
    "CVE-2024-55565"
  );
  script_xref(name:"RHSA", value:"2025:0340");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.5 Product Security and Bug Fix Update (Important) (RHSA-2025:0340)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:0340 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):
    * automation-controller: Potential SQL injection in HasKey(lhs, rhs) on Oracle (CVE-2024-53908)
    * automation-controller: Potential denial-of-service in django.utils.html.strip_tags() (CVE-2024-53907)
    * automation-controller: Denial of Service through Data corruption in gRPC-C++ (CVE-2024-11407)
    * automation-gateway: nanoid mishandles non-integer values (CVE-2024-55565)
    * python3.11-aiohttp: aiohttp vulnerable to request smuggling due to incorrect parsing of chunk extensions
    (CVE-2024-52304)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes included:

    Platform
    * Fixed 'not found' error that occurred occasionally when navigating form wizards (AAP-37495)
    * Fixed an issue where ID_KEY attribute was improperly used to determine the username field in social auth
    pipelines (AAP-38300)
    * Fixed an issue where the X-DAB-JW-TOKEN header message would flood logs (AAP-38169)
    * Fixed an issue where authenticator could create a userid and return a non-viable authenticator_uid
    (AAP-38021)
    * Enhanced the status API, /api/gateway/v1/status/, from the services property within the JSON to an array
    (AAP-37903)
    * Fixes an issue where a private key was displayed in plain text when downloading the OpenAPI schema file.
    NOTE: This was not the private key used by gateway, just a random default key (AAP-37843)

    Automation controller
    * Added 'job_lifecycle' as a choice in loggers to send externally and added 'organization_id' field to
    logs related to a job (AAP-37537)
    * Fixed date comparison mismatch for traceback from 'host_metric_summary_monthly' task (AAP-37487)
    * Fixed scheduled jobs with count set to a non-zero value to no longer run unexpectedly (AAP-37290)
    * Fixed the POST operation to '/api/controller/login/' via gateway to no longer result in a fatal error
    (AAP-37235)
    * Fixed the behavior of the project's 'requirements.yml' to no longer revert to a prior state in a cluster
    (AAP-37228)
    * Fixed occasional error while creating event partition table before starting a job, when lots of jobs are
    launched quickly (AAP-37227)
    * Fixed the named URL to no longer return a 404 error code while launching a job template (AAP-37025)
    * Updated receptor to clean up temporary receptor files after a job completes on nodes (AAP-36904)
    * Fixed the POST operation to '/api/controller/login/' via gateway to no longer result in a fatal error
    (AAP-33911)
    * automation-controller has been updated to 4.6.6

    Container-based Ansible Automation Platform
    * Fixed an issue where the provided inventory file sample for growth inventories could cause the
    installation to stall on low resource systems (AAP-38372)
    * Fixed an issue where the throttle capacity of controller in growth topology installation would allow for
    performance degradation (AAP-38207)
    * Fixed an issue where the receptor TLS certificate content was not validated during the preflight role
    execution ensuring that the x509 Subject Alt Name (SAN) field contains the required ISO Object Identifier
    (OID) (AAP-37880)
    * TLS certificate and key files are now validated during the preflight role execution (AAP-37845)
    * Fixed an issue where the Postgresql SSL mode variables were not validated during the preflight role
    execution (AAP-37352)
    * containerized installer setup has been updated to 2.5-8

    RPM-based Ansible Automation Platform
    * Fixed an issue where adding a new automation hub host to upgraded environment has caused the
    installation to fail (AAP-38204)
    * Fixed an issue where the link to the documents in the installer README.md was broken (AAP-37627)
    * Updated nginx configuration to properly return API status for Event-Driven Ansible event stream service
    (AAP-32816)
    * ansible-automation-platform-installer and installer setup have been updated to 2.5-7

    Additional changes:
    * Installing ansible-core no longer installs python3-jmespath on RHEL 8 (AAP-18251)
    * ansible-core has been updated to 2.16.14-2
    * automation-gateway has been updated to 2.5.20250115
    * python3.11-aiohttp has been updated to 3.10.11 along with its dependencies
    * python3.11-django-ansible-base has been updated to 2.5.20250115
    * python3.11-galaxy-importer has been updated to 0.4.27
    * python3.11-pulpcore has been updated to 3.49.29

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331063");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_0340.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30b348d8");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:0340");
  script_set_attribute(attribute:"solution", value:
"Update the affected automation-controller-venv-tower, automation-gateway-server and / or python3.11-aiohttp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/S:N/AU:N/R:A/RE:L/U:Green");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53908");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-11407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89, 444, 682, 835, 1169);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-controller-venv-tower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-gateway-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiohttp");
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
      {'reference':'automation-controller-venv-tower-4.6.6-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-11407', 'CVE-2024-53907', 'CVE-2024-53908']}
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
      {'reference':'automation-gateway-server-2.5.20250115-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-55565']},
      {'reference':'python3.11-aiohttp-3.10.11-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-52304']}
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
      {'reference':'automation-controller-venv-tower-4.6.6-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-11407', 'CVE-2024-53907', 'CVE-2024-53908']}
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
      {'reference':'automation-gateway-server-2.5.20250115-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-55565']},
      {'reference':'python3.11-aiohttp-3.10.11-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-52304']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-controller-venv-tower / automation-gateway-server / etc');
}
