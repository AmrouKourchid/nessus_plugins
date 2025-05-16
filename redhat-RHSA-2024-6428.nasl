#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:6428. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206781);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2024-5569",
    "CVE-2024-6840",
    "CVE-2024-7246",
    "CVE-2024-32879",
    "CVE-2024-33663",
    "CVE-2024-38875",
    "CVE-2024-39329",
    "CVE-2024-39330",
    "CVE-2024-39614",
    "CVE-2024-41989",
    "CVE-2024-41990",
    "CVE-2024-41991",
    "CVE-2024-42005"
  );
  script_xref(name:"RHSA", value:"2024:6428");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.4 Product Security and Bug Fix Update (Moderate) (RHSA-2024:6428)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:6428 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * automation-controller: Django: Potential SQL injection in QuerySet.values() and values_list()
    (CVE-2024-42005)
    * automation-controller: Django: Potential denial-of-service vulnerability in django.utils.html.urlize()
    and AdminURLFieldWidget (CVE-2024-41991)
    * automation-controller: Django: Potential denial-of-service vulnerability in django.utils.html.urlize()
    (CVE-2024-41990)
    * automation-controller: python-jose: algorithm confusion with OpenSSH ECDSA keys and other key formats
    (CVE-2024-33663)
    * automation-controller: python-social-auth: Improper Handling of Case Sensitivity in social-auth-app-
    django (CVE-2024-32879)
    * automation-controller: Gain access to the k8s API server via job execution with Container Group
    (CVE-2024-6840)
    * python3/python39-django: Potential SQL injection in QuerySet.values() and values_list() (CVE-2024-42005)
    * python3/python39-django: Potential denial-of-service vulnerability in django.utils.html.urlize() and
    AdminURLFieldWidget (CVE-2024-41991)
    * python3/python39-django: Potential denial-of-service vulnerability in django.utils.html.urlize()
    (CVE-2024-41990)
    * python3/python39-django: Memory exhaustion in django.utils.numberformat.floatformat() (CVE-2024-41989)
    * python3/python39-django: Potential denial-of-service in
    django.utils.translation.get_supported_language_variant() (CVE-2024-39614)
    * python3/python39-django: Potential directory-traversal in django.core.files.storage.Storage.save()
    (CVE-2024-39330)
    * python3/python39-django: Username enumeration through timing difference for users with unusable
    passwords (CVE-2024-39329)
    * python3/python39-django: Potential denial-of-service in django.utils.html.urlize() (CVE-2024-38875)
    * python3/python39-grpcio: client communicating with a HTTP/2 proxy can poison the HPACK table between the
    proxy and the backend (CVE-2024-7246)
    * python3/python39-zipp: Denial of Service (infinite loop) via crafted zip file (CVE-2024-5569)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes for automation controller:
    * Updated the receptor to not automatically release the receptor work unit when
    RECEPTOR_KEEP_WORK_ON_ERROR is set to true (AAP-27635)
    * Updated the Help link in the REST API to point to the latest API Reference documentation (AAP-27573)
    * Fixed a timeout error in the UI when trying to load the Activity Stream (AAP-26772)
    * automation-controller has been updated to 4.5.10

    Updates and fixes for automation hub:
    * API browser now correctly escapes JSON values (AAH-3272, AAP-14463)
    * python3/python39-pulpcore has been updated to 3.28.31
    * python3/python39-pulp-ansible has been updated to 0.20.8

    Additional fixes:
    * Gunicorn python package will no longer obsolete itself when checking for or applying updates (AAP-28364)
    * python3/python39-django has been updated to 4.2.15
    * python3/python39-grpcio has been updated to 1.58.3
    * python3/python39-jmespath has been updated to 0.10.0-5
    * python3/python39-zipp has been updated to 3.19.2

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2296413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302436");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_6428.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e98c6bbc");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:6428");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42005");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-7246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 89, 208, 285, 303, 400, 440, 1287, 130);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-controller-venv-tower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-grpcio");
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
      {'reference':'python39-zipp-3.19.2-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-5569']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-controller-venv-tower-4.5.10-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-6840', 'CVE-2024-32879', 'CVE-2024-33663', 'CVE-2024-41990', 'CVE-2024-41991', 'CVE-2024-42005']}
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
      {'reference':'python39-django-4.2.15-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-38875', 'CVE-2024-39329', 'CVE-2024-39330', 'CVE-2024-39614', 'CVE-2024-41989', 'CVE-2024-41990', 'CVE-2024-41991', 'CVE-2024-42005']},
      {'reference':'python39-grpcio-1.58.3-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-7246']}
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
      {'reference':'python3-zipp-3.19.2-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-5569']}
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
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-controller-venv-tower-4.5.10-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-6840', 'CVE-2024-32879', 'CVE-2024-33663', 'CVE-2024-41990', 'CVE-2024-41991', 'CVE-2024-42005']}
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
      {'reference':'python3-django-4.2.15-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-38875', 'CVE-2024-39329', 'CVE-2024-39330', 'CVE-2024-39614', 'CVE-2024-41989', 'CVE-2024-41990', 'CVE-2024-41991', 'CVE-2024-42005']},
      {'reference':'python3-grpcio-1.58.3-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-7246']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-controller-venv-tower / python3-django / python3-grpcio / etc');
}
