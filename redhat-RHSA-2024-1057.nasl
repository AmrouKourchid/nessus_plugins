#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1057. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191748);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-40896",
    "CVE-2023-44271",
    "CVE-2023-47627",
    "CVE-2023-49081",
    "CVE-2023-49082",
    "CVE-2023-52323",
    "CVE-2024-1657",
    "CVE-2024-22195",
    "CVE-2024-24680"
  );
  script_xref(name:"IAVA", value:"2024-A-0126");
  script_xref(name:"RHSA", value:"2024:1057");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.4 Product Security and Bug Fix Update (Important) (RHSA-2024:1057)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:1057 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * automation-eda-controller / ansible-rulebook / ansible-automation-platform-installer: Insecure websocket
    used when interacting with EDA server (CVE-2024-1657)

    * python3-django/python39-django: denial-of-service in 'intcomma' template filter (CVE-2024-24680)

    * python3-jinja2/python39-jinja2: HTML attribute injection when passing user input as keys to xmlattr
    filter (CVE-2024-22195)

    * python3-aiohttp/python39-aiohttp: CRLF injection if user controls the HTTP method using aiohttp client
    (CVE-2023-49082)

    * python3-aiohttp/python39-aiohttp: HTTP request modification (CVE-2023-49081)

    * python3-aiohttp/python39-aiohttp: numerous issues in HTTP parser with header parsing (CVE-2023-47627)

    * python3-pycryptodomex/python39-pycryptodomex: side-channel leakage for OAEP decryption in PyCryptodome
    and pycryptodomex (CVE-2023-52323)

    * python3-pillow/python39-pillow: uncontrolled resource consumption when textlength in an ImageDraw
    instance operates on a long text argument (CVE-2023-44271)

    * python3-pygments/python39-pygments: ReDoS in pygments (CVE-2022-40896)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes for automation controller:
    * automation-controller has been updated to 4.5.2
    * Enabled HashiCorp Vault LDAP and Userpass authentication (AAP-19842)

    Updates and fixes for automation hub:
    * automation-hub and python3-galaxy-ng/python39-galaxy-ng have been updated to 4.9.1
    * various dependencies have been updated

    Updates and fixes for Event-Driven Ansible:
    * automation-eda-controller has been updated to 1.0.5
    * various dependencies have been updated
    * Fixed a vulnerability that allowed command line injections in user and url fields for projects
    (AAP-17778)
    * The communication between the activations and eda-server is now authenticated. Once EDA Controller is
    upgraded, all the existing running activations must be restarted with upgraded Decision Environment images
    (AAP-17619)
    * Removed 409 conflict error when enabling an activation (AAP-16305)
    * An activation status did not change to failed when an internal error occurred (AAP-16014)
    * Restarting the EDA server can cause activation states to become stale (AAP-13064)
    * RHEL 9.2 activations can not connect to the host (AAP-12929)
    * Added podman_containers_conf_logs_max_size variable to control max log size for podman installations
    with a default value of 10 MiB (AAP-12295)

    Note: The 2.4-6 installer/setup should be used to update Event-Driven Ansible to 1.0.5

    Updates and fixes for installer and setup:
    * Added podman_containers_conf_logs_max_size variable for containers.conf to control max log size for
    podman installations with a default value of 10 MiB (AAP-19775)
    * EDA debug flag of false will now correctly disable django debug mode (AAP-19577)
    * installer and setup have been updated to 2.4-6

    Additional changes:
    * ansible-builder has been updated to 3.0.1
    * ansible-runner has been updated to 2.3.5
    * ansible-dev-tools has been added

    For more details about the updates and fixes included in this release, refer to the Release Notes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1057.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bdad743");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265085");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1057");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 93, 203, 400, 434, 444, 1385);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-automation-platform-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-rulebook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-eda-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-eda-controller-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-eda-controller-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pygments");
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
      {'reference':'python39-jinja2-3.1.3-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-22195']},
      {'reference':'python39-pygments-2.17.2-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2022-40896']}
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
      {'reference':'ansible-automation-platform-installer-2.4-6.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'ansible-rulebook-1.0.5-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'automation-eda-controller-1.0.5-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'automation-eda-controller-server-1.0.5-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'automation-eda-controller-ui-1.0.5-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'python39-aiohttp-3.9.1-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-47627', 'CVE-2023-49081', 'CVE-2023-49082']},
      {'reference':'python39-django-4.2.10-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-24680']},
      {'reference':'python39-pillow-10.0.1-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-44271']},
      {'reference':'python39-pycryptodomex-3.20.0-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-52323']}
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
      {'reference':'python3-jinja2-3.1.3-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-22195']},
      {'reference':'python3-pygments-2.17.2-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2022-40896']}
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
      {'reference':'ansible-automation-platform-installer-2.4-6.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'ansible-rulebook-1.0.5-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'automation-eda-controller-1.0.5-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'automation-eda-controller-server-1.0.5-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'automation-eda-controller-ui-1.0.5-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1657']},
      {'reference':'python3-aiohttp-3.9.1-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-47627', 'CVE-2023-49081', 'CVE-2023-49082']},
      {'reference':'python3-django-4.2.10-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-24680']},
      {'reference':'python3-pillow-10.0.1-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-44271']},
      {'reference':'python3-pycryptodomex-3.20.0-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-52323']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-automation-platform-installer / ansible-rulebook / etc');
}
