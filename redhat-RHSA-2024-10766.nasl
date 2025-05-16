#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:10766. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212045);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-52304", "CVE-2024-53259");
  script_xref(name:"RHSA", value:"2024:10766");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.5 Product Security and Bug Fix Update (Moderate) (RHSA-2024:10766)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:10766 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * automation-controller: aiohttp vulnerable to request smuggling due to incorrect parsing of chunk
    extensions (CVE-2024-52304)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes included:

    Automation controller
    * Fix job schedules running at incorrect times when rrule interval was set to HOURLY or MINUTELY
    (AAP-36572)
    * Fix bug where unrelated jobs could be marked as a dependency of other jobs (AAP-35309)
    * Include pod anti-affinity configuration on default containergroup pod spec to optimally spread workload
    (AAP-35055)
    * Updated the minor version of uWSGI to obtain updated log verbiage (AAP-33169)
    * automation-controller has been updated to 4.6.3

    Receptor
    * Fixed an issue that caused a Receptor runtime panic error (AAP-36476)
    * receptor has been updated to 1.5.1

    Container-based Ansible Automation Platform
    * With this update, you cannot change the postgresql_admin_username value when using a managed database
    node (AAP-36577)
    * Added update support for PCP monitoring role (AAP-36576)
    * With this update, ID and Image fields from a container image are used instead of Digest and ImageDigest
    to trigger a container update (AAP-36575)
    * Disabled platform gateway authentication in the proxy configuration to prevent HTTP 502 errors when the
    control plane is down (AAP-36484)
    * With this update, you can use dedicated nodes for the Redis group (AAP-36480)
    * Fixed an issue where disabling TLS on Automation Gateway would cause installation to fail (AAP-35966)
    * Fixed an issue where platform gateway uninstall would leave container systemd unit files on disk
    (AAP-35329)
    * Fixed an issue where disabling TLS on Automation Gateway proxy would cause installation to fail
    (AAP-35145)
    * With this update, you can now update the registry URL value in Event-Driven Ansible credentials
    (AAP-35085)
    * Fixed an issue where the automation hub container signing service creation failed when
    hub_collection_signing=false but hub_container_signing=true (AAP-34977)
    * Fixed an issue with the HOME environment variable for receptor containers which would cause a permission
    denied error on the containerized execution node (AAP-34945)
    * Fixed an issue where not setting up the GPG agent socket properly when multiple hub nodes are
    configured, resulted in not creating a GPG socket file in /var/tmp/pulp (AAP-34815)
    * With this update, you can now change the automation gateway port value after the initial deployment
    (AAP-34813)
    * With this update, the kernel.keys.maxkeys and kernel.keys.maxbytes settings are increased on systems
    with large memory configuration (AAP-34019)
    * Added ansible_connection=local to the inventory-growth file and clarified its usage (AAP-34016)
    * containerized installer setup has been updated to 2.5-6

    RPM-based Ansible Automation Platform
    * Receptor data directory can now be configured using 'receptor_datadir' variable (AAP-36697)
    * Disabled platform gateway authentication in the proxy configuration to allow access to UI when the
    control plane is down (AAP-36667)
    * Fixed an issue where the metrics-utility command failed to run after updating automation controller
    (AAP-36486)
    * Fix issue where the dispatcher service went into FATAL status and failed to process new jobs after a
    database outage of a few minutes (AAP-36457)
    * Fixed the owner and group permissions on the /etc/tower/uwsgi.ini file (AAP-35765)
    * With this update, you can now update the registry URL value in Event-Driven Ansible credentials
    (AAP-35162)
    * Fixed an issue where not having eda_node_type defined in the inventory file would result in backup
    failure (AAP-34730)
    * Fixed an issue where not having routable_hostname defined in the inventory file would result in a
    restore failure (AAP-34563)
    * With this update, the inventory-growth file is now included in the ansible-automation-platform-installer
    (AAP-33944)
    * ansible-automation-platform-installer and installer setup have been updated to 2.5-6

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327130");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_10766.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7fc0e06");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:10766");
  script_set_attribute(attribute:"solution", value:
"Update the affected automation-controller-venv-tower, receptor and / or receptorctl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-53259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(345, 444);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-controller-venv-tower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:receptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:receptorctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'receptor-1.5.1-2.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-53259']},
      {'reference':'receptorctl-1.5.1-2.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-53259']}
    ]
  },
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
      {'reference':'automation-controller-venv-tower-4.6.3-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-52304']}
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
      {'reference':'receptor-1.5.1-2.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-53259']},
      {'reference':'receptorctl-1.5.1-2.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-53259']}
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
      {'reference':'automation-controller-venv-tower-4.6.3-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.5', 'cves':['CVE-2024-52304']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-controller-venv-tower / receptor / receptorctl');
}
