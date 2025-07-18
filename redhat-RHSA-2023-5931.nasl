#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5931. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194378);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-2068",
    "CVE-2022-3874",
    "CVE-2022-24439",
    "CVE-2022-46648",
    "CVE-2022-47318",
    "CVE-2023-0462",
    "CVE-2023-3817",
    "CVE-2023-31047",
    "CVE-2023-36053",
    "CVE-2023-39325",
    "CVE-2023-40267",
    "CVE-2023-44487"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"RHSA", value:"2023:5931");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"RHEL 8 : Satellite 6.13.5 Async Security Update (Important) (RHSA-2023:5931)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5931 advisory.

    Red Hat Satellite is a system management solution that allows organizations to configure and maintain
    their systems without the necessity to provide public Internet access to their servers or other client
    systems. It performs provisioning and configuration management of predefined standard operating
    environments.

    Security fix(es):

    * Yggdrasil-worker-forwarder (gRPC): Rapid Reset Attack through HTTP/2 enabled web service which leads to
    DDoS attack (CVE-2023-44487 & CVE-2023-39325)

    A Red Hat Security Bulletin which addresses further details about this flaw is available in the References
    section.

    * Foreman: OS command injection via ct_command and fcct_command (CVE-2022-3874)

    * Foreman: Arbitrary code execution through yaml global parameters (CVE-2023-0462)

    * GitPython: Remote code execution and improper input validation vulnerability (CVE-2022-24439 &
    CVE-2023-40267)

    * Ruby-git & tfm-rubygem-git: Code injection vulnerability (CVE-2022-47318 & CVE-2022-46648)

    * Python-django: Multiple flaws (CVE-2023-31047 & CVE-2023-36053)

    * Puppet-agent (openssl): Multiple flaws (CVE-2022-1292 CVE-2022-2068)

    This update fixes the following bugs:

    2238346 - Red Hat supported provisioning templates are not recognized by RH icon on the row for a given
    template
    2238348 - when creating a backup on rhel7 and restoring on rhel8, the restore process will fail with
    permission issues
    2238350 - Virtual machine goes in re-provisioning mode while registration host using Global registration
    template.
    2238359 - Capsule redundantly synces *-Export-Library repos
    2238361 - Can't update the redhat_repository_url without changing the cdn_configuration to custom_cdn
    2238363 - katello-certs-check does not cause the installer to halt execution on failure
    2238367 - Satellite Web UI >> Hosts >> All Hosts page loading slow even after power isn't selected from
    the new option Manage columns.
    2238369 - Content-export incremental with syncable format based does not include productid file into
    repodata directory
    2238371 - SELinux is preventing pulpcore-worker from read access on the key labeled pulpcore_server_t
    2239041 - Reclaim space for repository fails with Cannot delete some instances of model 'Artifact' because
    they are referenced through protected foreign keys: 'ContentArtifact.artifact'.
    2238353 - The hammer export command using single thread encryption causes a performance bottleneck.
    2240781 - Remediation from CRC via Satellite shows Failed status even after successful remediation of
    Insights recommendations.
    2241914 - NoMethodError: undefined method `fact_values' while trying to perform inventory upload

    Users of Red Hat Satellite are advised to upgrade to these updated packages, which fix these bugs.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.13/html/upgrading_and_updating_red_hat_satellite/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?508efa57");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5931.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?864f25f3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2023-003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2140577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2151583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2159672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2169385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2192565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243296");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5931");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-40267");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 77, 78, 94, 400, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-dynflow-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-git");
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
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.13/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.13/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.13/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.13/debug',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.13/os',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.13/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-cli-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-debug-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-dynflow-sidekiq-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-ec2-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-journald-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-libvirt-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-openstack-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-ovirt-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-postgresql-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-service-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-telemetry-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']},
      {'reference':'foreman-vmware-3.5.1.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-3874', 'CVE-2023-0462']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.13/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.13/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.13/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-7.26.0-3.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-1292', 'CVE-2022-2068', 'CVE-2023-3817']},
      {'reference':'python39-django-3.2.21-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-31047', 'CVE-2023-36053']},
      {'reference':'python39-gitpython-3.1.32-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-24439', 'CVE-2023-40267']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/satellite/6.13/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-git-1.18.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-46648', 'CVE-2022-47318']},
      {'reference':'yggdrasil-worker-forwarder-0.0.3-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-39325', 'CVE-2023-44487']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'foreman / foreman-cli / foreman-debug / foreman-dynflow-sidekiq / etc');
}
