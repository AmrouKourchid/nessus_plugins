#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:7242. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194216);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2022-30122", "CVE-2022-31163");
  script_xref(name:"RHSA", value:"2022:7242");

  script_name(english:"RHEL 7 / 8 : Satellite 6.11.4 Async Security Update (Important) (RHSA-2022:7242)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:7242 advisory.

    Red Hat Satellite is a system management solution that allows organizations to configure and maintain
    their systems without the necessity to provide public Internet access to their servers or other client
    systems. It performs provisioning and configuration management of predefined standard operating
    environments.

    This update fixes the following bugs:

    2131757 - Enhance foreman-rake katello:correct_repositories to handle Katello::Errors::CandlepinError:
    Unable to find content with the ID xxxxxxxxxxx.
    2131759 - RHEL 9 provisioned host goes into emergency mode after initial reboot
    2131761 - hammer cannot use the cluster name or id as valid input when clusters are residing inside
    folders and fails with error Fog::Vsphere::Compute::NotFound error
    2131763 - Running satellite-maintain self-upgrade on a Satellite\Capsule 6.11.1.1 fails with error
    Error: 'satellite-maintenance-6.11.2-for-rhel-8-x86_64-rpms' does not match a valid repository ID
    2131769 - Post upgrade to 6.11.z, DHCP error with wrong number of arguments for validate_supported_address
    2131771 - With every edit of an exising webhook, the value in password field disappears in Satellite
    6.10/6.11/6.12
    2131773 - foreman-maintain still enables ansible-2.9-for-rhel-8-x86_64-rpms repository for running an
    update to 6.11.z when no packages are installed from that repository
    2131776 - please update to Satellite Ansible Collection 3.6.0
    2131781 - 'candlepin-validate-db' pre-upgrade check fails with Could not open SSL root certificate file
    /root/.postgresql/root.crt error for external DB setup with SSL
    2131788 - Documentation bug for the compute_resource module
    2131790 - [BUG] Invalid choice for template_kind listed for os_default_template module
    2132075 - CVE-2022-31163 tfm-rubygem-tzinfo: rubygem-tzinfo: arbitrary code execution [rhn_satellite_6.11]
    2132076 - CVE-2022-31163 rubygem-tzinfo: rubygem-tzinfo: arbitrary code execution [rhn_satellite_6.11]
    2132079 - CVE-2022-30122 rubygem-rack: crafted multipart POST request may cause a DoS
    [rhn_satellite_6-default]
    2122205 - Package python3-pulp_manifest is not available in Satellite Utils repository
    2132999 - Satellite cannot be installed on RHEL 8.7

    CVEs

    CVE-2022-30122
    CVE-2022-31163

    Users of Red Hat Satellite are advised to upgrade to these updated packages, which fix these bugs.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_7242.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?677c9c61");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2110551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2122205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2131790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2132999");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:7242");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31163");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(23, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-tzinfo");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.11/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.11/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.11/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.11/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.11/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-rack-2.2.3.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-30122']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/satellite/6.11/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.11/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-tzinfo-1.2.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-31163']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.11/os',
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.11/os',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tfm-rubygem-rack-2.2.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-30122']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.11/os',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'tfm-rubygem-tzinfo-1.2.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2022-31163']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rubygem-rack / rubygem-tzinfo / tfm-rubygem-rack / etc');
}
