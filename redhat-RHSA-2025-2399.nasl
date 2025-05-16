#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:2399. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232538);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/22");

  script_cve_id("CVE-2024-35195", "CVE-2024-56326", "CVE-2024-56374");
  script_xref(name:"RHSA", value:"2025:2399");

  script_name(english:"RHEL 8 / 9 : Satellite 6.16.3 Async Update (Moderate) (RHSA-2025:2399)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:2399 advisory.

    Red Hat Satellite is a system management solution that allows organizations
    to configure and maintain their systems without the necessity to provide
    public Internet access to their servers or other client systems. It
    performs provisioning and configuration management of predefined standard
    operating environments.

    Security Fix(es):

    * python-jinja2: Jinja has a sandbox breakout through indirect reference to format method (CVE-2024-56326)

    * python-django: potential denial-of-service vulnerability in IPv6 validation (CVE-2024-56374)

    Users of Red Hat Satellite are advised to upgrade to these updated
    packages, which fix these bugs.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.16/html/updating_red_hat_satellite/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94bfd15");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337996");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30027");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30099");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30256");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30283");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30293");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30294");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30918");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30934");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30936");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30937");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30938");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30939");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30940");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30941");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30942");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30954");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30955");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_2399.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2f33b8c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:2399");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56326");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(670, 693, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-dynflow-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-glue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-glue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_maintain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_remote_execution-cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scap-security-guide-satellite");
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
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-foreman_maintain-1.7.12-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-cli-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-debug-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-dynflow-sidekiq-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-ec2-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-journald-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-libvirt-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-openstack-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-ovirt-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-pcp-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-postgresql-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-redis-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-service-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-telemetry-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-vmware-3.12.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-6.16.3-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-capsule-6.16.3-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-cli-6.16.3-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-common-6.16.3-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-installer-3.12.0.4-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-installer-katello-3.12.0.4-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-django-4.2.19-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195', 'CVE-2024-56374']},
      {'reference':'python3.11-jinja2-3.1.5-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195', 'CVE-2024-56326']},
      {'reference':'python3.11-pulp-cli-0.29.2-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-pulp-container-2.20.5-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-pulp-glue-0.29.2-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-pulpcore-3.49.33-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-requests-2.32.3-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'candlepin-4.4.21-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'candlepin-selinux-4.4.21-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_ansible-14.2.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_openscap-9.0.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_remote_execution-13.2.7-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_remote_execution-cockpit-13.2.7-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_theme_satellite-13.3.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-katello-4.14.0.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'scap-security-guide-satellite-1.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-foreman_maintain-1.7.12-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-cli-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-debug-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-dynflow-sidekiq-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-ec2-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-journald-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-libvirt-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-openstack-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-ovirt-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-pcp-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-postgresql-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-redis-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-service-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-telemetry-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-vmware-3.12.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-6.16.3-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-capsule-6.16.3-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-cli-6.16.3-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'satellite-common-6.16.3-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-installer-3.12.0.4-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'foreman-installer-katello-3.12.0.4-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-django-4.2.19-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195', 'CVE-2024-56374']},
      {'reference':'python3.11-jinja2-3.1.5-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195', 'CVE-2024-56326']},
      {'reference':'python3.11-pulp-cli-0.29.2-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-pulp-container-2.20.5-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-pulp-glue-0.29.2-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-pulpcore-3.49.33-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'python3.11-requests-2.32.3-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'candlepin-4.4.21-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'candlepin-selinux-4.4.21-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_ansible-14.2.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_openscap-9.0.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_remote_execution-13.2.7-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_remote_execution-cockpit-13.2.7-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-foreman_theme_satellite-13.3.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'rubygem-katello-4.14.0.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']},
      {'reference':'scap-security-guide-satellite-1.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-35195']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'candlepin / candlepin-selinux / foreman / foreman-cli / etc');
}
