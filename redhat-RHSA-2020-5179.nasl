##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5179. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143235);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2019-20920", "CVE-2019-20922", "CVE-2020-8203");
  script_xref(name:"RHSA", value:"2020:5179");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : Red Hat Virtualization (RHSA-2020:5179)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:5179 advisory.

    The org.ovirt.engine-root is a core component of oVirt.

    The following packages have been upgraded to a later upstream version: engine-db-query (1.6.2),
    org.ovirt.engine-root (4.4.3.8), ovirt-engine-dwh (4.4.3.1), ovirt-engine-extension-aaa-ldap (1.4.2),
    ovirt-engine-extension-logger-log4j (1.1.1), ovirt-engine-metrics (1.4.2.1), ovirt-engine-ui-extensions
    (1.2.4), ovirt-log-collector (4.4.4), ovirt-web-ui (1.6.5), rhv-log-collector-analyzer (1.0.5), rhvm-
    branding-rhv (4.4.6). (BZ#1866981, BZ#1879377)

    Security Fix(es):

    * nodejs-handlebars: lookup helper fails to properly validate templates allowing for arbitrary JavaScript
    execution (CVE-2019-20920)

    * nodejs-handlebars: an endless loop while processing specially-crafted templates leads to DoS
    (CVE-2019-20922)

    * nodejs-lodash: prototype pollution in zipObjectDeep function (CVE-2020-8203)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * send --nowait to libvirt when we collect qemu stats, to consume bz#1552092 (BZ#1613514)

    * Block moving HE hosts into different Data Centers and make HE host moved to different cluster
    NonOperational after activation (BZ#1702016)

    * If an in-use MAC is held by a VM on a different cluster, the engine does not attempt to get the next
    free MAC. (BZ#1760170)

    * Search backend cannot find VMs which name starts with a search keyword (BZ#1797717)

    * [Permissions] DataCenterAdmin role defined on DC level does not allow Cluster creation (BZ#1808320)

    * enable-usb-autoshare is always 0 in console.vv and usb-filter option is listed two times (BZ#1811466)

    * NumaPinningHelper is not huge pages aware, denies migration to suitable host (BZ#1812316)

    * Adding quota to group doesn't propagate to users (BZ#1822372)

    * Engine adding PCI-E elements on XML of i440FX SeaBIOS VM created from Q35 Template (BZ#1829691)

    * Live Migration Bandwidth unit is different from Engine configuration (Mbps) and VDSM (MBps) (BZ#1845397)

    * RHV-M shows successful operation if OVA export/import failed during qemu-img convert phase
    (BZ#1854888)

    * Cannot hotplug disk reports libvirtError: Requested operation is not valid: Domain already contains a
    disk with that address (BZ#1855305)

    * rhv-log-collector-analyzer --json fails with TypeError (BZ#1859314)

    * RHV 4.4 on AMD EPYC 7742 throws an NUMA related error on VM run (BZ#1866862)

    * Issue with dashboards creation when sending metrics to external Elasticsearch (BZ#1870133)

    * HostedEngine VM is broken after Cluster changed to UEFI (BZ#1871694)

    * [CNV&RHV]Notification about VM creation contain <UNKNOWN> string (BZ#1873136)

    * VM stuck in Migrating status after migration completed due to incorrect status reported by VDSM after
    restart (BZ#1877632)

    * Use 4.5 as compatibility level for the Default DataCenter and the Default Cluster during installation
    (BZ#1879280)

    * unable to create/add index pattern in step 5 from kcs articles#4921101 (BZ#1881634)

    * [CNV&RHV] Remove warning about no active storage domain for Kubevirt VMs (BZ#1883844)

    * Deprecate and remove ovirt-engine-api-explorer (BZ#1884146)

    * [CNV&RHV] Disable creating new disks for Kubevirt VM (BZ#1884634)

    * Require ansible-2.9.14 in ovirt-engine (BZ#1888626)

    Enhancement(s):

    * [RFE] Virtualization support for NVDIMM - RHV (BZ#1361718)

    * [RFE] - enable renaming HostedEngine VM name (BZ#1657294)

    * [RFE] Enabling Icelake new NIs - RHV (BZ#1745024)

    * [RFE] Show vCPUs and allocated memory in virtual machines summary (BZ#1752751)

    * [RFE] RHV-M Deployment/Install Needs it's own UUID (BZ#1825020)

    * [RFE] Destination Host in migrate VM dialog has to be searchable and sortable (BZ#1851865)

    * [RFE] Expose the reinstallation required flag of the hosts in the API (BZ#1856671)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_5179.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aa62d53");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1613514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1657294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1691253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1752751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1760170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1797717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1808320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1811466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1812316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1822372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1825020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1829691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1842344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1845432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1851865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1854888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1855305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1857412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1862101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1866981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1870133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1871694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1881634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1883844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1884146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1884634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1885976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1887268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1888626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889522");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20920");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-health-check-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-cinderlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-imageio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-web-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ovirt-engine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/os',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ovirt-engine-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-backend-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-dbscripts-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-health-check-bundler-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-restapi-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-base-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-plugin-cinderlib-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-plugin-imageio-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-common-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-setup-plugin-websocket-proxy-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-tools-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-tools-backup-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-vmconsole-proxy-helper-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-webadmin-portal-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-engine-websocket-proxy-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'ovirt-web-ui-1.6.5-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2019-20920', 'CVE-2019-20922']},
      {'reference':'python3-ovirt-engine-lib-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']},
      {'reference':'rhvm-4.4.3.8-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-8203']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ovirt-engine / ovirt-engine-backend / ovirt-engine-dbscripts / etc');
}
