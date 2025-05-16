#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:3264. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197789);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2024-3019");
  script_xref(name:"RHSA", value:"2024:3264");

  script_name(english:"RHEL 8 : pcp (RHSA-2024:3264)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for pcp.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:3264 advisory.

    Performance Co-Pilot (PCP) is a suite of tools, services, and libraries for acquisition, archiving, and
    analysis of system-level performance measurements. Its light-weight distributed architecture makes it
    particularly well-suited to centralized analysis of complex systems.

    Security Fix(es):

    * pcp: exposure of the redis server backend allows remote command execution via pmproxy (CVE-2024-3019)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271898");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_3264.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee596879");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:3264");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL pcp package based on the guidance in RHSA-2024:3264.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(668);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-bcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-bpftrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-denki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-hacluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-netcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-openmetrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-rabbitmq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-statsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pcp");
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
      'content/dist/rhel8/8.10/aarch64/appstream/debug',
      'content/dist/rhel8/8.10/aarch64/appstream/os',
      'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/appstream/debug',
      'content/dist/rhel8/8.10/ppc64le/appstream/os',
      'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/appstream/debug',
      'content/dist/rhel8/8.10/x86_64/appstream/os',
      'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/appstream/debug',
      'content/dist/rhel8/8.6/aarch64/appstream/os',
      'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/appstream/debug',
      'content/dist/rhel8/8.6/ppc64le/appstream/os',
      'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/appstream/debug',
      'content/dist/rhel8/8.6/x86_64/appstream/os',
      'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/appstream/debug',
      'content/dist/rhel8/8.8/aarch64/appstream/os',
      'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/appstream/debug',
      'content/dist/rhel8/8.8/ppc64le/appstream/os',
      'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/appstream/debug',
      'content/dist/rhel8/8.8/x86_64/appstream/os',
      'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/appstream/debug',
      'content/dist/rhel8/8.9/aarch64/appstream/os',
      'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/appstream/debug',
      'content/dist/rhel8/8.9/ppc64le/appstream/os',
      'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/appstream/debug',
      'content/dist/rhel8/8.9/x86_64/appstream/os',
      'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-conf-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-devel-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-doc-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2elasticsearch-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2graphite-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2influxdb-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2json-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2spark-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2xml-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-pcp2zabbix-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-export-zabbix-agent-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-gui-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-import-collectl2pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-import-ganglia2pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-import-iostat2pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-import-mrtg2pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-import-sar2pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-libs-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-libs-devel-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-activemq-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-apache-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-bash-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-bcc-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-bind2-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-bonding-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-bpftrace-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-cifs-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-cisco-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-dbping-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-denki-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-dm-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-docker-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-ds389-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-ds389log-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-elasticsearch-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-gfs2-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-gluster-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-gpfs-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-gpsd-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-hacluster-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-haproxy-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-infiniband-5.3.7-20.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-infiniband-5.3.7-20.el8_10', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-infiniband-5.3.7-20.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-json-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-libvirt-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-lio-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-lmsensors-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-logger-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-lustre-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-lustrecomm-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-mailq-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-memcache-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-mic-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-mongodb-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-mounts-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-mssql-5.3.7-20.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-mysql-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-named-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-netcheck-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-netfilter-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-news-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-nfsclient-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-nginx-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-nvidia-gpu-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-openmetrics-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-openvswitch-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-oracle-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-pdns-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-perfevent-5.3.7-20.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-perfevent-5.3.7-20.el8_10', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-perfevent-5.3.7-20.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-podman-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-postfix-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-postgresql-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-rabbitmq-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-redis-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-roomtemp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-rsyslog-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-samba-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-sendmail-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-shping-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-slurm-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-smart-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-snmp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-sockets-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-statsd-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-summary-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-systemd-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-trace-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-unbound-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-weblog-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-zimbra-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-pmda-zswap-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-selinux-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-system-tools-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-testsuite-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-zeroconf-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PCP-LogImport-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PCP-LogSummary-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PCP-MMV-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PCP-PMDA-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pcp-5.3.7-20.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pcp / pcp-conf / pcp-devel / pcp-doc / pcp-export-pcp2elasticsearch / etc');
}
