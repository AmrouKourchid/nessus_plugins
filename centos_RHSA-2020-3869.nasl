##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3869 and
# CentOS Errata and Security Advisory 2020:3869 respectively.
##

include('compat.inc');

if (description)
{
  script_id(143283);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id("CVE-2019-3695", "CVE-2019-3696");
  script_xref(name:"RHSA", value:"2020:3869");

  script_name(english:"CentOS 7 : pcp (RHSA-2020:3869)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2020:3869 advisory.

  - A Improper Control of Generation of Code vulnerability in the packaging of pcp of SUSE Linux Enterprise
    High Performance Computing 15-ESPOS, SUSE Linux Enterprise High Performance Computing 15-LTSS, SUSE Linux
    Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Development Tools 15-SP1,
    SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Server
    15-LTSS, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Software Development Kit 12-SP4,
    SUSE Linux Enterprise Software Development Kit 12-SP5; openSUSE Leap 15.1 allows the user pcp to run code
    as root by placing it into /var/log/pcp/configs.sh This issue affects: SUSE Linux Enterprise High
    Performance Computing 15-ESPOS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise High Performance
    Computing 15-LTSS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for Development Tools
    15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for Development Tools 15-SP1 pcp
    versions prior to 4.3.1-3.5.3. SUSE Linux Enterprise Module for Open Buildservice Development Tools 15 pcp
    versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Server 15-LTSS pcp versions prior to 3.11.9-5.8.1.
    SUSE Linux Enterprise Server for SAP 15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Software
    Development Kit 12-SP4 pcp versions prior to 3.11.9-6.14.1. SUSE Linux Enterprise Software Development Kit
    12-SP5 pcp versions prior to 3.11.9-6.14.1. openSUSE Leap 15.1 pcp versions prior to 4.3.1-lp151.2.3.1.
    (CVE-2019-3695)

  - A Improper Limitation of a Pathname to a Restricted Directory vulnerability in the packaging of pcp of
    SUSE Linux Enterprise High Performance Computing 15-ESPOS, SUSE Linux Enterprise High Performance
    Computing 15-LTSS, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for
    Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE
    Linux Enterprise Server 15-LTSS, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Software
    Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5; openSUSE Leap 15.1 allows
    local user pcp to overwrite arbitrary files with arbitrary content. This issue affects: SUSE Linux
    Enterprise High Performance Computing 15-ESPOS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise
    High Performance Computing 15-LTSS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for
    Development Tools 15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for Development
    Tools 15-SP1 pcp versions prior to 4.3.1-3.5.3. SUSE Linux Enterprise Module for Open Buildservice
    Development Tools 15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Server 15-LTSS pcp versions
    prior to 3.11.9-5.8.1. SUSE Linux Enterprise Server for SAP 15 pcp versions prior to 3.11.9-5.8.1. SUSE
    Linux Enterprise Software Development Kit 12-SP4 pcp versions prior to 3.11.9-6.14.1. SUSE Linux
    Enterprise Software Development Kit 12-SP5 pcp versions prior to 3.11.9-6.14.1. openSUSE Leap 15.1 pcp
    versions prior to 4.3.1-lp151.2.3.1. (CVE-2019-3696)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3869");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3695");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-blinkenlights");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-vector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-conf-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-conf-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-devel-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-devel-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-doc-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-doc-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2elasticsearch-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2elasticsearch-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2graphite-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2graphite-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2influxdb-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2influxdb-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2json-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2json-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2spark-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2spark-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2xml-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2xml-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2zabbix-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-pcp2zabbix-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-zabbix-agent-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-export-zabbix-agent-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-gui-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-gui-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-collectl2pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-collectl2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-ganglia2pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-ganglia2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-iostat2pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-iostat2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-mrtg2pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-mrtg2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-sar2pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-import-sar2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-libs-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-libs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-libs-devel-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-libs-devel-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-manager-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-manager-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-activemq-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-activemq-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-apache-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-apache-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bash-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bash-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bcc-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bcc-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bind2-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bind2-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bonding-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-bonding-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-cifs-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-cifs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-cisco-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-cisco-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-dbping-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-dbping-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-dm-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-dm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-docker-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-docker-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-ds389-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-ds389-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-ds389log-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-ds389log-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-elasticsearch-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-elasticsearch-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gfs2-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gfs2-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gluster-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gluster-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gpfs-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gpfs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gpsd-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-gpsd-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-haproxy-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-haproxy-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-infiniband-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-infiniband-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-json-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-json-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-libvirt-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-libvirt-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lio-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lio-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lmsensors-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lmsensors-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-logger-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-logger-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lustre-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lustre-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lustrecomm-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-lustrecomm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mailq-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mailq-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-memcache-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-memcache-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mic-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mic-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mounts-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mounts-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mysql-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-mysql-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-named-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-named-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-netfilter-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-netfilter-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-news-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-news-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-nfsclient-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-nfsclient-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-nginx-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-nginx-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-nvidia-gpu-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-nvidia-gpu-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-oracle-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-oracle-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-pdns-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-pdns-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-perfevent-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-perfevent-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-postfix-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-postfix-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-postgresql-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-postgresql-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-prometheus-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-prometheus-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-redis-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-redis-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-roomtemp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-roomtemp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-rpm-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-rpm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-rsyslog-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-rsyslog-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-samba-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-samba-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-sendmail-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-sendmail-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-shping-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-shping-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-slurm-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-slurm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-smart-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-smart-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-snmp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-snmp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-summary-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-summary-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-systemd-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-systemd-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-trace-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-trace-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-unbound-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-unbound-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-vmware-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-vmware-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-weblog-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-weblog-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-zimbra-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-zimbra-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-zswap-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-pmda-zswap-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-selinux-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-selinux-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-system-tools-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-system-tools-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-testsuite-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-testsuite-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapi-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapi-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-blinkenlights-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-blinkenlights-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-grafana-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-grafana-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-graphite-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-graphite-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-vector-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webapp-vector-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webjs-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-webjs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-zeroconf-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcp-zeroconf-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-LogImport-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-LogImport-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-LogSummary-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-LogSummary-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-MMV-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-MMV-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-PMDA-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-PCP-PMDA-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pcp-4.3.2-12.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pcp / pcp-conf / pcp-devel / etc');
}
