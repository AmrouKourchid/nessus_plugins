#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:6848.
##

include('compat.inc');

if (description)
{
  script_id(207526);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id("CVE-2024-45769", "CVE-2024-45770");
  script_xref(name:"ALSA", value:"2024:6848");

  script_name(english:"AlmaLinux 9 : pcp (ALSA-2024:6848)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:6848 advisory.

    * pcp: pmpost symlink attack allows escalating pcp to root user (CVE-2024-45770)
    * pcp: pmcd heap corruption through metric pmstore operations (CVE-2024-45769)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-6848.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-geolocate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-bcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-bpf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-bpftrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-denki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-farm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-hacluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-netcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-openmetrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-rabbitmq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-resctrl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-statsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-conf-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-devel-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-doc-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2elasticsearch-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2graphite-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2influxdb-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2json-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2spark-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2xml-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-pcp2zabbix-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-export-zabbix-agent-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-geolocate-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-gui-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-import-collectl2pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-import-ganglia2pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-import-iostat2pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-import-mrtg2pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-import-sar2pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-libs-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-libs-devel-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-activemq-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-apache-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-bash-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-bcc-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-bind2-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-bonding-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-bpf-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-bpftrace-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-cifs-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-cisco-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-dbping-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-denki-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-dm-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-docker-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-ds389-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-ds389log-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-elasticsearch-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-farm-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-gfs2-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-gluster-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-gpfs-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-gpsd-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-hacluster-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-haproxy-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-infiniband-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-json-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-libvirt-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-lio-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-lmsensors-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-logger-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-lustre-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-lustrecomm-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-mailq-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-memcache-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-mic-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-mongodb-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-mounts-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-mssql-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-mysql-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-named-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-netcheck-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-netfilter-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-news-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-nfsclient-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-nginx-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-nvidia-gpu-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-openmetrics-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-openvswitch-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-oracle-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-pdns-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-perfevent-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-podman-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-postfix-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-postgresql-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-rabbitmq-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-redis-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-resctrl-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-roomtemp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-rsyslog-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-samba-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-sendmail-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-shping-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-slurm-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-smart-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-snmp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-sockets-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-statsd-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-summary-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-systemd-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-trace-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-unbound-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-weblog-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-zimbra-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-pmda-zswap-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-selinux-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-system-tools-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-testsuite-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pcp-zeroconf-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-PCP-LogImport-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-PCP-LogSummary-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-PCP-MMV-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-PCP-PMDA-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pcp-6.2.0-5.el9_4', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pcp / pcp-conf / pcp-devel / pcp-doc / pcp-export-pcp2elasticsearch / etc');
}
