#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0384-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212492);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-22114", "CVE-2024-36461");

  script_name(english:"openSUSE 15 Security Update : zabbix (openSUSE-SU-2024:0384-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0384-1 advisory.

    Zabbix was updated to 6.0.33:

    - this version fixes CVE-2024-36461 and CVE-2024-22114
    - New Features and Improvements

      + ZBXNEXT-9000 Changed query table for ASM disk group metrics in Oracle Database plugin and
        Oracle by ODBC template Agent Templates
      + ZBXNEXT-9217 Added AWS Lambda by HTTP template Templates
      + ZBXNEXT-9293 Updated max supported MySQL version to 9.0 Proxy Server
      + ZBXNEXT-8657 Updated Zabbix health templates with new visualization Templates
      + ZBXNEXT-9143 Added index on auditlog recordsetid Server
      + ZBXNEXT-9081 Added Small Computer System Interface (SCSI) device type support to Zabbix agent 2 Smart
    plugin Agent
      + ZBXNEXT-6445 Added recovery expression for fuzzytime triggers in Linux and Windows templates,
        removed fuzzytime triggers from active agent templates Templates
      + ZBXNEXT-9201 Updated max supported MySQL version to 8.4 Proxy Server
      + ZBXNEXT-9225 Updated max supported TimescaleDB version to 2.15 Server
      + ZBXNEXT-9226 Updated max supported MariaDB version to 11.4 Proxy Server
      + ZBXNEXT-8868 Added discovery and template for Azure VM Scale Sets Templates

    - Bug Fixes

      + BX-24947 Fixed PHP runtime errors while processing frontend notifications Frontend
      + ZBX-24824 Improved loadable plugin connection broker Agent
      + ZBX-24583 Fixed inability to export/import web scenario with digest authentication API
      + ZBX-23905 Fixed double scroll in script dialogs Frontend
      + ZBX-18767 Fixed word breaks in flexible text input fields and trigger expressions Frontend
      + ZBX-24909 Fixed resolving of macro functions in the 'Item value' widget Frontend
      + ZBX-24859 Fixed JavaScript in S3 buckets discovery rule Templates
      + ZBX-24617 Fixed hardcoded region in AWS by HTTP template Templates
      + ZBX-24524 Fixed 'New values per second' statistic to include dependent items in calculation Proxy
    Server
      + ZBX-24821 Made 'execute_on' value being recorded in audit only for shell scripts Server
      + ZBX-23312 Fixed discovery edit form being saved incorrectly after dcheck update Frontend
      + ZBX-24773 Fixed duplicate item preprocessing in Kubernetes Kubelet by HTTP template Templates
      + ZBX-24514 Fixed standalone Zabbix server and Zabbix proxy not stopping when database is read-only
    Proxy Server
      + ZBX-23936 Fixed state and styling of readonly fields Frontend
      + ZBX-24520 Fixed an issue with incorrect translations used in several frontend places Frontend
      + ZBX-21815 Fixed issue with undefined offset for media type when it was deleted before saving the user
    Frontend
      + ZBX-24108 Fixed error in dashboard if Map widget contains map element that user doesn't have access to
    Frontend
      + ZBX-24569 Fixed old and added new items to Azure Virtual Machine template Templates
      + ZBX-24537 Fixed tags subfilter in Latest data kiosk mode Frontend
      + ZBX-24167 Fixed template linkage when item prototype collision is found Server
      + ZBX-23770 Improved monitoring user permissions documentation for Zabbix agent 2 Oracle plugin and
    Oracle by ODBC template Documentation
      + ZBX-24565 Removed redundant kernel header include, fixed musl compatibility issues (thanks to Alpine
    Linux maintainers for spotting this)
      + ZBX-24610 Fixed interface field appearance for discovered items without interface set Frontend
      + ZBX-24562 Fixed incorrect problem order in Problems by severity widget's hintbox Frontend
      + ZBX-23751 Fixed inability to pass an action filter condition without an 'operator' property, implying
    a default value of 'Equal' API
      + ZBX-21429 Prevented ability to disable all UI element access via role.update API API
      + ZBX-19271 Fixed inconsistent tag row rendering in different edit forms Frontend
      + ZBX-24539 Fixed incorrect threshold in trigger expression of Check Point Next Generation Firewall by
    SNMP template Templates
      + ZBX-24667 Fixed vm.memory.size[pused] item on Solaris Agent
      + ZBX-23781 Added storage volumes check in HPE iLO by HTTP template Templates
      + ZBX-24391 Fixed Zabbix agent to return net.tcp.socket.count result without error if IPv6 is disabled
    Agent
      + ZBX-24235 Fixed value misalignment in Item value widget Frontend
      + ZBX-24352 Fixed custom severity name usage in Geomap widget Frontend
      + ZBX-24665 Fixed potential problem with deprecated GCE Integrity feature Templates
      + ZBX-20993 Fixed Zabbix agent 2 MQTT plugin clientID to be generated by strict requirements Agent
      + ZBX-23426 Added dependent item with JavaScript preprocessing for edges SD-WAN in VMWare SD-WAN
    VeloCloud by HTTP template Templates
      + ZBX-24566 Fixed crash when expression macro is used in unsupported location Server
      + ZBX-24450 Fixed issue where graph could differ for data gathered from PostgreSQL and other databases
    Frontend
      + ZBX-24513 Fixed real-time export of rarely updated trends Server
      + ZBX-24163 Fixed submap addition in Map navigation tree widget to not append same submaps repeatedly
    Frontend
      + ZBX-23398 Fixed trigger expression constructor incorrectly showing '<' and '>' operators Frontend
      + ZBX-23584 Fixed error message being displayed when updating host after changing item status Frontend
      + ZBX-24635 Fixed datastore triggers in VMware templates Templates


    Update to 6.0.31:

    - New Features and Improvements

      + ZBXNEXT-9140 Added support for custom compartments in Oracle Cloud by HTTP templates Templates
      + ZBXNEXT-9034 Added Jira Data Center by JMX template Templates
      + ZBXNEXT-8682 Introduced a length limit of 512KB for item test values that server returns to Zabbix
    frontend Frontend Server
      + ZBXNEXT-8248 Added database filter macros to MySQL templates Templates
      + ZBXNEXT-6698 Removed absolute threshold and timeleft from OS template triggers of filesystem space
    Templates
      + ZBXNEXT-7930 Added user macro support for username and password fields in email media type Server
      + ZBXCTR-22 Refactored JavaScript filter functions for Kubernetes templates Templates
      + ZBXNEXT-9098 Added AWS ELB Network Load Balancer by HTTP template Templates
      + ZBXNEXT-6864 Replaced {HOST.CONN} with user macros in templates Templates
      + ZBXNEXT-9117 Updated max supported MariaDB version to 11.3 Proxy Server
      + ZBXNEXT-9026 Added Go compiler version to Zabbix agent 2 version output Agent
      + ZBXNEXT-8786 Changed 'odbc.discovery' keys to 'odbc.get' in MySQL by ODBC and Oracle by ODBC templates
    Templates
      + ZBXNEXT-8536 Added cbdhsvc service to macros in Windows agent templates Templates
      + ZBXNEXT-8861 Made changes and added more metrics to the FortiGate by SNMP template Templates
      + ZBXNEXT-8240 Added a new set of templates for integration with Oracle Cloud Infrastructure Templates

    - Bug Fixes

      + ZBX-24483 Improved memory usage in Zabbix server/proxy trappers and in proxy
        pollers when sending large configuration Proxy Server
      + ZBX-23073 Fixed URL widget resizing and dragging Frontend
      + ZBX-24574 Fixed HA node flipping between standby and active states Server
      + ZBX-24119 Fixed possible blocking of alert manager when it periodically pings database Server
      + ZBX-7998 Added VMware service username, password and URL check for empty values Proxy Server
      + ZBX-24402 Reduced main process connections to database during startup Proxy Server
      + ZBX-24369 Fixed filter behavior in monitoring pages after deleting filter parameters Frontend
      + ZBX-24484 Fixed Geomap widget console error when dragging map in widget edit mode Frontend
      + ZBX-23337 Improved supported version documentation for Oracle Database plugin and both templates
    Documentation
      + ZBX-24180 Fixed inability to import existing host or template when its dependent item prototype,
        which is used in trigger prototypes or graph prototypes, would have a different master item API
      + ZBX-20871 Fixed inability to use LLD macro functions in Prometheus pattern and labels used in item
    prototype preprocessing API
      + ZBX-24527 Fixed unnecessary loading text being displayed in hintbox preloader Frontend
      + ZBX-24362 Fixed wrong Zabbix agent 2 loadable plugin process handling catching all child process exits
    Agent
      + ZBX-24470 Fixed scale of VMware vmware.vm.memory.size.compressed key Proxy Server
      + ZBX-24415 Added triggers for datastores in VMware templates Templates
      + ZBX-18094 Fixed multiple pie graph issues related to calculation of item angles Frontend
      + ZBX-20766 Fixed confusing port binding error message Agent Proxy Server
      + ZBX-24481 Fixed inability to unset value map from existing item or item prototype by passing
        a version without valuemap parameter into configuration.import API
      + ZBX-24531 Fixed compile time data not being set for agent2 Agent
      + ZBX-24453 Implemented socket file cleanup when shutting down, added blocking of signals during
    important stages of startup Proxy Server
      + ZBX-24152 Fixed host form submission with Enter button if the form is opened in a popup and focus is
    in a flexible text area field Frontend
      + ZBX-23788 Added SNMP OID ifAlias in Network interfaces discovery Templates
      + ZBX-24482 Fixed the presence of the http_proxy field in the initial data Installation
      + ZBX-24210 Improved Zabbix agent 2 loadable plugin capacity code style Agent
      + ZBX-23951 Fixed issue of incorrect template matching when no UUID exists in export file API
      + ZBX-23953 Fixed CIDR network mask of VMware HV network interface Proxy Server
      + ZBX-24195 Fixed host IPMI username and password field max length Frontend
      + ZBX-24451 Added tags and changed a item in Proxmox template Templates
      + ZBX-23386 Fixed hintbox sizing to fit screen Frontend
      + ZBX-24024 Fixed OIDs for external sensors in APC UPC by SNMP templates Templates
      + ZBX-21751 Fixed node's loadavg item in Proxmox template Templates
      + ZBX-24315 Fixed linking template to host when some LLD macro paths already exist Server
      + ZBX-24172 Fixed Zabbix server issue with scheduled intervals on Feb 29th of leap year Server
      + ZBX-23407 Improved performance of retrieving last history values when primary keys are available API
      + ZBX-24246 Updated descriptions for family of MySQL and Oracle templates,
        changed macro in the trigger 'Tablespace utilization is too high' for family of Oracle templates
    Templates
      + ZBX-23988 Renamed Agent2 Go module
      + ZBX-24222 Fixed incorrect item OIDs in the FortiGate by SNMP template Templates
      + ZBX-24393 Updated README in Redis by Zabbix agent 2 template Templates
      + ZBX-24298 Allowed any JNDI service providers back in JMX monitoring Java gateway
      + ZBX-19990 Separated LLD filter macros in Apache Tomcat by JMX template Templates
      + ZBX-24364 Added preprocessing steps for LLD rules in RabbitMQ templates Templates
      + ZBX-24368 Improved PostgreSQL autovacuum's count query Templates
      + ZBX-24282 Fixed Zabbix proxy to report error for not supported items Proxy Server
      + ZBX-19507 Fixed vmware.eventlog item to recover after event keys are reset Server
      + ZBX-24241 Fixed Zabbix server issue with random order of host groups for a host during real-time
    export Server
      + ZBX-24275 Fixed item prototype JSONPath preprocessing, added missing volume health metric and triggers
    in HPE MSA templates Templates
      + ZBX-24316 Fixed username macro in GridGain by JMX template Templates
      + ZBX-23719 Updated plugin-support to add duplicate flag handling Agent
      + ZBX-22429 Fixed typo in Zabbix proxy automake file Installation
      + ZBX-24264 Fixed value cache being filled with values of newly added items with triggers Server
      + ZBX-24088 Fixed problem filtering in maps with nested maps Frontend
      + ZBX-24206 Fixed line breaks in JavaScript in Cloudflare template Templates
      + ZBX-24236 Fixed nested transaction error in LLD when connection is terminated Server
      + ZBX-24134 Added sensor discovery in VMware Hypervisor template Templates
      + ZBX-23918 Fixed item pattern select popup to display all available items Frontend
      + ZBX-24190 Fixed items being updated incorrectly when configuring graph Frontend
      + ZBX-24289 Fixed issue with interface assignment for items copied from host to host Frontend
      + ZBX-23032 Added triggers for cluster status in VMware templates Templates
      + ZBX-23948 Added support for TabularData data when parsing an MBean attribute Java gateway
      + ZBX-23742 Fixed tag filtering logic for tags with one name and different types of operators API
      + ZBX-24271 Added delay in JavaScript execution for Azure Cost Management by HTTP template Templates
      + ZBX-24208 Fixed Oracle, MySQL plugin connection cache blocking Agent
      + ZBX-24202 Fixed JavaScript in AWS S3 bucket by HTTP template Templates
      + ZBX-23478 Fixed issue when missing locale error would not be displayed for user under certain
    conditions Frontend
      + ZBX-24166 Fixed Zabbix not being able to restart due to RTC and sockets not being closed before
    stopping Agent Proxy Server
      + ZBX-23853 Fixed duplicate agent check timestamps when time shifts back due to system clock
    synchronization Agent

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229204");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/C6HFPCXWPBUGZ3BE7T5OXXTSGEHUCHFU/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70b5b5b4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36461");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-user-zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-ui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'system-user-zabbix-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-agent-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-java-gateway-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-mysql-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-postgresql-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-sqlite-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-server-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-server-mysql-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-server-postgresql-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-ui-6.0.33-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'system-user-zabbix / zabbix-agent / zabbix-java-gateway / etc');
}
