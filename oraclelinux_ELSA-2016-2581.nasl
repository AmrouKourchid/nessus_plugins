#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2581 and 
# Oracle Linux Security Advisory ELSA-2016-2581 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94703);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2016-0764");
  script_xref(name:"RHSA", value:"2016:2581");

  script_name(english:"Oracle Linux 7 : NetworkManager (ELSA-2016-2581)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2016-2581 advisory.

    NetworkManager
    [1:1.4.0-12]
    - device: consider a device with slaves configured (rh#1333983)

    [1:1.4.0-11]
    - build: add RPM dependency for exact glib2 version (rh#1378809)

    [1:1.4.0-10]
    - device: improve connection matching for assuming bond and infiniband (rh#1375558)

    [1:1.4.0-9]
    - clients: handle secret requests only for current connection (rh#1351272)
    - device: fix crash reapplying connection to slave devices (rh#1376784)
    - cli: fix autocompletion after ifname (rh#1375933)

    [1:1.4.0-8]
    - libnm: fix crash in nm_vpn_plugin_info_list_get_service_types() (rh#1374526)
    - device: wait for MAC address change before setting up interface (rh#1371623, rh#1374023)

    [1:1.4.0-7]
    - wifi: another fix activation failure due to error changing MAC address (rh#1371623, rh#1374023)
    - dhcp: fix race condition that may cause lost lease events and DHCP timeouts (rh#1373276)

    [1:1.4.0-6]
    - po: add translations (rh#1276476)

    [1:1.4.0-5]
    - libnm,nmtui: fix handling empty cloned-mac-address property (rh#1372799)
    - ibft: grant required CAP_SYS_ADMIN capabilities (rh#1371201)

    [1:1.4.0-4]
    - core: really fix wrong source interface for PropertiesChanged D-Bus signal (rh#1371920)

    [1:1.4.0-3]
    - wifi: fix activation failure due to error changing MAC address (rh#1371623)
    - core: fix wrong source interface for PropertiesChanged D-Bus signal (rh#1371920)
    - team: restore validation of JSON configuration (rh#1371967)
    - device: manage firewall zone for assumed persistent connections (rh#1366288)
    - device: don't let external changes cause a release of the slave (rh#1357738)

    [1:1.4.0-2]
    - ifcfg-rh: clear IP settings for slave connections (rh#1368761)
    - ifcfg-rh: accept TEAM connections also without DEVICETYPE setting (rh#1367180)

    [1:1.4.0-1]
    - Update to 1.4.0 release
    - cli: show username when interactively connecting to a wireless network (rh #1351272)
    - ifcfg-rh: ensure master is cleared when updating a connection (rh #1355656)
    - policy: always try to update kernel hostname (rh #1362542)
    - cli: return sane error message for D-Bus policy permission errors (rh #1362542)
    - device: don't flush addresses when unmanaging assumed devices (rh #1364393)
    - team: be more tolerant when handling invalid or empty configuration (rh #1366300)
    - act-request: queue failing the slave when master fails (rh #1367702)
    - vpn: fix ipv6 configuration of VPNs without a separate interface (rh #1368354)
    - vpn: properly discard routes with invalid prefix length (rh #1368355)

    [1:1.4.0-0.6.beta1]
    - logging: default to syslog (rh #1358335)

    [1:1.4.0-0.5.beta1]
    - Update to 1.4-beta1 release
    - core: fix setting hostname from DHCP (rh #1356015)
    - vlan: honor the REORDER_HDR flag (rh #1312281)
    - device: apply MTU setting also to devices without IPv4 configuration (rh #1364275)
    - bond: improved connection matching (rh #1304641)
    - team: check return value of g_dbus_connection_call_sync() (rh #1349749)

    [1:1.4.0-0.4.git20160727.9446481f]
    - Rebuild for fixed documentation directory in redhat-rpm-macros

    [1:1.4.0-0.3.git20160727.9446481f]
    - Update to a more recent 1.4.0 snapshot:
    - bond: fix defaults and be more liberal in accepting different formats of option values (rh #1352131)
    - bond: fix setting of 'lp_interval' option (rh #1348573)
    - device: don't try to generate ipv6ll address for disconnected devices (rh #1351633)
    - device: make sure we update system hostname when DHCP configuration changes (rh #1356015)
    - device: tune down warning about failure to set userspace IPv6LL on non-existing device (rh #1323571)
    - nmcli: add 'nmcli device modify' subcommand to do runtime configuration changes (rh #998000)
    - nmcli: crash on connection delete/down timeout (rh 355740)
    - nmcli: fix 8021x settings tab-completion (rh #1301226)
    - secrets: increase timeout for getting the secrets from the agent (rh #1349740)
    - team: keep device config property up to date with actual configuration (rh #1310435)
    - team: make synchronization with teamd more robust (rh #1257237)
    - vpn: don't merge DNS properties into parent device's configuration (rh #1348901)

    [1:1.4.0-0.3.git20160621.072358da]
    - Do not regenerate gtk-doc. Together with parallel make it may cause multilib conflicts

    [1:1.4.0-0.2.git20160621.072358da]
    - enable JSON validation configure option
    - Update to a more recent 1.3.0 snapshot:
    - team: check return value of g_dbus_connection_call_sync() (rh #1347015)

    [1:1.4.0-0.1.git20160606.b769b4df]
    - Update to a 1.3.0 snapshot:
    - cli: hide secret certificate blobs unless --show-secrets set (rh #1184530)
    - dns: add support for specifying dns priorities (rh #1228707)
    - core: wait for IPv6 DAD before completing activation (rh #1243958)
    - device: take care of default route of DHCP generated-assumed connections (rh #1265239)
    - team: improve matching of team connection upon service restart (rh #1294728)
    - device: apply MTU setting also to devices without IPv4 configuration (rh #1303968)
    - device: reconfigure IP addressing after bringing up device (rh #1309899)
    - team: expose current device configuration through D-Bus and nmcli (rh #1310435)
    - systemd: add 'After=dbus.service' to NetworkManager.service (rh #1311988)
    - cli: handle device failure when activating (rh #1312726)
    - core,libnm: remove gateway from connection if never-default is set (rh #1313091)
    - platform: remove padding for IP address lifetimes (rh #1318945)
    - manager: run dispatcher scripts on suspend/sleep (rh #1330694)
    - device: remove pending dhcp actions also in IP_DONE state (rh #1330893)
    - wwan: fixed multiple crashes (rh #1331395)
    - nmcli: fix tab completion for libreswan import (rh #1337300)

    [1:1.2.0-2]
    - write /etc/resolv.conf as file by default instead of symlink (rh#1337222)
    - rename package config-routing-rules to dispatcher-routing-rules (rh #1334876)

    [1:1.2.0-1]
    - Update to NetworkManager 1.2.0 release
    - vlan: keep the hardware address synchronized with parent device (rh #1325752)
    - bond: add more options (rh #1299103)

    [1:1.2.0-0.1.beta3]
    - Update to a more recent 1.2.0 snapshot

    [1:1.2.0-0.1.beta2]
    - Update to a 1.2.0 snapshot:
    - core: add a connection defaults section to NetworkManager.conf (rh #1164677)
    - dhcp: make timeout configurable (rh #1262922)
    - pppoe: set the firewall zone on the correct ip interface (rh #1110465)
    - device: properly roll back the device activation attempt on failure (rh #1270814)
    - nmcli: add monitor command (rh #1034158)
    - nmcli: fix shell completion of bluetooth device names (rh #1271271)
    - ipv4: add an option to send full FQDN in DHCP requests (rh #1255507)
    - core: fix a use-after-free() when activating a secondary VPN connection (rh #1277247)
    - wifi: fix bssid cache updating (rh #1094298)
    - vlan: honor the reorder-header flag (rh #1250225)
    - ipv4: do a duplicate address detection (rh #1259063)
    - core: add LLDP listener to the daemon and utilities (rh #1142898)
    - vpn: don't fail activation when plugin supports interactive mode, but the VPN daemon does not (rh
    #1298732)
    - ipv6: readd the address when the MAC address changes (rh #1286105)
    - core: avoid generating excessively long names for virtual devices (rh #1300755)
    - nmcli: add connection import and export (rh #1034105)
    - vlan: fix matching of connections on assumption (rh #1276343)
    - core: fix matching of static route metrics on connection assumption (rh #1302532)
    - core: work around broken device drivers (AWS ENI) that initially have zero MAC address (rh #1288110)
    - infiniband: set the link down when changing mode, some drivers need that (rh #1281301)
    - infiniband: retry autoactivation of partitions when parent device changes (rh #1275875)


    libnl3
    [3.2.28-2]
    - route: fix nl_object_identical() comparing AF_INET addresses (rh #1370503)

    [3.2.28-1]
    - update to latest upstream release 3.2.28 (rh #1296058)

    [3.2.28-0.1]
    - update to latest upstream release 3.2.28-rc1 (rh #1296058)

    [3.2.27-1]
    - rebase package to upstream version 3.2.27 (rh #1296058)

    network-manager-applet
    [1.4.0-2]
    - c-e: fix team page with older GTK and jansson (rh #1079465)

    [1.4.0-1]
    - Update to network-manager-applet 1.4.0 release
    - c-e: add editor for teaming devices (rh #1079465)

    [1.2.2-2]
    - c-e: fix tab stop for Create button (rh#1339565)

    [1.2.2-1]
    - Update to network-manager-applet 1.2.2 release

    [1.2.0-1]
    - Update to network-manager-applet 1.2.0 release

    [1.2.0-0.1.beta3]
    - Rebase to 1.2-beta3

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-2581.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libreswan-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnl3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnm-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnma-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nm-connection-editor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'NetworkManager-glib-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-devel-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libreswan-1.2.4-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-libreswan-gnome-1.2.4-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-team-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.4.0-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libnl3-3.2.28-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-cli-3.2.28-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-devel-3.2.28-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-doc-3.2.28-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-1.4.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-devel-1.4.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-1.4.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-devel-1.4.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'network-manager-applet-1.4.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nm-connection-editor-1.4.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-adsl-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-bluetooth-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-server-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-dispatcher-routing-rules-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-devel-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libreswan-1.2.4-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-libreswan-gnome-1.2.4-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-team-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.4.0-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libnl3-3.2.28-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-cli-3.2.28-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-devel-3.2.28-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-doc-3.2.28-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-1.4.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-devel-1.4.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-1.4.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-devel-1.4.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'network-manager-applet-1.4.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nm-connection-editor-1.4.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc');
}
