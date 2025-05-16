#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2299 and 
# Oracle Linux Security Advisory ELSA-2017-2299 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102341);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-0553");
  script_xref(name:"RHSA", value:"2017:2299");

  script_name(english:"Oracle Linux 7 : NetworkManager / and / libnl3 (ELSA-2017-2299)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2017-2299 advisory.

    NetworkManager
    [1:1.8.0-9]
    - device: don't change MTU unless explicitly configured (rh #1460760)
    - core: don't remove external IPv4 addresses (rh #1459813)

    [1:1.8.0-8]
    - cli: fix output of iface in overview output (rh#1460219)
    - ppp: unexport NMPPPManager instance on dispose (rh#1459579)
    - cli: remove spurious device names from wifi subcommands output (rh#1460527)

    [1:1.8.0-7]
    - bond: fix crash comparing mode while generating bond connection (rh #1459580)
    - connectivity: fix route penalty if WWAN and BT device using ip-ifindex (rh #1459932)
    - device: persist nm-owned in run state (rh #1376199)
    - device: fix assuming master device on restart (rh #1452062)
    - device: apply route metric penality only when the default route exists (rh #1459604)

    [1:1.8.0-6]
    - connectivity: fix periodic connectivity check (rh #1458399)
    - bond: improve option matching on daemon restart (rh #1457909)
    - device: fix touching device after external activation (rh #1457242)

    [1:1.8.0-5]
    - ifcfg-rh: fix writing legacy NETMASK value (rh #1445414)
    - tui: fix crash during connect (rh #1456826)
    - libnm: fix libnm rejecting VLAN ID 4095 (rh #1456911)

    [1:1.8.0-4]
    - device: update external configuration before commit (rh #1449873)
    - bluetooth: fix crash on connecting to a NAP (rh #1454385)
    - device: release removed devices from master on cleanup (rh #1448907)
    - core: activate slaves using ifindex order by default (rh #1452585)
    - nmcli: fix crash when setting 802-1x.password-raw (rh #1456362)
    - po: update translations (rh #1382625)

    [1:1.8.0-3]
    - dhcp: don't add route to DHCP4 server (rh #1448987)
    - libnm: fix NUL termination of device's description (rh #1443114)
    - libnm, core: ensure valid UTF-8 in device properties (rh #1443114)
    - core: fix device's UDI property on D-Bus (rh #1443114)
    - ifcfg-rh: omit empty next hop for routes in legacy format (rh #1452648)

    [1:1.8.0-2]
    - core: fix persisting managed state of device (rh #1440171)
    - proxy: fix use-after-free (rh #1450459)
    - device: don't wrongly delay startup complete waiting for carrier (rh #1450444)

    [1:1.8.0-1]
    - Update to upstream release 1.8.0
    - device: support dummy devices (rh#1398932)
    - core: support attaching user-data to connection profiles (rh#1421429)
    - core: fix allowing FQDN in dhcp-hostname setting (rh#1443437)
    - core: fix configuring firewall while device is activating (rh#1445242)
    - core: don't block activation without carrier for IPv6 DAD (rh#1446367)
    - tui: force writing master key to ifcfg file when editing connection (rh#1425409)

    [1:1.8.0-0.4.rc3]
    - Update to third Release Candidate of NetworkManager 1.8
    - device: fix regressions in assuming devices on carryover from initrd (rh #1443878)
    - device: add support for SRIOV num_vfs (rh #1398934)
    - device: leave device up when setting it as unmanaged by user (rh #1371433)
    - core: properly track manager, route manager and default route manager references (rh #1440089)
    - route: properly deal with routes with non-empty host parts (rh #1439376)
    - vpn: fix a crash on disconnect (rh #1442064)
    - cli: fix hang on connection down (rh #1422786)
    - cli: fix interactive edit of bond slaves (rh #1440957)
    - vpn: fix early error handling on failed activations (rh #1440077)
    - core: only persist explicit managed state in device's state file (rh #1440171)

    [1:1.8.0-0.4.rc2]
    - Update to second Release Candidate of NetworkManager 1.8
    - device: don't update disconnected devices routes after connectivity check (rh #1436978)
    - ifcfg-rh: also check BONDING_OPTS to determine the connection type (rh #1434555)
    - nmcli: fix nmcli con edit crash (rh #1436993)
    - nmcli: fix nmcli con down (rh #1436990)

    [1:1.8.0-0.4.rc1]
    - Update to first Release Candidate of NetworkManager 1.8
    - nmcli: speedup with large numbers of VLANs (rh #1231526)
    - dns: avoid cleaning resolv.conf on exit if not needed (rh #1344303, rh #1426748)
    - device: bond: implement connection reapply (rh #1348198)
    - platform: add support for some route options (rh #1373698)
    - core: add mtu property to cdma and gsm settings (rh #1388613)
    - nmcli: fix output in terse mode (rh #1391170)
    - improve handling of unmanaged/assumed devices (rh #1394579)
    - policy: make DHCP hostname behaviour configurable (rh #1405275)
    - manager: ensure proper disposal of unrealized devices (rh #1433303)
    - nmcli: fix connection down (rh #1433883)
    - libnm-glib: fix memory leak (rh #1433912)
    - device: deal with non-existing IP settings in get_ip_config_may_fail() (rh #1436601)
    - nmcli: make --ask and --show-secrets global options (rh #1351263)
    - nmcli: improve error handling (rh #1394334)
    - device: apply a loose IPv4 rp_filter when it would interfere with multihoming (rh #1394344)
    - core: make connectivity checking per-device (rh #1394345)
    - manager: sort slaves to be autoconnected by device name (rh #1420708)
    - policy: add support to configurable hostname mode (rh #1422610)
    - team: support the ethernet.cloned-mac-address property (rh #1424641)
    - ifcfg-rh: fix reading team slave types of vlan type (rh #1427482)
    - default-route-manager: alyways force a sync of the default route (rh #1431268)
    - device: fail DHCPv6 if a link-local address is not present (rh #1432251)

    [1:1.8.0-0.3.git20170215.1d40c5f4]
    - Revert default behavior for clone-mac-address to permanent (rh #1413312)

    [1:1.8.0-0.2.git20170215.1d40c5f4]
    - Update to a 1.7.1 snapshot:
    - rebase NetworkManger package to new upstream 1.8.x version (rh #1414103)
    - device: introduce support to ipv6.method=shared (rh #1256822)
    - device: add support to vlan on virtual devices (rh #1312359)
    - core/supplicant: introduce support to MACsec connections (rh #1337997)
    - core: allow enforcing of 802-3 link properties (rh #1353612)
    - manager: allow a slave connection which has slaves to autoactivate them (rh #1360386)
    - cli: check the active-connection state to detect activation failure (rh #1367752, rh #1384937)
    - cli: remove the separate thread when in editor mode to fix races (rh #1368353)
    - ifcfg-rh: write the master device name even if the master property is an UUID (rh #1369008)
    - ifcfg-rh: higly improved parsing of ifcfg files (rh #1369380)
    - checkpoint: improved the checkpoint/rollback functionality (rh #1369716)
    - core: core: don't unmanage devices on shutdown (rh #1371126, rh #1378418)
    - cli: properly set multiple addresses in questionnaire mode (rh #1380165)
    - manager: keep scheduling connectivity check if there is a default active connection (rh #1386106)
    - device: allow custom MAC address on bond and bridge interfaces (rh #1386872)
    - core: avoid race reading permanent MAC address before udev initialized (rh #1388286)
    - ifcfg-rh: fix import of 802.1x connections with empty EAP-TLS identity (rh #1391477)
    - libnm-core: remove INFERRABLE flag from dhcp-hostname property (rh #1393997)
    - platform: preserve the order when multiple ip addresses are present (rh #1394500)
    - device: avoid a crash when both IPv4 and IPv6 configurations fail (rh #1404148)
    - dns: export dns state to DBUS (rh #1404594)
    - ppp: moved PPP support into a separate package (rh #1404598)
    - dns: don't apply DNS configuration coming from non-active devices (rh #1405431)
    - vlan: inherit default MTU from parent device (rh #1414186)
    - bond: fix crash when reading from sysfs 'NULL' (rh #1420244)
    - build: rebuild with correct hardening flags (rh #1420771)
    - platform: downgrade warning about failure to detect kernel support to debug (rh #1421019)
    - dns: change behavior for 'rc-manager=symlink' to preserve '/etc/resolv.conf' as file (rh #1367551)
    - libnm: order the property updates (rh #1417292)

    NetworkManager-libreswan
    [1.2.4-2]
    - po: update Japanese translation (rh #1383163)

    libnl3
    [3.2.28-4]
    * lib: check for integer overflow in nl_reserve() (rh#1440788, rh#1442723)

    network-manager-applet
    [1.8.0-3]
    - editor: fix crash when destroying 802.1x page (rh #1458567)

    [1.8.0-2]
    - po: update Japanese translation (rh #1379642)

    [1.8.0-1]
    - Update to 1.8.0 release (rh #1441621)

    [1.8.0-0.1.git20170326.f260f8a]
    - Update to network-manager-applet 1.8 snapshot
    - c-e: add missing mnemonic characters to buttons (rh #1434317)
    - c-e: fix handling of devices without permanent MAC address in devices combo box (rh #1380424)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-2299.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0553");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-ppp");
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

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'NetworkManager-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-adsl-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-bluetooth-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-server-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-dispatcher-routing-rules-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-devel-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libreswan-1.2.4-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-libreswan-gnome-1.2.4-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-ppp-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-team-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.8.0-9.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libnl3-3.2.28-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-cli-3.2.28-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-devel-3.2.28-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-doc-3.2.28-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-1.8.0-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-devel-1.8.0-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-1.8.0-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-devel-1.8.0-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'network-manager-applet-1.8.0-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nm-connection-editor-1.8.0-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-glib-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-devel-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libreswan-1.2.4-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-libreswan-gnome-1.2.4-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-ppp-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-team-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.8.0-9.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libnl3-3.2.28-4.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-cli-3.2.28-4.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-devel-3.2.28-4.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-doc-3.2.28-4.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-1.8.0-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-devel-1.8.0-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-1.8.0-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-devel-1.8.0-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'network-manager-applet-1.8.0-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nm-connection-editor-1.8.0-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-adsl-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-bluetooth-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-server-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-dispatcher-routing-rules-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-glib-devel-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libreswan-1.2.4-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-libreswan-gnome-1.2.4-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'NetworkManager-ppp-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-team-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.8.0-9.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libnl3-3.2.28-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-cli-3.2.28-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-devel-3.2.28-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnl3-doc-3.2.28-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-1.8.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnm-gtk-devel-1.8.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-1.8.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnma-devel-1.8.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'network-manager-applet-1.8.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nm-connection-editor-1.8.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
