#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-9317.
##

include('compat.inc');

if (description)
{
  script_id(211547);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2024-6501");

  script_name(english:"Oracle Linux 9 : NetworkManager (ELSA-2024-9317)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2024-9317 advisory.

    [1.48.10-2.0.1]
    - disable MPTCP handling by default [Orabug: 34801142]
    - add connectivity check via Oracle servers [Orabug: 32051972]

    [1:1.48.10-2]
    - cloud-setup: Allow bigger restart bursts (RHEL-56740)
    - cloud-setup: Fix Azure swap of primary and secondary IP addresses (RHEL-56387)

    [1:1.48.10-1]
    - Unblock the autoconnect for children when parent is available (RHEL-46904)
    - Fix crash produced by malformed LLDP package when debug logging (RHEL-46199)
    - Support reapplying bridge-port VLANs (RHEL-26750)
    - Add small backoff time before resync (RHEL-29902)

    [1:1.46.8-1]
    - Stop writing offensive terms into keyfiles (RHEL-52597)
    - Remove offensive words (RHEL-33368)
    - Fix cloned-mac-address race condition with DHCP on ovs-interfaces (RHEL-49796)

    [1:1.48.6-1]
    - Wait until link is ready before activating for ovs-interface (RHEL-49796)
    - Fix rollback on OVS checkpoint (RHEL-31972)
    - Assert that the auto-activate list is empty on dispose (RHEL-44345)

    [1:1.48.4-1]
    - Update to 1.48.4 release
    - Support matching a OVS system interface by MAC address (RHEL-34617)
    - When looking up the system hostname from the reverse DNS lookup of
      addresses configured on interfaces, NetworkManager now takes into
      account the content of /etc/hosts (RHEL-33435)

    [1:1.48.2-2]
    - Add ipcalc as dependency of NetworkManager-dispatcher-routing-rules (RHEL-36648)

    [1:1.48.2-1]
    - Update to 1.48.2 release
    - Save connection timestamps when shutting down (RHEL-35539)
    - Fix regression with OpenVPN dynamic challenge (RHEL-43720)

    [1:1.48.0-1]
    - Upgrade to 1.48.0 release

    [1:1.47.91-1]
    - Upgrade to 1.47.91 (rc2)

    [1:1.47.90-1]
    - Upgrade to 1.47.90 (rc1)

    [1:1.47.5-1]
    - Fix a crash during shutdown (RHEL-29856)

    [1:1.47.4-1]
    - Fix LLDP support for interfaces attached to OVS bridges. (RHEL-1418)
    - Fix NMCI crashes on ovs_mtu and bond tests. (RHEL-30348)

    [1.47.3-2]
    - Rebuild for CI gating

    [1.47.3-1]
    - Upgrade to 1.47.3 release (development)
    - Support rollback on global DNS (RHEL-23446)
    - Support VLAN over OVS interface which holds the same name as OVS bridge (RHEL-26753)

    * Fri Mar 08 2024 Inigo Huguet <ihuguet@redhat.com>
    - Update to 1.47.2 release (development)
    - Support sending DHCPRELEASE (RHEL-17310)

    * Thu Feb 22 2024 Stanislas FAYE <sfaye@redhat.com>
    - Update to 1.46.0 release
    - Fix DHCPv4 lease can't be renewed after it expires (RHEL-24127)
    - Support the MACsec offload mode (RHEL-24337)
    - Support creating generic devices via external 'device-handler' dispatcher (RHEL-1567)
    - Support changing the eswitch mode (RHEL-1441)

    [1.45.91-1]
    - Update to 1.45.91 release (release candidate)
    - Support changing the DSCP header field for DHCP packets, and set the default to CS0 (RHEL-16040)
    - Deprecate connection.autoconnect-slaves in favour of autoconnect-ports (RHEL-17621)
    - Don't reset bridge's PVID in reapply if it didn't change (RHEL-21576)

    [1.45.90-1]
    - Update to 1.45.90 release (release candidate)
    - Deprecate and Replace connection.slave-type in libnm-core and libnm (RHEL-17620)
    - [RFE] Support assigning IPv4 static route to interface without IPv4 address (RHEL-5098)

    [1.45.10-1]
    - Update to 1.45.10 (development)
    - Deprecate and Replace connection.master in libnm-core and libnm (RHEL-17619)

    [1.45.9-1]
    - Update to 1.45.9 (development)
    - Add support for PRP/HSR interface (RHEL-5852)
    - Drop support for the 'slaves-order' option in NetworkManager.conf (RHEL-19437)
    - Return error when setting invalid IP addresses or properties via D-Bus (RHEL-19315)
    - Fix extra route being created besides ECMP route (RHEL-1682)

    [1.45.8-1]
    - Update to 1.45.8 (development)
    - Introduce 'stable-ssid' option for wifi.cloned-mac-address property (RHEL-16470)

    [1.45.7-1]
    - Update to 1.45.7 release (development)
    - Migrate to SPDX license

    [1.45.6-1]
    - Update to 1.45.6 release (development)
    - Fix ovs activation with netdev datapath and cloned MAC (RHEL-5886)

    [1.45.5-1]
    - Update to 1.45.5 release (development)
    - Various fixes to Duplicate Address Detection (DAD) (RHEL-1581, RHEL-1411)
    - New option to avoid sending the DHCPv4 client-identifier (RHEL-1469)
    - Support setting channels in ethtool options (RHEL-1471)

    [1.45.4-1]
    - Update to 1.45.4 release (development)
    - Add 'dns-change' dispatcher event (RHEL-1671)

    [1.45.3-1]
    - Update to 1.45.3 release (development)
    - Improve explanation of the format and routes properties in keyfile man page (RHEL-1407)
    - Improve nm-settings-nmcli manpage to show format and valid values of properties (RHEL-2465)
    - Honor the autoactivate priority for port connections (RHEL-2202)
    - Properly document valid values for ip-tunnel properties (RHEL-1459)

    [1.45.2-1]
    - update to 1.45.2 release (development)

    [1.44.0-4]
    - Rebuild for RHEL 9.4

    [1:1.44.0-3]
    - checkpoint: Fix segfault crash when rollback (rhel-1526)

    [1:1.44.0-2]
    - manager: ensure device is exported on D-Bus in authentication request (rh #2210271)

    [1:1.44.0-1]
    - update to 1.44.0 release
    - nmcli: add nmcli version mismatch warning (rh #2173196)
    - checkpoint: preserve devices that were removed and readded (rh #2177590)

    [1:1.43.90-1]
    - update to 1.43.90 release (release candidate)
    - manager: allow controller activation if device is deactivating (rh #2125615)
    - assume: change IPv6 method from 'ignore' and 'disabled' into 'auto' for loopback device (rh #2207878)
    - device: delete software device when lose carrier and is controller (rh #2224479)
    - core: better handle ignore-carrier=no for bond/bridge/team devices (rh #2180363)

    [1:1.43.11-1]
    - update to 1.43.11 release (development)
    - fix assertion about missing ifindex when resetting MAC (rh #2215022)
    - fix wrong order of entries in resolv.conf after reconnect (rh #2218448)
    - do not fail activation when SR-IOV VF parameters can't be applied (rh #2210164)
    - warn that the ifcfg-rh plugin is deprecated (rh #2190375)

    [1:1.43.10-1]
    - Update to 1.43.10 release (development)
    - fix reading infiniband p-key from ifcfg files (rh #2209974)
    - improve autoconnect when selecting controller (rh #2121451)
    - fix managing devices after network reconnect (rh #2149012)
    - better handle ignore-carrier for bond/bridge/team (rh #2180363)
    - cloud-setup: block wait-online while configuration is ongoing (rh #2151040)
    - cloud-setup: avoid leaving half configured system (rh #2207812)
    - cloud-setup: log warning when no provider detected (rh #2214880)
    - cloud-setup: fix RPM description (rh #2214491)

    [1:1.43.9-1]
    - Update to 1.43.9 release (development)
    - improve autoconnect logic for port/controller configurations (rh #2121451)
    - fix handling external devices during network off/on (rh #2149012)

    [1:1.43.8-1]
    - Update to 1.43.8 release (development)
    - ipv6ll: don't regenerate the address when it's removed externally (rh #2196441)

    [1:1.43.7-1]
    - Update to 1.43.7 release (development)
    - bond: support port priorities (rh #2152304)
    - ovs: fix autoconnect race (rh #2152864)

    [1:1.43.6-1]
    - Update to 1.43.6 release (development)
    - fix assertion failure when renewing DHCP lease (rh #2179890)
    - emit the dhcp-change dispatcher script event on lease renewal (rh #2179537)
    - ensure the NetworkManager is restarted when dbus is restarted (rh #2161915)
    - add support for the 'no-aaaa' resolv.conf option (rh #2176137)
    -

    [1:1.43.5-1]
    - Update to 1.43.5 release (development)
    - cloud-init/ec2: use right HTTP method for IMDSv2 (rh #2179718)
    - core: request a bus name only when dbus objects are present (rh #2175919)
    - core: fix autoconnect retry count tracking (rh #2174353)
    - core: fix retry on netlink socket buffer exhaustion (rh #2169512)
    - ovs: fix a race condition on port detachment (rh #2054933)

    [1:1.43.4-1]
    - Update to 1.43.4 release (development)
    - core: fix handling of IPv4 prefsrc routes with ACD (rh #2046293)
    - core: don't configure static routes without addresses (rh #2102212)
    - core: fix race activating VLAN devices (rh #2155991)

    [1:1.43.3-1]
    - Update to an early 1.44 snapshot
    - cloud-setup: add IDMSv2 support (rh #2151986)
    - core: add [link] setting (rh #2158328)
    - dhcp: expose client ID, DUID and IAID that have been used (rh #2169869)
    - ovs: ensure device has a proper MAC address once we start dhcp (rh #2168477)
    - team: fix assumption of team port management (rh #2092215)

    [1:1.42.2-1]
    - Update to 1.42.2 release
    - fix hostname lookup from IPv6 address (rh #2167816)
    - add new connection property to remove the autogenerated local route rule (rh #2167805)
    - fix race condition while setting the MAC of a OVS interface (rh #2168477)
    - expose the DHCP IAID in the lease information (rh #2169869)

    [1:1.42.0-1]
    - Update to 1.42.0 release

    [1:1.41.91-1]
    - Update to 1.41.91 release (release candidate)
    - core: retry if a rtnetlink socket runs out of buffer space (rh #2154350)
    - dns: allow changing resolv.conf options alone via global-dns (rh #2019306)

    [1:1.41.90-1]
    - Update to 1.41.90 release (release candidate)
    - l3cfg: schedule an update after every commit-type/config-data register/unregister (rh #2158394)
    - all: add support for ovs-dpdk n-rxq-desc and n-txq-desc (rh #2156385)
    - core: fix consistency for internal cache for IPv6 routes (rh #2060684)

    [1:1.41.8-1]
    - Update to 1.41.8 release (development)
    - core: add support for equal-cost multi-path (ECMP) routes (rh #2081302)
    - device: preserve the DHCP lease during reapply (rh #2117352)
    - ovs: add support for 'other_config' settings (rh #2151455)

    [1:1.41.7-2]
    - core: avoid infinite autoconnect with multi-connect profiles (rh #2150000)

    [1:1.41.7-1]
    - Update to 1.41.7 release (development)
    - macsec: fix tracking of parent ifindex (rh #2122564)
    - cloud-setup: set preserve-external-ip flag during reapply (rh #2132754)

    [1:1.41.6-1]
    - Update to 1.41.6 release (development)
    - add support for loopback interfaces (rh #2073512)
    - ovs: support VLAN trunks for OVS port (rh #2111959)

    [1:1.41.5-1]
    - Update to 1.41.5 release (development)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-9317.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:5:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:5:baseos_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-cloud-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-config-connectivity-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-initscripts-updown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-wwan");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'NetworkManager-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-adsl-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-bluetooth-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-cloud-setup-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-connectivity-oracle-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-server-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-dispatcher-routing-rules-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-initscripts-updown-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-ovs-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-ppp-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-team-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.48.10-2.0.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-ovs-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-ppp-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-team-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.48.10-2.0.1.el9_5', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-adsl-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-bluetooth-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-cloud-setup-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-connectivity-oracle-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-config-server-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-dispatcher-routing-rules-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-initscripts-updown-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-libnm-devel-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-ovs-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-ppp-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-team-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-tui-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wifi-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'NetworkManager-wwan-1.48.10-2.0.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
