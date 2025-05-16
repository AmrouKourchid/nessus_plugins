#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3113 and 
# Oracle Linux Security Advisory ELSA-2018-3113 respectively.
#

include('compat.inc');

if (description)
{
  script_id(118773);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2018-6764");
  script_xref(name:"RHSA", value:"2018:3113");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2018-3113)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2018-3113 advisory.

    [4.5.0-10]
    - conf: correct false boot order error during domain parse (rhbz#1601318)

    [4.5.0-9]
    - virDomainDefCompatibleDevice: Relax alias change check (rhbz#1621910)
    - virDomainDetachDeviceFlags: Clarify update semantics (rhbz#1621910)
    - virDomainNetDefCheckABIStability: Check for MTU change too (rhbz#1623157)

    [4.5.0-8]
    - storage: Add --shrink to qemu-img command when shrinking vol (rhbz#1613746)
    - access: Fix nwfilter-binding ACL access API name generation (rhbz#1611320)
    - qemu: mdev: Use vfio-pci 'display' property only with vfio-pci mdevs (rhbz#1624735)

    [4.5.0-7]
    - qemu_migration: Avoid writing to freed memory (rhbz#1593137)
    - qemu: hotplug: Fix asynchronous unplug of 'shmem' (rhbz#1618622)
    - tests: rename hugepages to hugepages-default (rhbz#1591235)
    - tests: extract hugepages-numa-default-dimm out of hugepages-numa (rhbz#1591235)
    - tests: rename hugepages-numa into hugepages-numa-default (rhbz#1591235)
    - tests: remove unnecessary XML elements from hugepages-numa-default (rhbz#1591235)
    - tests: extract pages-discard out of hugepages-pages (rhbz#1591235)
    - tests: rename hugepages-pages into hugepages-numa-nodeset (rhbz#1591235)
    - tests: rename hugepages-pages2 into hugepages-numa-default-2M (rhbz#1591235)
    - tests: extract pages-discard-hugepages out of hugepages-pages3 (rhbz#1591235)
    - tests: rename hugepages-pages3 into hugepages-numa-nodeset-part (rhbz#1591235)
    - tests: rename hugepages-pages4 into hugepages-numa-nodeset-nonexist (rhbz#1591235)
    - tests: rename hugepages-pages5 into hugepages-default-2M (rhbz#1591235)
    - tests: rename hugepages-pages6 into hugepages-default-system-size (rhbz#1591235)
    - tests: rename hugepages-pages7 into pages-dimm-discard (rhbz#1591235)
    - tests: rename hugepages-pages8 into hugepages-nodeset-nonexist (rhbz#1591235)
    - tests: introduce hugepages-default-1G-nodeset-2M (rhbz#1591235)
    - tests: introduce hugepages-nodeset (rhbz#1591235)
    - conf: Move hugepage XML validation check out of qemu_command (rhbz#1591235)
    - conf: Move hugepages validation out of XML parser (rhbz#1591235)
    - conf: Introduce virDomainDefPostParseMemtune (rhbz#1591235)
    - tests: sev: Test launch-security with specific QEMU version (rhbz#1612009)
    - qemu: Fix probing of AMD SEV support (rhbz#1612009)
    - qemu: caps: Format SEV platform data into qemuCaps cache (rhbz#1612009)

    [4.5.0-6]
    - qemu: Exempt video model 'none' from getting a PCI address on Q35 (rhbz#1609087)
    - conf: Fix a error msg typo in virDomainVideoDefValidate (rhbz#1607825)

    [4.5.0-5]
    - esx storage: Fix typo lsilogic -> lsiLogic (rhbz#1571759)
    - networkGetDHCPLeases: Dont always report error if unable to read leases file (rhbz#1600468)
    - nwfilter: Resolve SEGV for NWFilter Snoop processing (rhbz#1599973)
    - qemu: Remove unused bypassSecurityDriver from qemuOpenFileAs (rhbz#1589115)
    - qemuDomainSaveMemory: Dont enforce dynamicOwnership (rhbz#1589115)
    - domain_nwfilter: Return early if net has no name in virDomainConfNWFilterTeardownImpl (rhbz#1607831)
    - examples: Add clean-traffic-gateway into nwfilters (rhbz#1603115)

    [4.5.0-4]
    - qemu: hotplug: dont overwrite error message in qemuDomainAttachNetDevice (rhbz#1598311)
    - qemu: hotplug: report error when changing rom enabled attr for net iface (rhbz#1599513)
    - qemu: Fix setting global_period cputune element (rhbz#1600427)
    - tests: qemucaps: Add test data for upcoming qemu 3.0.0 (rhbz#1475770)
    - qemu: capabilities: Add capability for werror/rerror for 'usb-device' frontend (rhbz#1475770)
    - qemu: command: Move graphics iteration to its own function (rhbz#1475770)
    - qemu: address: Handle all the video devices within a single loop (rhbz#1475770)
    - conf: Introduce virDomainVideoDefClear helper (rhbz#1475770)
    - conf: Introduce virDomainDefPostParseVideo helper (rhbz#1475770)
    - qemu: validate: Enforce compile time switch type checking for videos (rhbz#1475770)
    - tests: Add capabilities data for QEMU 2.11 x86_64 (rhbz#1475770)
    - tests: Update capabilities data for QEMU 3.0.0 x86_64 (rhbz#1475770)
    - qemu: qemuBuildHostdevCommandLine: Use a helper variable mdevsrc (rhbz#1475770)
    - qemu: caps: Introduce a capability for egl-headless (rhbz#1475770)
    - qemu: Introduce a new graphics display type 'headless' (rhbz#1475770)
    - qemu: caps: Add vfio-pci.display capability (rhbz#1475770)
    - conf: Introduce virDomainGraphicsDefHasOpenGL helper (rhbz#1475770)
    - conf: Replace 'error' with 'cleanup' in virDomainHostdevDefParseXMLSubsys (rhbz#1475770)
    - conf: Introduce new <hostdev> attribute 'display' (rhbz#1475770)
    - qemu: command: Enable formatting vfio-pci.display option onto cmdline (rhbz#1475770)
    - docs: Rephrase the mediated devices hostdev section a bit (rhbz#1475770)
    - conf: Introduce new video type 'none' (rhbz#1475770)
    - virt-xml-validate: Add schema for nwfilterbinding (rhbz#1600330)
    - tools: Fix typo generating adapter_wwpn field (rhbz#1601377)
    - src: Fix memory leak in virNWFilterBindingDispose (rhbz#1603025)

    [4.5.0-3]
    - qemu: hotplug: Do not try to add secret object for TLS if it does not exist (rhbz#1598015)
    - qemu: monitor: Make qemuMonitorAddObject more robust against programming errors (rhbz#1598015)
    - spec: Explicitly require matching libvirt-libs (rhbz#1600122)
    - virDomainConfNWFilterInstantiate: initialize @xml to avoid random crash (rhbz#1599545)
    - qemuProcessStartPRDaemonHook: Try to set NS iff domain was started with one (rhbz#1470007)
    - qemuDomainValidateStorageSource: Relax PR validation (rhbz#1470007)
    - virStoragePRDefFormat: Suppress path formatting for migratable XML (rhbz#1470007)
    - qemu: Wire up PR_MANAGER_STATUS_CHANGED event (rhbz#1470007)
    - qemu_monitor: Introduce qemuMonitorJSONGetPRManagerInfo (rhbz#1470007)
    - qemu: Fetch pr-helper process info on reconnect (rhbz#1470007)
    - qemu: Fix ATTRIBUTE_NONNULL for qemuMonitorAddObject (rhbz#1598015)
    - virsh.pod: Fix a command name typo in nwfilter-binding-undefine (rhbz#1600329)
    - docs: schema: Add missing <alias> to vsock device (rhbz#1600345)
    - virnetdevtap: Dont crash on !ifname in virNetDevTapInterfaceStats (rhbz#1595184)

    [4.5.0-2]
    - qemu: Add capability for the HTM pSeries feature (rhbz#1525599)
    - conf: Parse and format the HTM pSeries feature (rhbz#1525599)
    - qemu: Format the HTM pSeries feature (rhbz#1525599)
    - qemu: hotplug: Dont access srcPriv when its not allocated (rhbz#1597550)
    - qemuDomainNestedJobAllowed: Allow QEMU_JOB_NONE (rhbz#1598084)
    - src: Mention DEVICE_REMOVAL_FAILED event in virDomainDetachDeviceAlias docs (rhbz#1598087)
    - virsh.pod: Drop --persistent for detach-device-alias (rhbz#1598087)
    - qemu: dont use chardev FD passing with standalone args (rhbz#1598281)
    - qemu: remove chardevStdioLogd param from vhostuser code path (rhbz#1597940)
    - qemu: consolidate parameters of qemuBuildChrChardevStr into flags (rhbz#1597940)
    - qemu: dont use chardev FD passing for vhostuser backend (rhbz#1597940)
    - qemu: fix UNIX socket chardevs operating in client mode (rhbz#1598440)
    - qemuDomainDeviceDefValidateNetwork: Check for range only if IP prefix set (rhbz#1515533)

    [4.5.0-1]
    - Rebased to libvirt-4.5.0 (rhbz#1563169)
    - The rebase also fixes the following bugs:
        rhbz#1291851, rhbz#1393106, rhbz#1468422, rhbz#1469338, rhbz#1526382
        rhbz#1529059, rhbz#1541921, rhbz#1544869, rhbz#1552092, rhbz#1568407
        rhbz#1583623, rhbz#1584091, rhbz#1585108, rhbz#1586027, rhbz#1588295
        rhbz#1588336, rhbz#1589730, rhbz#1590214, rhbz#1591017, rhbz#1591561
        rhbz#1591628, rhbz#1591645, rhbz#1593549

    [4.4.0-2]
    - build: Dont install sysconfig files as scripts (rhbz#1563169)

    [4.4.0-1]
    - Rebased to libvirt-4.4.0 (rhbz#1563169)
    - The rebase also fixes the following bugs:
        rhbz#1149445, rhbz#1291851, rhbz#1300772, rhbz#1400475, rhbz#1456165
        rhbz#1470007, rhbz#1480668, rhbz#1534418, rhbz#1549531, rhbz#1559284
        rhbz#1559835, rhbz#1560946, rhbz#1566416, rhbz#1569861, rhbz#1572491
        rhbz#1574089, rhbz#1576916, rhbz#1583484, rhbz#1583927, rhbz#1584071
        rhbz#1584073

    [4.3.0-1]
    - Rebased to libvirt-4.3.0 (rhbz#1563169)
    - The rebase also fixes the following bugs:
        rhbz#1509870, rhbz#1530451, rhbz#1577920, rhbz#1283700, rhbz#1425757
        rhbz#1448149, rhbz#1454709, rhbz#1502754, rhbz#1507737, rhbz#1519130
        rhbz#1519146, rhbz#1522706, rhbz#1523564, rhbz#1524399, rhbz#1525496
        rhbz#1527740, rhbz#1550980, rhbz#916061, rhbz#1494454, rhbz#1515533
        rhbz#1532542, rhbz#1538570, rhbz#1544325, rhbz#1544659, rhbz#1546971
        rhbz#1347550, rhbz#1367238, rhbz#1483816, rhbz#1543775, rhbz#1551000
        rhbz#1552127, rhbz#1553075, rhbz#1553085, rhbz#1554876, rhbz#1556828
        rhbz#1558317, rhbz#1425058, rhbz#1490158, rhbz#1492597, rhbz#1520821
        rhbz#1529256, rhbz#1547250, rhbz#1557769, rhbz#1560917, rhbz#1560976
        rhbz#1568148, rhbz#1569678, rhbz#1576464

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-3113.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libvirt-client-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-lxc-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-lxc-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-login-shell-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-4.5.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-admin-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-bash-completion-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-lxc-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-core-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-disk-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-gluster-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-iscsi-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-logical-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-mpath-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-rbd-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-scsi-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-lxc-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-libs-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-login-shell-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-4.5.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt / libvirt-admin / libvirt-bash-completion / etc');
}
