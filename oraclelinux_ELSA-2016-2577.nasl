#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2577 and 
# Oracle Linux Security Advisory ELSA-2016-2577 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94700);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2015-5160", "CVE-2015-5313", "CVE-2016-5008");
  script_xref(name:"RHSA", value:"2016:2577");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2016-2577)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2016-2577 advisory.

    [2.0.0-10]
    - virtlogd: Don't stop or restart along with libvirtd (rhbz#1372576)

    [2.0.0-9]
    - Add helper for removing transient definition (rhbz#1368774)
    - qemu: Remove stale transient def when migration fails (rhbz#1368774)
    - qemu: Don't use query-migrate on destination (rhbz#1374613)
    - conf: allow hotplugging 'legacy PCI' device to manually addressed PCIe slot (rhbz#1337490)
    - conf: Add support for virtio-net.rx_queue_size (rhbz#1366989)
    - qemu_capabilities: Introduce virtio-net-*.rx_queue_size (rhbz#1366989)
    - qemu: Implement virtio-net rx_queue_size (rhbz#1366989)
    - audit: Audit information about shmem devices (rhbz#1218603)
    - qemu: monitor: Use a more obvious iterator name (rhbz#1375783)
    - qemu: monitor: qemuMonitorGetCPUInfoHotplug: Add iterator 'anycpu' (rhbz#1375783)
    - qemu: monitor: Add vcpu state information to monitor data (rhbz#1375783)
    - qemu: domain: Don't infer vcpu state (rhbz#1375783)

    [2.0.0-8]
    - util: storage: Properly set protocol type when parsing gluster json string (rhbz#1372251)
    - conf: Add IOThread quota and period scheduler/cputune defs (rhbz#1356937)
    - qemu: Add support to get/set IOThread period and quota cgroup values (rhbz#1356937)
    - network: new network forward mode 'open' (rhbz#846810)
    - virtlogd.socket: Tie lifecycle to libvirtd.service (rhbz#1372576)
    - cpu_x86: Fix minimum match custom CPUs on hosts with CMT (rhbz#1365500)
    - qemu: cgroup: Extract temporary relaxing of cgroup setting for vcpu hotplug (rhbz#1097930)
    - qemu: process: Fix start with unpluggable vcpus with NUMA pinning (rhbz#1097930)

    [2.0.0-7]
    - qemu: caps: Always assume QEMU_CAPS_SMP_TOPOLOGY (rhbz#1097930)
    - conf: Extract code formatting vCPU info (rhbz#1097930)
    - conf: Rename virDomainVcpuInfoPtr to virDomainVcpuDefPtr (rhbz#1097930)
    - conf: Don't report errors from virDomainDefGetVcpu (rhbz#1097930)
    - tests: qemuxml2xml: Format status XML header dynamically (rhbz#1097930)
    - conf: convert def->vcpus to a array of pointers (rhbz#1097930)
    - conf: Add private data for virDomainVcpuDef (rhbz#1097930)
    - qemu: domain: Add vcpu private data structure (rhbz#1097930)
    - qemu: domain: Extract formating and parsing of vCPU thread ids (rhbz#1097930)
    - qemu: Add cpu ID to the vCPU pid list in the status XML (rhbz#1097930)
    - qemu: Store vCPU thread ids in vcpu private data objects (rhbz#1097930)
    - Fix logic in qemuDomainObjPrivateXMLParseVcpu (rhbz#1097930)
    - qemu: Add qemuProcessSetupPid() and use it in qemuProcessSetupIOThread() (rhbz#1097930)
    - qemu: Use qemuProcessSetupPid() in qemuProcessSetupEmulator() (rhbz#1097930)
    - qemu: Use qemuProcessSetupPid() in qemuProcessSetupVcpu() (rhbz#1097930)
    - qemuBuildCpuCommandLine: Don't leak @buf (rhbz#1097930)
    - conf: Make really sure we don't access non-existing vCPUs (rhbz#1097930)
    - conf: Make really sure we don't access non-existing vCPUs again (rhbz#1097930)
    - qemu: capabilities: Drop unused function virQEMUCapsGetMachineTypes (rhbz#1097930)
    - qemu: caps: Sanitize storage of machine type related data (rhbz#1097930)
    - qemu: cap: Refactor access to array in virQEMUCapsProbeQMPMachineTypes (rhbz#1097930)
    - qemu: monitor: Add monitor API for device_add supporting JSON objects (rhbz#1097930)
    - qemu: monitor: Add do-while block to QEMU_CHECK_MONITOR_FULL (rhbz#1097930)
    - qemu: Improve error message in virDomainGetVcpus (rhbz#1097930)
    - qemu: domain: Rename qemuDomainDetectVcpuPids to qemuDomainRefreshVcpuInfo (rhbz#1097930)
    - qemu: monitor: Rename qemuMonitor(JSON|Text)GetCPUInfo (rhbz#1097930)
    - qemu: domain: Improve vCPU data checking in qemuDomainRefreshVcpu (rhbz#1097930)
    - qemu: domain: Simplify return values of qemuDomainRefreshVcpuInfo (rhbz#1097930)
    - internal: Introduce macro for stealing pointers (rhbz#1097930)
    - tests: qemucapabilities: Add data for qemu 2.7.0 (rhbz#1097930)
    - qemu: setcpus: Report better errors (rhbz#1097930)
    - qemu: setvcpus: Extract setting of maximum vcpu count (rhbz#1097930)
    - qemu: driver: Extract setting of live vcpu count (rhbz#1097930)
    - qemu: driver: Split out regular vcpu hotplug code into a function (rhbz#1097930)
    - conf: Provide error on undefined vcpusched entry (rhbz#1097930)
    - qemu: monitor: Return structures from qemuMonitorGetCPUInfo (rhbz#1097930)
    - qemu: monitor: Return struct from qemuMonitor(Text|Json)QueryCPUs (rhbz#1097930)
    - qemu: Add capability for query-hotpluggable-cpus command (rhbz#1097930)
    - qemu: Forbid config when topology based cpu count doesn't match the config (rhbz#1097930)
    - qemu: capabilities: Extract availability of new cpu hotplug for machine types (rhbz#1097930)
    - qemu: monitor: Extract QOM path from query-cpus reply (rhbz#1097930)
    - qemu: monitor: Add support for calling query-hotpluggable-cpus (rhbz#1097930)
    - qemu: monitor: Add algorithm for combining query-(hotpluggable-)-cpus data (rhbz#1097930)
    - tests: Add test infrastructure for qemuMonitorGetCPUInfo (rhbz#1097930)
    - tests: cpu-hotplug: Add data for x86 hotplug with 11+ vcpus (rhbz#1097930)
    - tests: cpu-hotplug: Add data for ppc64 platform including hotplug (rhbz#1097930)
    - tests: cpu-hotplug: Add data for ppc64 out-of-order hotplug (rhbz#1097930)
    - tests: cpu-hotplug: Add data for ppc64 without threads enabled (rhbz#1097930)
    - qemu: domain: Extract cpu-hotplug related data (rhbz#1097930)
    - qemu: domain: Prepare for VCPUs vanishing while libvirt is not running (rhbz#1097930)
    - util: Extract and rename qemuDomainDelCgroupForThread to virCgroupDelThread (rhbz#1097930)
    - conf: Add XML for individual vCPU hotplug (rhbz#1097930)
    - qemu: migration: Prepare for non-contiguous vcpu configurations (rhbz#1097930)
    - qemu: command: Add helper to convert vcpu definition to JSON props (rhbz#1097930)
    - qemu: process: Copy final vcpu order information into the vcpu definition (rhbz#1097930)
    - qemu: command: Add support for sparse vcpu topologies (rhbz#1097930)
    - qemu: Use modern vcpu hotplug approach if possible (rhbz#1097930)
    - qemu: hotplug: Allow marking unplugged devices by alias (rhbz#1097930)
    - qemu: hotplug: Add support for VCPU unplug (rhbz#1224341)
    - virsh: vcpuinfo: Report vcpu number from the structure rather than it's position (rhbz#1097930)
    - qemu: driver: Fix qemuDomainHelperGetVcpus for sparse vcpu topologies (rhbz#1097930)
    - doc: clarify documentation for vcpu order (rhbz#1097930)
    - conf: Don't validate vcpu count in XML parser (rhbz#1097930)
    - qemu: driver: Validate configuration when setting maximum vcpu count (rhbz#1370066)
    - conf: Fix build with picky GCC (rhbz#1097930)

    [2.0.0-6]
    - qemu_command: don't modify heads for graphics device (rhbz#1366119)
    - virsh: Fix core for cmdSecretGetValue (rhbz#1366611)
    - conf: report an error message for non-existing USB hubs (rhbz#1367130)
    - conf: free the ports array of a USB hub (rhbz#1366097)
    - utils: storage: Fix JSON field name for uri based storage (rhbz#1367260)
    - qemu: Adjust the cur_ballon on coldplug/unplug of dimms (rhbz#1220702)
    - conf: Provide error on undefined iothreadsched entry (rhbz#1366484)
    - qemu: Fix the command line generation for rbd auth using aes secrets (rhbz#1182074)
    - qemu: Fix crash hot plugging luks volume (rhbz#1367259)
    - Revert 'admin: Fix the default uri for session daemon to libvirtd:///session' (rhbz#1367269)
    - libvirt: convert to typesafe virConf accessors (rhbz#1367269)
    - admin: Fix default uri config option name s/admin_uri_default/uri_default (rhbz#1367269)
    - virt-admin: Properly fix the default session daemon URI to admin server (rhbz#1367269)

    [2.0.0-5]
    - qemu: Fix domain state after reset (rhbz#1269575)
    - rpc: virnetserver: Rename ClientSetProcessingControls to ClientSetLimits (rhbz#1357776)
    - rpc: virnetserver: Move virNetServerCheckLimits which is static up in the file (rhbz#1357776)
    - rpc: virnetserver: Add code to CheckLimits to handle suspending of services (rhbz#1357776)
    - admin: rpc: virnetserver: Fix updating of the client limits (rhbz#1357776)
    - rpc: virnetserver: Remove dead code checking the client limits (rhbz#1357776)
    - storage: Fix a NULL ptr dereference in virStorageBackendCreateQemuImg (rhbz#1363636)
    - qemu: Introduce qemuAliasFromHostdev (rhbz#1289391)
    - qemu: Use the hostdev alias in qemuDomainAttachHostSCSIDevice error path (rhbz#1289391)
    - storage: Don't remove the pool for buildPool failure in storagePoolCreate (rhbz#1362349)
    - lxcDomainCreateXMLWithFiles: Avoid crash (rhbz#1363773)
    - admin: Fix the default uri for session daemon to libvirtd:///session (rhbz#1356858)
    - docs: Distribute subsite.xsl (rhbz#1365004)
    - qemuBuildMachineCommandLine: Follow our pattern (rhbz#1304483)
    - Introduce SMM feature (rhbz#1304483)
    - Introduce @secure attribute to os loader element (rhbz#1304483)
    - qemu: Enable secure boot (rhbz#1304483)
    - qemu: Advertise OVMF_CODE.secboot.fd (rhbz#1304483)
    - tests: Fix broken build (rhbz#1304483)
    - cpu_x86: Introduce x86FeatureIsMigratable (rhbz#1365500)
    - cpu_x86: Properly drop non-migratable features (rhbz#1365500)
    - tests: Add a test for host-model CPU with CMT feature (rhbz#1365500)
    - cpu_x86: Fix host-model CPUs on hosts with CMT (rhbz#1365500)
    - virt-admin: Fix the error when an invalid URI has been provided (rhbz#1365903)
    - conf: improve error log when PCI devices don't match requested controller (rhbz#1363627)
    - conf: don't allow connecting upstream-port directly to pce-expander-bus (rhbz#1361172)
    - conf: restrict where dmi-to-pci-bridge can be connected (rhbz#1363648)
    - conf: restrict expander buses to connect only to a root bus (rhbz#1358712)
    - virNetDevMacVLanCreateWithVPortProfile: Don't mask virNetDevMacVLanTapOpen error (rhbz#1240439)

    [2.0.0-4]
    - qemu: hotplug: fix changeable media ejection (rhbz#1359071)
    - lxc: Don't crash by forgetting to ref transient domains (rhbz#1351057)
    - Introduce <iommu> device (rhbz#1235581)
    - Add QEMU_CAPS_DEVICE_INTEL_IOMMU (rhbz#1235581)
    - qemu: format intel-iommu on the command line (rhbz#1235581)
    - qemu_monitor_json: add support to search QOM device path by device alias (rhbz#1358728)
    - hvsupport: Introduce parseSymsFile (rhbz#1286679)
    - hvsupport: use a regex instead of XML::XPath (rhbz#1286679)
    - hvsupport: construct the group regex upfront (rhbz#1286679)
    - hvsupport: skip non-matching lines early (rhbz#1286679)
    - virconf: Fix config file path construction (rhbz#1357364)
    - virDomainHostdevDefFree: Don't leak privateData (rhbz#1357346)
    - virt-admin: Output srv-threadpool-info data as unsigned int rather than signed (rhbz#1356769)
    - util: Introduce virISCSINodeNew (rhbz#1356436)
    - iscsi: Establish connection to target via static target login (rhbz#1356436)
    - storage: Document wiping formatted volume types (rhbz#868771)
    - admin: Retrieve the SASL context for both local and remote connection (rhbz#1361948)
    - daemon: sasl: Don't forget to save SASL username to client's identity (rhbz#1361948)
    - vsh: Make vshInitDebug return int instead of void (rhbz#1357363)
    - tools: Make use of the correct environment variables (rhbz#1357363)
    - util: Add 'usage' for encryption (rhbz#1301021)
    - virStorageEncryptionSecretFree: Don't leak secret lookup definition (rhbz#1301021)
    - encryption: Add luks parsing for storageencryption (rhbz#1301021)
    - encryption: Add <cipher> and <ivgen> to encryption (rhbz#1301021)
    - qemu: Introduce helper qemuDomainSecretDiskCapable (rhbz#1301021)
    - tests: Adjust LUKS tests to use 'volume' secret type (rhbz#1301021)
    - docs: Update docs to reflect LUKS secret changes (rhbz#1301021)
    - qemu: Alter error path cleanup for qemuDomainAttachHostSCSIDevice (rhbz#1301021)
    - qemu: Alter error path cleanup for qemuDomainAttachVirtioDiskDevice (rhbz#1301021)
    - qemu: Alter error path cleanup for qemuDomainAttachSCSIDisk (rhbz#1301021)
    - qemu: Move and rename qemuBufferEscapeComma (rhbz#1301021)
    - storage: Add support to create a luks volume (rhbz#1301021)
    - qemu: Add secinfo for hotplug virtio disk (rhbz#1301021)
    - qemu: Alter the qemuDomainGetSecretAESAlias to add new arg (rhbz#1301021)
    - qemu: Add luks support for domain disk (rhbz#1301021)
    - qemu: Move setting of obj bools for qemuDomainAttachVirtioDiskDevice (rhbz#1301021)
    - qemu: Move setting of encobjAdded for qemuDomainAttachSCSIDisk (rhbz#1301021)
    - storage: Fix error path (rhbz#1301021)
    - qemu: Disallow usage of luks encryption if aes secret not possible (rhbz#1301021)
    - storage: Add extra failure condition for luks volume creation (rhbz#1301021)
    - virstoragefile: refactor virStorageFileMatchesNNN methods (rhbz#1301021)
    - qemu: Make qemuDomainCheckDiskStartupPolicy self-contained (rhbz#1168453)
    - qemu: Remove unnecessary label and its only reference (rhbz#1168453)
    - qemu: Fix support for startupPolicy with volume/pool disks (rhbz#1168453)
    - virsh: Report error when explicit connection fails (rhbz#1356461)
    - tests: Add testing of backing store string parser (rhbz#1134878)
    - util: json: Make first argument of virJSONValueObjectForeachKeyValue const (rhbz#1134878)
    - util: qemu: Add wrapper for JSON -> commandline conversion (rhbz#1134878)
    - util: qemu: Add support for user-passed strings in JSON->commandline (rhbz#1134878)
    - util: qemu: Allow nested objects in JSON -> commandline generator (rhbz#1134878)
    - util: qemu: Allow for different approaches to format JSON arrays (rhbz#1134878)
    - util: qemu: Don't generate any extra commas in virQEMUBuildCommandLineJSON (rhbz#1134878)
    - util: json: Make first argument of virJSONValueCopy const (rhbz#1134878)
    - util: storage: Add parser for qemu's json backing pseudo-protocol (rhbz#1134878)
    - util: storage: Add support for host device backing specified via JSON (rhbz#1134878)
    - util: storage: Add support for URI based backing volumes in qemu's JSON pseudo-protocol (rhbz#1134878)
    - util: storage: Add json pseudo protocol support for gluster volumes (rhbz#1134878)
    - util: storage: Add json pseudo protocol support for iSCSI volumes (rhbz#1134878)
    - util: storage: Add JSON backing volume parser for 'nbd' protocol (rhbz#1134878)
    - util: storage: Add JSON backing store parser for 'sheepdog' protocol (rhbz#1134878)
    - util: storage: Add 'ssh' network storage protocol (rhbz#1134878)
    - util: storage: Add JSON backing volume parser for 'ssh' protocol (rhbz#1134878)
    - qemu: command: Rename qemuBuildNetworkDriveURI to qemuBuildNetworkDriveStr (rhbz#1247521)
    - qemu: command: Split out network disk URI building (rhbz#1247521)
    - qemu: command: Extract drive source command line formatter (rhbz#1247521)
    - qemu: command: Refactor code extracted to qemuBuildDriveSourceStr (rhbz#1247521)
    - storage: gluster: Support multiple hosts in backend functions (rhbz#1247521)
    - util: qemu: Add support for numbered array members (rhbz#1247521)
    - qemu: command: Add infrastructure for object specified disk sources (rhbz#1247521)
    - qemu: command: Add support for multi-host gluster disks (rhbz#1247521)
    - qemu: Need to free fileprops in error path (rhbz#1247521)
    - storage: remove 'luks' storage volume type (rhbz#1301021)

    [2.0.0-3]
    - qemu: getAutoDumpPath() return value should be dumpfile not domname. (rhbz#1354238)
    - qemu: Copy complete domain def in qemuDomainDefFormatBuf (rhbz#1320470)
    - qemu: Drop default channel path during migration (rhbz#1320470)
    - qemu: Fix migration from old libvirt (rhbz#1320500)
    - Add USB addresses to qemuhotplug test cases (rhbz#1215968)
    - Introduce virDomainUSBDeviceDefForeach (rhbz#1215968)
    - Allow omitting USB port (rhbz#1215968)
    - Store USB port path as an array of integers (rhbz#1215968)
    - Introduce virDomainUSBAddressSet (rhbz#1215968)
    - Add functions for adding USB controllers to addrs (rhbz#1215968)
    - Add functions for adding USB hubs to addrs (rhbz#1215968)
    - Reserve existing USB addresses (rhbz#1215968)
    - Add tests for USB address assignment (rhbz#1215968)
    - Assign addresses to USB devices (rhbz#1215968)
    - Assign addresses on USB device hotplug (rhbz#1215968)
    - Auto-add one hub if there are too many USB devices (rhbz#1215968)

    [2.0.0-2]
    - qemu: Use bootindex whenever possible (rhbz#1323085)
    - qemu: Properly reset spiceMigration flag (rhbz#1151723)
    - qemu: Drop useless SPICE migration code (rhbz#1151723)
    - qemu: Memory locking is only required for KVM guests on ppc64 (rhbz#1350772)
    - virtlogd: make max file size & number of backups configurable (rhbz#1351209)
    - virtlogd: increase max file size to 2 MB (rhbz#1351209)

    [2.0.0-1]
    - Rebased to libvirt-2.0.0 (rhbz#1286679)
    - The rebase also fixes the following bugs:
        rhbz#735385, rhbz#1004602, rhbz#1046833, rhbz#1180092, rhbz#1216281
        rhbz#1283207, rhbz#1286679, rhbz#1289288, rhbz#1302373, rhbz#1304222
        rhbz#1312188, rhbz#1316370, rhbz#1320893, rhbz#1322210, rhbz#1325072
        rhbz#1325080, rhbz#1332446, rhbz#1333248, rhbz#1333404, rhbz#1334237
        rhbz#1335617, rhbz#1335832, rhbz#1337869, rhbz#1341415, rhbz#1342342
        rhbz#1342874, rhbz#1342962, rhbz#1343442, rhbz#1344892, rhbz#1344897
        rhbz#1345743, rhbz#1346723, rhbz#1346724, rhbz#1346730, rhbz#1350688
        rhbz#1351473

    [1.3.5-1]
    - Rebased to libvirt-1.3.5 (rhbz#1286679)
    - The rebase also fixes the following bugs:
        rhbz#1139766, rhbz#1182074, rhbz#1209802, rhbz#1265694, rhbz#1286679
        rhbz#1286709, rhbz#1318993, rhbz#1319044, rhbz#1320836, rhbz#1326660
        rhbz#1327537, rhbz#1328003, rhbz#1328301, rhbz#1329045, rhbz#1336629
        rhbz#1337073, rhbz#1339900, rhbz#1341460

    [1.3.4-1]
    - Rebased to libvirt-1.3.4 (rhbz#1286679)
    - The rebase also fixes the following bugs:
        rhbz#1002423, rhbz#1004593, rhbz#1038888, rhbz#1103314, rhbz#1220702
        rhbz#1286679, rhbz#1289363, rhbz#1320447, rhbz#1324551, rhbz#1325043
        rhbz#1325075, rhbz#1325757, rhbz#1326270, rhbz#1327499, rhbz#1328401
        rhbz#1329041, rhbz#1329046, rhbz#1329819, rhbz#1331228

    [1.3.3-2]
    - qemu: perf: Fix crash/memory corruption on failed VM start (rhbz#1324757)

    [1.3.3-1]
    - Rebased to libvirt-1.3.3 (rhbz#1286679)
    - The rebase also fixes the following bugs:
        rhbz#830971, rhbz#986365, rhbz#1151723, rhbz#1195176, rhbz#1249441
        rhbz#1260749, rhbz#1264008, rhbz#1269715, rhbz#1278727, rhbz#1281706
        rhbz#1282744, rhbz#1286679, rhbz#1288000, rhbz#1289363, rhbz#1293804
        rhbz#1306556, rhbz#1308317, rhbz#1313264, rhbz#1313314, rhbz#1314594
        rhbz#1315059, rhbz#1316371, rhbz#1316384, rhbz#1316420, rhbz#1316433
        rhbz#1316465, rhbz#1317531, rhbz#1318569, rhbz#1321546

    [1.3.2-1]
    - Rebased to libvirt-1.3.2 (rhbz#1286679)
    - The rebase also fixes the following bugs:
        rhbz#1197592, rhbz#1235180, rhbz#1244128, rhbz#1244567, rhbz#1245013
        rhbz#1250331, rhbz#1265694, rhbz#1267256, rhbz#1275039, rhbz#1282846
        rhbz#1283085, rhbz#1286679, rhbz#1290324, rhbz#1293241, rhbz#1293899
        rhbz#1299696, rhbz#1305922

    [1.3.1-1]
    - Rebased to libvirt-1.3.1 (rhbz#1286679)
    - The rebase also fixes the following bugs:
        rhbz#1207692, rhbz#1233115, rhbz#1245476, rhbz#1298065, rhbz#1026136
        rhbz#1207751, rhbz#1210587, rhbz#1250287, rhbz#1253107, rhbz#1254152
        rhbz#1257486, rhbz#1266078, rhbz#1271107, rhbz#1159219, rhbz#1163091
        rhbz#1196711, rhbz#1263574, rhbz#1270427, rhbz#1245525, rhbz#1247987
        rhbz#1248277, rhbz#1249981, rhbz#1251461, rhbz#1256999, rhbz#1264008
        rhbz#1265049, rhbz#1265114, rhbz#1270715, rhbz#1272301, rhbz#1273686
        rhbz#997561, rhbz#1166452, rhbz#1231114, rhbz#1233003, rhbz#1260576
        rhbz#1261432, rhbz#1273480, rhbz#1273491, rhbz#1277781, rhbz#1278404
        rhbz#1281707, rhbz#1282288, rhbz#1285665, rhbz#1288690, rhbz#1292984
        rhbz#921135, rhbz#1025230, rhbz#1240439, rhbz#1266982, rhbz#1270709
        rhbz#1276198, rhbz#1278068, rhbz#1278421, rhbz#1281710, rhbz#1291035
        rhbz#1297020, rhbz#1297690
    - RHEL: Add rhel machine types to qemuDomainMachineNeedsFDC (rhbz#1227880)
    - RHEL: qemu: Support vhost-user-multiqueue with QEMU 2.3 (rhbz#1207692)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-2577.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libvirt-client-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-lxc-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-lxc-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-login-shell-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-2.0.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-client-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-network-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-config-nwfilter-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-interface-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-lxc-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-network-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nodedev-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-nwfilter-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-qemu-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-secret-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-driver-storage-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-kvm-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-daemon-lxc-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-devel-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-docs-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-lock-sanlock-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-login-shell-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvirt-nss-2.0.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt / libvirt-client / libvirt-daemon / etc');
}
