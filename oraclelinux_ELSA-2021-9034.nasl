##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9034.
##

include('compat.inc');

if (description)
{
  script_id(146269);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2019-15034",
    "CVE-2020-10702",
    "CVE-2020-10756",
    "CVE-2020-11102",
    "CVE-2020-12829",
    "CVE-2020-13253",
    "CVE-2020-13362",
    "CVE-2020-13659",
    "CVE-2020-13754",
    "CVE-2020-13791",
    "CVE-2020-14364",
    "CVE-2020-14415",
    "CVE-2020-15863",
    "CVE-2020-16092",
    "CVE-2020-25084",
    "CVE-2020-25624",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-27616",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29130"
  );

  script_name(english:"Oracle Linux 7 : qemu (ELSA-2021-9034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9034 advisory.

    - Document CVE-2020-25723 as fixed (Mark Kanda)  [Orabug: 32222397]  {CVE-2020-25084} {CVE-2020-25723}
    - hw/net/e1000e: advance desc_offset in case of null descriptor (Prasad J Pandit)  [Orabug: 32217517]
    {CVE-2020-28916}
    - libslirp: Update version to include CVE fixes (Mark Kanda)  [Orabug: 32208456] [Orabug: 32208462]
    {CVE-2020-29129} {CVE-2020-29130}
    - Document CVE-2020-25624 as fixed (Mark Kanda)  [Orabug: 32212527]  {CVE-2020-25624} {CVE-2020-25625}
    - ati: check x y display parameter values (Prasad J Pandit)  [Orabug: 32108251]  {CVE-2020-27616}
    - hw: usb: hcd-ohci: check for processed TD before retire (Prasad J Pandit)  [Orabug: 31901690]
    {CVE-2020-25625}
    - hw: usb: hcd-ohci: check len and frame_number variables (Prasad J Pandit)  [Orabug: 31901690]
    {CVE-2020-25625}
    - hw: ehci: check return value of 'usb_packet_map' (Li Qiang)  [Orabug: 31901649]  {CVE-2020-25084}
    - hw: xhci: check return value of 'usb_packet_map' (Li Qiang)  [Orabug: 31901649]  {CVE-2020-25084}
    - usb: fix setup_len init (CVE-2020-14364) (Gerd Hoffmann)  [Orabug: 31848849]  {CVE-2020-14364}
    - Document CVE-2020-12829 and CVE-2020-14415 as fixed (Mark Kanda)  [Orabug: 31855502] [Orabug: 31855427]
    {CVE-2020-12829} {CVE-2020-14415}
    - hw/net/xgmac: Fix buffer overflow in xgmac_enet_send() (Mauro Matteo Cascella)  [Orabug: 31667649]
    {CVE-2020-15863}
    - hw/net/net_tx_pkt: fix assertion failure in net_tx_pkt_add_raw_fragment() (Mauro Matteo Cascella)
    [Orabug: 31737809]  {CVE-2020-16092}
    - hw/sd/sdcard: Do not switch to ReceivingData if address is invalid (Philippe Mathieu-Daude)  [Orabug:
    31414336]  {CVE-2020-13253}
    - hw/sd/sdcard: Do not allow invalid SD card sizes (Philippe Mathieu-Daude)  [Orabug: 31414336]
    {CVE-2020-13253}
    - libslirp: Update to v4.3.1 to fix CVE-2020-10756 (Karl Heubaum)  [Orabug: 31604999]  {CVE-2020-10756}
    - Document CVEs as fixed 2/2 (Karl Heubaum)  [Orabug: 30618035]  {CVE-2017-18043} {CVE-2018-10839}
    {CVE-2018-11806} {CVE-2018-12617} {CVE-2018-15746} {CVE-2018-16847} {CVE-2018-16867} {CVE-2018-17958}
    {CVE-2018-17962} {CVE-2018-17963} {CVE-2018-18849} {CVE-2018-19364} {CVE-2018-19489} {CVE-2018-3639}
    {CVE-2018-5683} {CVE-2018-7550} {CVE-2018-7858} {CVE-2019-12068} {CVE-2019-15034} {CVE-2019-15890}
    {CVE-2019-20382} {CVE-2020-10702} {CVE-2020-10761} {CVE-2020-11102} {CVE-2020-11869} {CVE-2020-13361}
    {CVE-2020-13765} {CVE-2020-13800} {CVE-2020-1711} {CVE-2020-1983} {CVE-2020-8608}
    - Document CVEs as fixed 1/2 (Karl Heubaum)  [Orabug: 30618035]  {CVE-2017-10806} {CVE-2017-11334}
    {CVE-2017-12809} {CVE-2017-13672} {CVE-2017-13673} {CVE-2017-13711} {CVE-2017-14167} {CVE-2017-15038}
    {CVE-2017-15119} {CVE-2017-15124} {CVE-2017-15268} {CVE-2017-15289} {CVE-2017-16845} {CVE-2017-17381}
    {CVE-2017-18030} {CVE-2017-2630} {CVE-2017-2633} {CVE-2017-5715} {CVE-2017-5753} {CVE-2017-5754}
    {CVE-2017-5931} {CVE-2017-6058} {CVE-2017-7471} {CVE-2017-7493} {CVE-2017-8112} {CVE-2017-8309}
    {CVE-2017-8379} {CVE-2017-8380} {CVE-2017-9503} {CVE-2017-9524} {CVE-2018-12126} {CVE-2018-12127}
    {CVE-2018-12130} {CVE-2018-16872} {CVE-2018-20123} {CVE-2018-20124} {CVE-2018-20125} {CVE-2018-20126}
    {CVE-2018-20191} {CVE-2018-20216} {CVE-2018-20815} {CVE-2019-11091} {CVE-2019-12155} {CVE-2019-14378}
    {CVE-2019-3812} {CVE-2019-5008} {CVE-2019-6501} {CVE-2019-6778} {CVE-2019-8934} {CVE-2019-9824}
    - exec: set map length to zero when returning NULL (Prasad J Pandit)  [Orabug: 31439733]  {CVE-2020-13659}
    - megasas: use unsigned type for reply_queue_head and check index (Prasad J Pandit)  [Orabug: 31414338]
    {CVE-2020-13362}
    - memory: Revert 'memory: accept mismatching sizes in memory_region_access_valid' (Michael S. Tsirkin)
    [Orabug: 31439736] [Orabug: 31452202]  {CVE-2020-13754} {CVE-2020-13791}
    - Document CVE-2020-13765 as fixed (Karl Heubaum)  [Orabug: 31463250]  {CVE-2020-13765}
    - ati-vga: check mm_index before recursive call (CVE-2020-13800) (Prasad J Pandit)  [Orabug: 31452206]
    {CVE-2020-13800}
    - es1370: check total frame count against current frame (Prasad J Pandit)  [Orabug: 31463235]
    {CVE-2020-13361}
    - ati-vga: Fix checks in ati_2d_blt() to avoid crash (BALATON Zoltan)  [Orabug: 31238432]
    {CVE-2020-11869}
    - libslirp: Update to stable-4.2 to fix CVE-2020-1983 (Karl Heubaum)  [Orabug: 31241227]  {CVE-2020-1983}
    - Document CVEs as fixed (Karl Heubaum)   {CVE-2019-12068} {CVE-2019-15034}
    - libslirp: Update to version 4.2.0 to fix CVEs (Karl Heubaum)  [Orabug: 30274592] [Orabug: 30869830]
    {CVE-2019-15890} {CVE-2020-8608}
    - vnc: fix memory leak when vnc disconnect (Li Qiang)  [Orabug: 30996427]  {CVE-2019-20382}
    - iscsi: Cap block count from GET LBA STATUS (CVE-2020-1711) (Felipe Franciosi)  [Orabug: 31124035]
    {CVE-2020-1711}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9034.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11102");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13754");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ivshmem-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86-core");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'ivshmem-tools-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-core-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-aarch64-core-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-x86-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
    {'reference':'qemu-system-x86-core-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ivshmem-tools / qemu / qemu-block-gluster / etc');
}
