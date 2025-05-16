#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-eabbf4ca4d
#

include('compat.inc');

if (description)
{
  script_id(180022);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");
  script_xref(name:"FEDORA", value:"2023-eabbf4ca4d");

  script_name(english:"Fedora 37 : linux-firmware (2023-eabbf4ca4d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2023-eabbf4ca4d advisory.

    New firmware for AMD Zen CPUs to mitigate the AMD 'Inception' attack. Only needed for affected AMD users.

    ----

    Update to upstream 20230804 release:

    *  Split out QCom Arm IP firmware
    *  Merge Marvell libertas WiFi firmware
    *  Mellanox: Add new mlxsw_spectrum firmware xx.2012.1012
    *  Add URL for latest FW binaries for NXP BT chipsets
    *  rtw89: 8851b: update firmware to v0.29.41.1
    *  qcom: sdm845: add RB3 sensors DSP firmware
    *  amdgpu: Update DMCUB for DCN314 & Yellow Carp
    *  ice: add LAG-supporting DDP package
    *  i915: Update MTL DMC to v2.13
    *  i915: Update ADLP DMC to v2.20
    *  cirrus: Add CS35L41 firmware for Dell Oasis Models
    *  copy-firmware: Fix linking directories when using compression
    *  copy-firmware: Fix test: unexpected operator
    *  qcom: sc8280xp: LENOVO: remove directory sym link
    *  qcom: sc8280xp: LENOVO: Remove execute bits
    *  amdgpu: update VCN 4.0.0 firmware
    *  amdgpu: add initial SMU 13.0.10 firmware
    *  amdgpu: add initial SDMA 6.0.3 firmware
    *  amdgpu: add initial PSP 13.0.10 firmware
    *  amdgpu: add initial GC 11.0.3 firmware
    *  Update AMD fam17h cpu microcode
    *  Update AMD cpu microcode
    *  amdgpu: update various generation VCN firmware
    *  amdgpu: update DMCUB to v0.0.175.0 for various AMDGPU ASICs
    *  Updated NXP SR150 UWB firmware
    *  wfx: update to firmware 3.16.1
    *  mediatek: Update mt8195 SCP firmware to support 10bit mode
    *  i915: update DG2 GuC to v70.8.0
    *  i915: update to GuC 70.8.0 and HuC 8.5.1 for MTL
    *  cirrus: Add CS35L41 firmware for ASUS ROG 2023 Models
    *  Partially revert amdgpu: DMCUB updates for DCN 3.1.4 and 3.1.5
    *  Update firmware for MT7922 WiFi/Bluetooth device
    *  Update firmware file for Intel Bluetooth AX200/201/203/210/211
    *  Fix qcom ASoC tglp WHENCE entry
    *  check_whence: Check link targets are valid
    *  iwlwifi: add new FWs from core80-39 release
    *  iwlwifi: update cc/Qu/QuZ firmwares for core80-39 release
    *  qcom: Add Audio firmware for SC8280XP X13s


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-eabbf4ca4d");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-firmware package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:linux-firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'linux-firmware-20230804-153.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-firmware');
}
