#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4611-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(186470);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/05");

  script_cve_id(
    "CVE-2023-39350",
    "CVE-2023-39351",
    "CVE-2023-39352",
    "CVE-2023-39353",
    "CVE-2023-39354",
    "CVE-2023-39356",
    "CVE-2023-40181",
    "CVE-2023-40186",
    "CVE-2023-40188",
    "CVE-2023-40567",
    "CVE-2023-40569",
    "CVE-2023-40574",
    "CVE-2023-40575",
    "CVE-2023-40576",
    "CVE-2023-40589"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4611-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : freerdp (SUSE-SU-2023:4611-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2023:4611-1 advisory.

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    This issue affects Clients only. Integer underflow leading to DOS (e.g. abort due to `WINPR_ASSERT` with
    default compilation flags). When an insufficient blockLen is provided, and proper length validation is not
    performed, an Integer Underflow occurs, leading to a Denial of Service (DOS) vulnerability. This issue has
    been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-39350)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions of FreeRDP are subject to a Null Pointer Dereference leading a crash in the RemoteFX
    (rfx) handling. Inside the `rfx_process_message_tileset` function, the program allocates tiles using
    `rfx_allocate_tiles` for the number of numTiles. If the initialization process of tiles is not completed
    for various reasons, tiles will have a NULL pointer. Which may be accessed in further processing and would
    cause a program crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised
    to upgrade. There are no known workarounds for this vulnerability. (CVE-2023-39351)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an invalid offset validation leading to Out Of Bound Write. This can be
    triggered when the values `rect->left` and `rect->top` are exactly equal to `surface->width` and
    `surface->height`. eg. `rect->left` == `surface->width` && `rect->top` == `surface->height`. In practice
    this should cause a crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are
    advised to upgrade. There are no known workarounds for this vulnerability. (CVE-2023-39352)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to a missing offset validation leading to Out Of Bound Read. In the
    `libfreerdp/codec/rfx.c` file there is no offset validation in `tile->quantIdxY`, `tile->quantIdxCb`, and
    `tile->quantIdxCr`. As a result crafted input can lead to an out of bounds read access which in turn will
    cause a crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-39353)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Read in the `nsc_rle_decompress_data` function. The Out-
    Of-Bounds Read occurs because it processes `context->Planes` without checking if it contains data of
    sufficient length. Should an attacker be able to leverage this vulnerability they may be able to cause a
    crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-39354)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    In affected versions a missing offset validation may lead to an Out Of Bound Read in the function
    `gdi_multi_opaque_rect`. In particular there is no code to validate if the value
    `multi_opaque_rect->numRectangles` is less than 45. Looping through `multi_opaque_rect->`numRectangles
    without proper boundary checks can lead to Out-of-Bounds Read errors which will likely lead to a crash.
    This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are
    no known workarounds for this vulnerability. (CVE-2023-39356)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Integer-Underflow leading to Out-Of-Bound Read in the
    `zgfx_decompress_segment` function. In the context of `CopyMemory`, it's possible to read data beyond the
    transmitted packet range and likely cause a crash. This issue has been addressed in versions 2.11.0 and
    3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2023-40181)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an IntegerOverflow leading to Out-Of-Bound Write Vulnerability in the
    `gdi_CreateSurface` function. This issue affects FreeRDP based clients only. FreeRDP proxies are not
    affected as image decoding is not done by a proxy. This issue has been addressed in versions 2.11.0 and
    3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2023-40186)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Read in the `general_LumaToYUV444` function. This Out-
    Of-Bounds Read occurs because processing is done on the `in` variable without checking if it contains data
    of sufficient length. Insufficient data for the `in` variable may cause errors or crashes. This issue has
    been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this issue. (CVE-2023-40188)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Write in the `clear_decompress_bands_data` function in
    which there is no offset validation. Abuse of this vulnerability may lead to an out of bounds write. This
    issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there are no
    known workarounds for this vulnerability. (CVE-2023-40567)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Write in the `progressive_decompress` function. This
    issue is likely down to incorrect calculations of the `nXSrc` and `nYSrc` variables. This issue has been
    addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there are no known workarounds
    for this vulnerability. (CVE-2023-40569)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Write in the `writePixelBGRX` function. This issue is
    likely down to incorrect calculations of the `nHeight` and `srcStep` variables. This issue has been
    addressed in version 3.0.0-beta3. Users are advised to upgrade. There are no known workarounds for this
    issue. (CVE-2023-40574)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Read in the `general_YUV444ToRGB_8u_P3AC4R_BGRX`
    function. This issue is likely down to insufficient data for the `pSrc` variable and results in crashes.
    This issue has been addressed in version 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this issue. (CVE-2023-40575)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Read in the `RleDecompress` function. This Out-Of-Bounds
    Read occurs because FreeRDP processes the `pbSrcBuffer` variable without checking if it contains data of
    sufficient length. Insufficient data in the `pbSrcBuffer` variable may cause errors or crashes. This issue
    has been addressed in version 3.0.0-beta3. Users are advised to upgrade. There are no known workarounds
    for this issue. (CVE-2023-40576)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    In affected versions there is a Global-Buffer-Overflow in the ncrush_decompress function. Feeding crafted
    input into this function can trigger the overflow which has only been shown to cause a crash. This issue
    has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this issue. (CVE-2023-40589)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214872");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-November/017261.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dd582e3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39351");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40186");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40589");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreerdp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwinpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:winpr2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'freerdp-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-devel-2.1.2-12.38.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.38.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.38.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'winpr2-devel-2.1.2-12.38.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-devel-2.1.2-12.38.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.38.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.38.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'winpr2-devel-2.1.2-12.38.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.38.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-proxy / freerdp-server / etc');
}
