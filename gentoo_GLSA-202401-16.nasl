#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-16.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187999);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id(
    "CVE-2022-39316",
    "CVE-2022-39317",
    "CVE-2022-39318",
    "CVE-2022-39319",
    "CVE-2022-39320",
    "CVE-2022-39347",
    "CVE-2022-41877",
    "CVE-2023-39350",
    "CVE-2023-39351",
    "CVE-2023-39352",
    "CVE-2023-39353",
    "CVE-2023-39354",
    "CVE-2023-39355",
    "CVE-2023-39356",
    "CVE-2023-40181",
    "CVE-2023-40186",
    "CVE-2023-40187",
    "CVE-2023-40188",
    "CVE-2023-40567",
    "CVE-2023-40569",
    "CVE-2023-40574",
    "CVE-2023-40575",
    "CVE-2023-40576",
    "CVE-2023-40589"
  );

  script_name(english:"GLSA-202401-16 : FreeRDP: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-16 (FreeRDP: Multiple Vulnerabilities)

  - FreeRDP is a free remote desktop protocol library and clients. In affected versions there is an out of
    bound read in ZGFX decoder component of FreeRDP. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it likely resulting in a crash. This issue has been addressed in
    the 2.9.0 release. Users are advised to upgrade. (CVE-2022-39316)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing a
    range check for input offset index in ZGFX decoder. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it. This issue has been addressed in version 2.9.0. There are no
    known workarounds for this issue. (CVE-2022-39317)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input validation in `urbdrc` channel. A malicious server can trick a FreeRDP based client to crash with
    division by zero. This issue has been addressed in version 2.9.0. All users are advised to upgrade. Users
    unable to upgrade should not use the `/usb` redirection switch. (CVE-2022-39318)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in the `urbdrc` channel. A malicious server can trick a FreeRDP based client to
    read out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and
    all users are advised to upgrade. Users unable to upgrade should not use the `/usb` redirection switch.
    (CVE-2022-39319)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP may attempt
    integer addition on too narrow types leads to allocation of a buffer too small holding the data written. A
    malicious server can trick a FreeRDP based client to read out of bound data and send it back to the
    server. This issue has been addressed in version 2.9.0 and all users are advised to upgrade. Users unable
    to upgrade should not use the `/usb` redirection switch. (CVE-2022-39320)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    path canonicalization and base path check for `drive` channel. A malicious server can trick a FreeRDP
    based client to read files outside the shared directory. This issue has been addressed in version 2.9.0
    and all users are advised to upgrade. Users unable to upgrade should not use the `/drive`, `/drives` or
    `+home-drive` redirection switch. (CVE-2022-39347)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in `drive` channel. A malicious server can trick a FreeRDP based client to read
    out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and all
    users are advised to upgrade. Users unable to upgrade should not use the drive redirection channel -
    command line options `/drive`, `+drives` or `+home-drive`. (CVE-2022-41877)

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
    Versions of FreeRDP on the 3.x release branch before beta3 are subject to a Use-After-Free in processing
    `RDPGFX_CMDID_RESETGRAPHICS` packets. If `context->maxPlaneSize` is 0, `context->planesBuffer` will be
    freed. However, without updating `context->planesBuffer`, this leads to a Use-After-Free exploit vector.
    In most environments this should only result in a crash. This issue has been addressed in version
    3.0.0-beta3 and users of the beta 3.x releases are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-39355)

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
    Affected versions of the 3.x beta branch are subject to a Use-After-Free issue in the
    `avc420_ensure_buffer` and `avc444_ensure_buffer` functions. If the value of `piDstSize[x]` is 0,
    `ppYUVDstData[x]` will be freed. However, in this case `ppYUVDstData[x]` will not have been updated which
    leads to a Use-After-Free vulnerability. This issue has been addressed in version 3.0.0-beta3. Users of
    the 3.x beta releases are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2023-40187)

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
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=881525");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918546");
  script_set_attribute(attribute:"solution", value:
"All FreeRDP users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-misc/freerdp-2.11.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-misc/freerdp',
    'unaffected' : make_list("ge 2.11.0"),
    'vulnerable' : make_list("lt 2.11.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'FreeRDP');
}
