#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191829);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id(
    "CVE-2023-39350",
    "CVE-2023-39353",
    "CVE-2023-39354",
    "CVE-2023-39356",
    "CVE-2023-40181",
    "CVE-2023-40186",
    "CVE-2023-40188",
    "CVE-2023-40567",
    "CVE-2023-40569",
    "CVE-2023-40589"
  );

  script_name(english:"EulerOS 2.0 SP8 : freerdp (EulerOS-SA-2024-1264)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freerdp packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    This issue affects Clients only. Integer underflow leading to DOS (e.g. abort due to `WINPR_ASSERT` with
    default compilation flags). When an insufficient blockLen is provided, and proper length validation is not
    performed, an Integer Underflow occurs, leading to a Denial of Service (DOS) vulnerability. This issue has
    been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-39350)

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
    In affected versions there is a Global-Buffer-Overflow in the ncrush_decompress function. Feeding crafted
    input into this function can trigger the overflow which has only been shown to cause a crash. This issue
    has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this issue. (CVE-2023-40589)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1264
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb884183");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwinpr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "freerdp-2.0.0-44.rc3.h16.eulerosv2r8",
  "freerdp-libs-2.0.0-44.rc3.h16.eulerosv2r8",
  "libwinpr-2.0.0-44.rc3.h16.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
