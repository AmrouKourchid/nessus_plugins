#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2269.
##

include('compat.inc');

if (description)
{
  script_id(182646);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2023-39350",
    "CVE-2023-39351",
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

  script_name(english:"Amazon Linux 2 : freerdp (ALAS-2023-2269)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of freerdp installed on the remote host is prior to 2.11.1-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2023-2269 advisory.

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    This issue affects Clients only. Integer underflow leading to DOS (e.g. abort due to `WINPR_ASSERT` with
    default compilation flags). When an insufficient blockLen is provided, and proper length validation is not
    performed, an Integer Underflow occurs, leading to a Denial of Service (DOS) vulnerability. This issue has
    been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-39350)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions of FreeRDP are subject to a Null Pointer Dereference leading a crash in the RemoteFX
    (rfx) handling.  Inside the `rfx_process_message_tileset` function, the program allocates tiles using
    `rfx_allocate_tiles` for the number of numTiles. If the initialization process of tiles is not completed
    for various reasons, tiles will have a NULL pointer. Which may be accessed in further processing and would
    cause a program crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised
    to upgrade. There are no known workarounds for this vulnerability. (CVE-2023-39351)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to a missing offset validation leading to Out Of Bound Read. In the
    `libfreerdp/codec/rfx.c` file there is no offset validation in `tile->quantIdxY`, `tile->quantIdxCb`, and
    `tile->quantIdxCr`. As a result crafted input can lead to an out of bounds read access which in turn will
    cause a crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-39353)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Read in the `nsc_rle_decompress_data` function. The Out-
    Of-Bounds Read occurs because it processes `context->Planes` without  checking if it contains data of
    sufficient length. Should an attacker be able to leverage this vulnerability they may be able to cause a
    crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-39354)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    In affected versions a missing offset validation may lead to an Out Of Bound Read in the function
    `gdi_multi_opaque_rect`. In particular there is no code to validate if the value
    `multi_opaque_rect->numRectangles` is less than 45. Looping through `multi_opaque_rect->`numRectangles
    without proper boundary checks can lead to Out-of-Bounds Read errors which will likely lead to a crash.
    This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are
    no known workarounds for this vulnerability. (CVE-2023-39356)

    NOTE: https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mxp4-rx7x-h2g8 (CVE-2023-40181)

    NOTE: https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-hcj4-3c3r-5j3v (CVE-2023-40186)

    NOTE: https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-9w28-wwj5-p4xq (CVE-2023-40188)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Write in the `clear_decompress_bands_data` function in
    which there is no offset validation. Abuse of this vulnerability may lead to an out of bounds write. This
    issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there are no
    known workarounds for this vulnerability. (CVE-2023-40567)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    Affected versions are subject to an Out-Of-Bounds Write in the `progressive_decompress` function. This
    issue is likely down to incorrect calculations of the `nXSrc` and `nYSrc` variables. This issue has been
    addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there are no known workarounds
    for this vulnerability. (CVE-2023-40569)

    FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    In affected versions there is a Global-Buffer-Overflow in the ncrush_decompress function. Feeding crafted
    input into this function can trigger the overflow which has only been shown to cause a crash. This issue
    has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
    workarounds for this issue. (CVE-2023-40589)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2269.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39350.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39351.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39353.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39354.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39356.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40181.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40186.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40188.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40567.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40569.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40589.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update freerdp' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'freerdp-2.11.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-2.11.1-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-2.11.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-debuginfo-2.11.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-debuginfo-2.11.1-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-debuginfo-2.11.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-devel-2.11.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-devel-2.11.1-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-devel-2.11.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-libs-2.11.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-libs-2.11.1-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freerdp-libs-2.11.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwinpr-2.11.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwinpr-2.11.1-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwinpr-2.11.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwinpr-devel-2.11.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwinpr-devel-2.11.1-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwinpr-devel-2.11.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-devel / etc");
}
