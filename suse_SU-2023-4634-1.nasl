#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4634-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(186519);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/02");

  script_cve_id(
    "CVE-2019-17540",
    "CVE-2020-21679",
    "CVE-2021-20176",
    "CVE-2021-20224",
    "CVE-2021-20241",
    "CVE-2021-20243",
    "CVE-2021-20244",
    "CVE-2021-20246",
    "CVE-2021-20309",
    "CVE-2021-20311",
    "CVE-2021-20312",
    "CVE-2021-20313",
    "CVE-2022-0284",
    "CVE-2022-2719",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547",
    "CVE-2022-44267",
    "CVE-2022-44268",
    "CVE-2023-1289",
    "CVE-2023-3745",
    "CVE-2023-5341",
    "CVE-2023-34151"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4634-1");

  script_name(english:"SUSE SLES15 Security Update : ImageMagick (SUSE-SU-2023:4634-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:4634-1 advisory.

  - ImageMagick before 7.0.8-54 has a heap-based buffer overflow in ReadPSInfo in coders/ps.c.
    (CVE-2019-17540)

  - Buffer Overflow vulnerability in WritePCXImage function in pcx.c in GraphicsMagick 1.4 allows remote
    attackers to cause a denial of service via converting of crafted image file to pcx format.
    (CVE-2020-21679)

  - A divide-by-zero flaw was found in ImageMagick 6.9.11-57 and 7.0.10-57 in gem.c. This flaw allows an
    attacker who submits a crafted file that is processed by ImageMagick to trigger undefined behavior through
    a division by zero. The highest threat from this vulnerability is to system availability. (CVE-2021-20176)

  - An integer overflow issue was discovered in ImageMagick's ExportIndexQuantum() function in
    MagickCore/quantum-export.c. Function calls to GetPixelIndex() could result in values outside the range of
    representable for the 'unsigned char'. When ImageMagick processes a crafted pdf file, this could lead to
    an undefined behaviour or a crash. (CVE-2021-20224)

  - A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20241)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20243)

  - A flaw was found in ImageMagick in MagickCore/visual-effects.c. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger undefined behavior in the form of math division by zero.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20244)

  - A flaw was found in ImageMagick in MagickCore/resample.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20246)

  - A flaw was found in ImageMagick in versions before 7.0.11 and before 6.9.12, where a division by zero in
    WaveImage() of MagickCore/visual-effects.c may trigger undefined behavior via a crafted image file
    submitted to an application using ImageMagick. The highest threat from this vulnerability is to system
    availability. (CVE-2021-20309)

  - A flaw was found in ImageMagick in versions before 7.0.11, where a division by zero in
    sRGBTransformImage() in the MagickCore/colorspace.c may trigger undefined behavior via a crafted image
    file that is submitted by an attacker processed by an application using ImageMagick. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20311)

  - A flaw was found in ImageMagick in versions 7.0.11, where an integer overflow in WriteTHUMBNAILImage of
    coders/thumbnail.c may trigger undefined behavior via a crafted image file that is submitted by an
    attacker and processed by an application using ImageMagick. The highest threat from this vulnerability is
    to system availability. (CVE-2021-20312)

  - A flaw was found in ImageMagick in versions before 7.0.11. A potential cipher leak when the calculate
    signatures in TransformSignature is possible. The highest threat from this vulnerability is to data
    confidentiality. (CVE-2021-20313)

  - A heap-based-buffer-over-read flaw was found in ImageMagick's GetPixelAlpha() function of 'pixel-
    accessor.h'. This vulnerability is triggered when an attacker passes a specially crafted Tagged Image File
    Format (TIFF) image to convert it into a PICON file format. This issue can potentially lead to a denial of
    service and information disclosure. (CVE-2022-0284)

  - In ImageMagick, a crafted file could trigger an assertion failure when a call to WriteImages was made in
    MagickWand/operation.c, due to a NULL image list. This could potentially cause a denial of service. This
    was fixed in upstream ImageMagick version 7.1.0-30. (CVE-2022-2719)

  - ImageMagick 7.1.0-27 is vulnerable to Buffer Overflow. (CVE-2022-28463)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned char' at coders/psd.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32545)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned long' at coders/pcl.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32546)

  - In ImageMagick, there is load of misaligned address for type 'double', which requires 8 byte alignment and
    for type 'float', which requires 4 byte alignment at MagickCore/property.c. Whenever crafted or untrusted
    input is processed by ImageMagick, this causes a negative impact to application availability or other
    problems related to undefined behavior. (CVE-2022-32547)

  - ImageMagick 7.1.0-49 is vulnerable to Denial of Service. When it parses a PNG image (e.g., for resize),
    the convert process could be left waiting for stdin input. (CVE-2022-44267)

  - ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for
    resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary
    has permissions to read it). (CVE-2022-44268)

  - A vulnerability was discovered in ImageMagick where a specially created SVG file loads itself and causes a
    segmentation fault. This flaw allows a remote attacker to pass a specially crafted SVG file that leads to
    a segmentation fault, generating many trash files in /tmp, resulting in a denial of service. When
    ImageMagick crashes, it generates a lot of trash files. These trash files can be large if the SVG file
    contains many render actions. In a denial of service attack, if a remote attacker uploads an SVG file of
    size t, ImageMagick generates files of size 103*t. If an attacker uploads a 100M SVG, the server will
    generate about 10G. (CVE-2023-1289)

  - A vulnerability was found in ImageMagick. This security flaw ouccers as an undefined behaviors of casting
    double to size_t in svg, mvg and other coders (recurring bugs of CVE-2022-32546). (CVE-2023-34151)

  - A heap-based buffer overflow issue was found in ImageMagick's PushCharPixel() function in quantum-
    private.h. This issue may allow a local attacker to trick the user into opening a specially crafted file,
    triggering an out-of-bounds read error and allowing an application to crash, resulting in a denial of
    service. (CVE-2023-3745)

  - A heap use-after-free flaw was found in coders/bmp.c in ImageMagick. (CVE-2023-5341)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215939");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-December/032996.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20243");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32547");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-34151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5341");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-7-SUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-7-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-7_Q16HDRI4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-7_Q16HDRI6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-7_Q16HDRI6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ImageMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'ImageMagick-config-7-SUSE-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'ImageMagick-config-7-upstream-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'ImageMagick-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libMagick++-7_Q16HDRI4-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libMagick++-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libMagickCore-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libMagickWand-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'perl-PerlMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'ImageMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-config-7-SUSE-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-config-7-SUSE-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-config-7-upstream-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-config-7-upstream-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagick++-7_Q16HDRI4-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagick++-7_Q16HDRI4-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagick++-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagick++-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagickCore-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagickCore-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagickWand-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libMagickWand-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'perl-PerlMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'perl-PerlMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'ImageMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'ImageMagick-config-7-SUSE-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'ImageMagick-config-7-upstream-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'ImageMagick-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libMagick++-7_Q16HDRI4-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libMagick++-devel-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libMagickCore-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libMagickWand-7_Q16HDRI6-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'perl-PerlMagick-7.0.7.34-150000.3.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ImageMagick / ImageMagick-config-7-SUSE / etc');
}
