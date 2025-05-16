#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2025-2848.
##

include('compat.inc');

if (description)
{
  script_id(235880);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2024-48423",
    "CVE-2024-48424",
    "CVE-2024-48425",
    "CVE-2024-53425",
    "CVE-2025-2151",
    "CVE-2025-2152",
    "CVE-2025-2592",
    "CVE-2025-3015",
    "CVE-2025-3016",
    "CVE-2025-3159",
    "CVE-2025-3160",
    "CVE-2025-3196",
    "CVE-2025-3548"
  );

  script_name(english:"Amazon Linux 2 : qt5-qt3d (ALAS-2025-2848)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of qt5-qt3d installed on the remote host is prior to 5.15.3-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2025-2848 advisory.

    An issue in assimp v.5.4.3 allows a local attacker to execute arbitrary code via the
    CallbackToLogRedirector function within the Assimp library. (CVE-2024-48423)

    A heap-buffer-overflow vulnerability has been identified in the OpenDDLParser::parseStructure function
    within the Assimp library, specifically during the processing of OpenGEX files. (CVE-2024-48424)

    A segmentation fault (SEGV) was detected in the Assimp::SplitLargeMeshesProcess_Triangle::UpdateNode
    function within the Assimp library during fuzz testing using AddressSanitizer. The crash occurs due to a
    read access violation at address 0x000000000460, which points to the zero page, indicating a null or
    invalid pointer dereference. (CVE-2024-48425)

    A heap-buffer-overflow vulnerability was discovered in the SkipSpacesAndLineEnd function in Assimp v5.4.3.
    This issue occurs when processing certain malformed MD5 model files, leading to an out-of-bounds read and
    potential application crash. (CVE-2024-53425)

    A vulnerability classified as critical was found in Open Asset Import Library Assimp 5.4.3. This
    vulnerability affects the function Assimp::GetNextLine in the library ParsingUtils.h of the component File
    Handler. The manipulation leads to stack-based buffer overflow. The attack can be initiated remotely. The
    exploit has been disclosed to the public and may be used. (CVE-2025-2151)

    A vulnerability, which was classified as critical, has been found in Open Asset Import Library Assimp
    5.4.3. This issue affects the function Assimp::BaseImporter::ConvertToUTF8 of the file BaseImporter.cpp of
    the component File Handler. The manipulation leads to heap-based buffer overflow. The attack may be
    initiated remotely. The exploit has been disclosed to the public and may be used. (CVE-2025-2152)

    A vulnerability, which was classified as critical, has been found in Open Asset Import Library Assimp
    5.4.3. This issue affects the function CSMImporter::InternReadFile of the file
    code/AssetLib/CSM/CSMLoader.cpp. The manipulation leads to heap-based buffer overflow. The attack may be
    initiated remotely. The exploit has been disclosed to the public and may be used. The patch is named
    2690e354da0c681db000cfd892a55226788f2743. It is recommended to apply a patch to fix this issue.
    (CVE-2025-2592)

    A vulnerability classified as critical has been found in Open Asset Import Library Assimp 5.4.3. This
    affects the function Assimp::ASEImporter::BuildUniqueRepresentation of the file
    code/AssetLib/ASE/ASELoader.cpp of the component ASE File Handler. The manipulation of the argument
    mIndices leads to out-of-bounds read. It is possible to initiate the attack remotely. The exploit has been
    disclosed to the public and may be used. Upgrading to version 6.0 is able to address this issue. The patch
    is named 7c705fde418d68cca4e8eff56be01b2617b0d6fe. It is recommended to apply a patch to fix this issue.
    (CVE-2025-3015)

    A vulnerability classified as problematic was found in Open Asset Import Library Assimp 5.4.3. This
    vulnerability affects the function Assimp::MDLImporter::ParseTextureColorData of the file
    code/AssetLib/MDL/MDLMaterialLoader.cpp of the component MDL File Handler. The manipulation of the
    argument mWidth/mHeight leads to resource consumption. The attack can be initiated remotely. Upgrading to
    version 6.0 is able to address this issue. The name of the patch is
    5d2a7482312db2e866439a8c05a07ce1e718bed1. It is recommended to apply a patch to fix this issue.
    (CVE-2025-3016)

    A vulnerability, which was classified as critical, was found in Open Asset Import Library Assimp 5.4.3.
    This affects the function Assimp::ASE::Parser::ParseLV4MeshBonesVertices of the file
    code/AssetLib/ASE/ASEParser.cpp of the component ASE File Handler. The manipulation leads to heap-based
    buffer overflow. The attack needs to be approached locally. The exploit has been disclosed to the public
    and may be used. The identifier of the patch is e8a6286542924e628e02749c4f5ac4f91fdae71b. It is
    recommended to apply a patch to fix this issue. (CVE-2025-3159)

    A vulnerability has been found in Open Asset Import Library Assimp 5.4.3 and classified as problematic.
    This vulnerability affects the function Assimp::SceneCombiner::AddNodeHashes of the file
    code/Common/SceneCombiner.cpp of the component File Handler. The manipulation leads to out-of-bounds read.
    An attack has to be approached locally. The exploit has been disclosed to the public and may be used. The
    patch is identified as a0993658f40d8e13ff5823990c30b43c82a5daf0. It is recommended to apply a patch to fix
    this issue. (CVE-2025-3160)

    A vulnerability, which was classified as critical, was found in Open Asset Import Library Assimp 5.4.3.
    Affected is the function Assimp::MD2Importer::InternReadFile in the library
    code/AssetLib/MD2/MD2Loader.cpp of the component Malformed File Handler. The manipulation of the argument
    Name leads to stack-based buffer overflow. The attack needs to be approached locally. The exploit has been
    disclosed to the public and may be used. It is recommended to upgrade the affected component.
    (CVE-2025-3196)

    A vulnerability, which was classified as critical, has been found in Open Asset Import Library Assimp up
    to 5.4.3. This issue affects the function aiString::Set in the library include/assimp/types.h of the
    component File Handler. The manipulation leads to heap-based buffer overflow. It is possible to launch the
    attack on the local host. The exploit has been disclosed to the public and may be used. It is recommended
    to apply a patch to fix this issue. (CVE-2025-3548)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2025-2848.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-48423.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-48424.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-48425.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-53425.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-2151.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-2152.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-2592.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-3015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-3016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-3159.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-3160.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-3196.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-3548.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update qt5-qt3d' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2592");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-2152");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-3016");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qt3d-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qt3d-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'qt5-qt3d-5.15.3-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.15.3-1.amzn2.0.5', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.15.3-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-debuginfo-5.15.3-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-debuginfo-5.15.3-1.amzn2.0.5', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-debuginfo-5.15.3-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.15.3-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.15.3-1.amzn2.0.5', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.15.3-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.15.3-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.15.3-1.amzn2.0.5', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.15.3-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qt3d / qt5-qt3d-debuginfo / qt5-qt3d-devel / etc");
}
