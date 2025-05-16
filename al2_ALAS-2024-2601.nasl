#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2601.
##

include('compat.inc');

if (description)
{
  script_id(202981);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2015-7747",
    "CVE-2017-6827",
    "CVE-2017-6828",
    "CVE-2017-6829",
    "CVE-2017-6830",
    "CVE-2017-6831",
    "CVE-2017-6832",
    "CVE-2017-6833",
    "CVE-2017-6834",
    "CVE-2017-6835",
    "CVE-2017-6836",
    "CVE-2017-6837",
    "CVE-2017-6838",
    "CVE-2017-6839",
    "CVE-2020-18781"
  );

  script_name(english:"Amazon Linux 2 : audiofile (ALAS-2024-2601)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of audiofile installed on the remote host is prior to 0.3.6-9. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2024-2601 advisory.

    Buffer overflow in the afReadFrames function in audiofile (aka libaudiofile and Audio File Library) allows
    user-assisted remote attackers to cause a denial of service (program crash) or possibly execute arbitrary
    code via a crafted audio file, as demonstrated by sixteen-stereo-to-eight-mono.c. (CVE-2015-7747)

    Heap-based buffer overflow in the MSADPCM::initializeCoefficients function in MSADPCM.cpp in audiofile
    (aka libaudiofile and Audio File Library) 0.3.6 allows remote attackers to have unspecified impact via a
    crafted audio file. (CVE-2017-6827)

    Heap-based buffer overflow in the readValue function in FileHandle.cpp in audiofile (aka libaudiofile and
    Audio File Library) 0.3.6 allows remote attackers to have unspecified impact via a crafted WAV file.
    (CVE-2017-6828)

    The decodeSample function in IMA.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers
    to cause a denial of service (crash) via a crafted file. (CVE-2017-6829)

    Heap-based buffer overflow in the alaw2linear_buf function in G711.cpp in Audio File Library (aka
    audiofile) 0.3.6 allows remote attackers to cause a denial of service (crash) via a crafted file.
    (CVE-2017-6830)

    Heap-based buffer overflow in the decodeBlockWAVE function in IMA.cpp in Audio File Library (aka
    audiofile) 0.3.6, 0.3.5, 0.3.4, 0.3.3, 0.3.2, 0.3.1, 0.3.0 and 0.2.7 allows remote attackers to cause a
    denial of service (crash) via a crafted file. (CVE-2017-6831)

    Heap-based buffer overflow in the decodeBlock in MSADPCM.cpp in Audio File Library (aka audiofile) 0.3.6,
    0.3.5, 0.3.4, 0.3.3, 0.3.2, 0.3.1, 0.3.0, 0.2.7 allows remote attackers to cause a denial of service
    (crash) via a crafted file. (CVE-2017-6832)

    The runPull function in libaudiofile/modules/BlockCodec.cpp in Audio File Library (aka audiofile) 0.3.6
    allows remote attackers to cause a denial of service (divide-by-zero error and crash) via a crafted file.
    (CVE-2017-6833)

    Heap-based buffer overflow in the ulaw2linear_buf function in G711.cpp in Audio File Library (aka
    audiofile) 0.3.6, 0.3.5, 0.3.4, 0.3.3, 0.3.2, 0.3.1, 0.3.0, 0.2.7 allows remote attackers to cause a
    denial of service (crash) via a crafted file. (CVE-2017-6834)

    The reset1 function in libaudiofile/modules/BlockCodec.cpp in Audio File Library (aka audiofile) 0.3.6
    allows remote attackers to cause a denial of service (divide-by-zero error and crash) via a crafted file.
    (CVE-2017-6835)

    Heap-based buffer overflow in the Expand3To4Module::run function in libaudiofile/modules/SimpleModule.h in
    Audio File Library (aka audiofile) 0.3.6, 0.3.5, 0.3.4, 0.3.3, 0.3.2, 0.3.1, 0.3.0 allows remote attackers
    to cause a denial of service (crash) via a crafted file. (CVE-2017-6836)

    WAVE.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote attackers to cause a denial of service
    (crash) via vectors related to a large number of coefficients. (CVE-2017-6837)

    Integer overflow in sfcommands/sfconvert.c in Audio File Library (aka audiofile) 0.3.6 allows remote
    attackers to cause a denial of service (crash) via a crafted file. (CVE-2017-6838)

    Integer overflow in modules/MSADPCM.cpp in Audio File Library (aka audiofile) 0.3.6 allows remote
    attackers to cause a denial of service (crash) via a crafted file. (CVE-2017-6839)

    Heap buffer overflow vulnerability in FilePOSIX::read in File.cpp in audiofile 0.3.6 may cause denial-of-
    service via a crafted wav file, this bug can be triggered by the executable sfconvert. (CVE-2020-18781)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2601.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2015-7747.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6827.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6828.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6829.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6830.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6831.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6832.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6833.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6834.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6835.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6836.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6837.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6838.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-6839.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-18781.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update audiofile' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6828");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-7747");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:audiofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:audiofile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:audiofile-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'audiofile-0.3.6-9.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-0.3.6-9.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-0.3.6-9.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-debuginfo-0.3.6-9.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-debuginfo-0.3.6-9.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-debuginfo-0.3.6-9.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-devel-0.3.6-9.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-devel-0.3.6-9.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audiofile-devel-0.3.6-9.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "audiofile / audiofile-debuginfo / audiofile-devel");
}
