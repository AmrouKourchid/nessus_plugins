#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2025-2747.
##

include('compat.inc');

if (description)
{
  script_id(214971);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id(
    "CVE-2024-4453",
    "CVE-2024-47538",
    "CVE-2024-47607",
    "CVE-2024-47615"
  );

  script_name(english:"Amazon Linux 2 : gstreamer1-plugins-base (ALAS-2025-2747)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of gstreamer1-plugins-base installed on the remote host is prior to 1.18.4-5. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2025-2747 advisory.

    GStreamer EXIF Metadata Parsing Integer Overflow Remote Code Execution Vulnerability. This vulnerability
    allows remote attackers to execute arbitrary code on affected installations of GStreamer. Interaction with
    this library is required to exploit this vulnerability but attack vectors may vary depending on the
    implementation.

    The specific flaw exists within the parsing of EXIF metadata. The issue results from the lack of proper
    validation of user-supplied data, which can result in an integer overflow before allocating a buffer. An
    attacker can leverage this vulnerability to execute code in the context of the current process.. Was ZDI-
    CAN-23896. (CVE-2024-4453)

    GStreamer is a library for constructing graphs of media-handling components. A stack-buffer overflow has
    been detected in the `vorbis_handle_identification_packet` function within `gstvorbisdec.c`. The position
    array is a stack-allocated buffer of size 64. If vd->vi.channels exceeds 64, the for loop will write
    beyond the boundaries of the position array. The value written will always be
    `GST_AUDIO_CHANNEL_POSITION_NONE`. This vulnerability allows someone to overwrite the EIP address
    allocated in the stack. Additionally, this bug can overwrite the `GstAudioInfo` info structure. This
    vulnerability is fixed in 1.24.10. (CVE-2024-47538)

    GStreamer is a library for constructing graphs of media-handling components.  stack-buffer overflow has
    been detected in the gst_opus_dec_parse_header function within `gstopusdec.c'. The pos array is a stack-
    allocated buffer of size 64. If n_channels exceeds 64, the for loop will write beyond the boundaries of
    the pos array. The value written will always be GST_AUDIO_CHANNEL_POSITION_NONE. This bug allows to
    overwrite the EIP address allocated in the stack. This vulnerability is fixed in 1.24.10. (CVE-2024-47607)

    GStreamer is a library for constructing graphs of media-handling components. An OOB-Write has been
    detected in the function gst_parse_vorbis_setup_packet within vorbis_parse.c. The integer size is read
    from the input file without proper validation. As a result, size can exceed the fixed size of the
    pad->vorbis_mode_sizes array (which size is 256). When this happens, the for loop overwrites the entire
    pad structure with 0s and 1s, affecting adjacent memory as well. This OOB-write can overwrite up to 380
    bytes of memory beyond the boundaries of the pad->vorbis_mode_sizes array. This vulnerability is fixed in
    1.24.10. (CVE-2024-47615)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2025-2747.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-4453.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47607.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-47615.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update gstreamer1-plugins-base' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47615");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gstreamer1-plugins-base-tools");
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
    {'reference':'gstreamer1-plugins-base-1.18.4-5.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-1.18.4-5.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-1.18.4-5.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-debuginfo-1.18.4-5.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-debuginfo-1.18.4-5.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-debuginfo-1.18.4-5.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-devel-1.18.4-5.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-devel-1.18.4-5.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-devel-1.18.4-5.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-tools-1.18.4-5.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-tools-1.18.4-5.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugins-base-tools-1.18.4-5.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer1-plugins-base / gstreamer1-plugins-base-debuginfo / gstreamer1-plugins-base-devel / etc");
}
