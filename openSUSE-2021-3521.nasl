#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3521-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154611);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2020-20891",
    "CVE-2020-20892",
    "CVE-2020-20895",
    "CVE-2020-20896",
    "CVE-2020-20899",
    "CVE-2020-20902",
    "CVE-2020-22037",
    "CVE-2020-35965",
    "CVE-2021-3566",
    "CVE-2021-38092",
    "CVE-2021-38093",
    "CVE-2021-38094"
  );

  script_name(english:"openSUSE 15 Security Update : ffmpeg (openSUSE-SU-2021:3521-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3521-1 advisory.

  - Buffer Overflow vulnerability in function config_input in libavfilter/vf_gblur.c in Ffmpeg 4.2.1, allows
    attackers to cause a Denial of Service or other unspecified impacts. (CVE-2020-20891)

  - An issue was discovered in function filter_frame in libavfilter/vf_lenscorrection.c in Ffmpeg 4.2.1,
    allows attackers to cause a Denial of Service or other unspecified impacts due to a division by zero.
    (CVE-2020-20892)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2020-22028. Reason: This candidate is a
    duplicate of CVE-2020-22028. Notes: All CVE users should reference CVE-2020-22028 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2020-20895)

  - An issue was discovered in function latm_write_packet in libavformat/latmenc.c in Ffmpeg 4.2.1, allows
    attackers to cause a Denial of Service or other unspecified impacts due to a Null pointer dereference.
    (CVE-2020-20896)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2020-22036. Reason: This candidate is a
    duplicate of CVE-2020-22036. Notes: All CVE users should reference CVE-2020-22036 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2020-20899)

  - A CWE-125: Out-of-bounds read vulnerability exists in long_term_filter function in g729postfilter.c in
    FFmpeg 4.2.1 during computation of the denominator of pseudo-normalized correlation R'(0), that could
    result in disclosure of information. (CVE-2020-20902)

  - A Denial of Service vulnerability exists in FFmpeg 4.2 due to a memory leak in avcodec_alloc_context3 at
    options.c. (CVE-2020-22037)

  - decode_frame in libavcodec/exr.c in FFmpeg 4.3.1 has an out-of-bounds write because of errors in
    calculations of when to perform memset zero operations. (CVE-2020-35965)

  - Prior to ffmpeg version 4.3, the tty demuxer did not have a 'read_probe' function assigned to it. By
    crafting a legitimate ffconcat file that references an image, followed by a file the triggers the tty
    demuxer, the contents of the second file will be copied into the output file verbatim (as long as the
    `-vcodec copy` option is passed to ffmpeg). (CVE-2021-3566)

  - Integer Overflow vulnerability in function filter_prewitt in libavfilter/vf_convolution.c in Ffmpeg 4.2.1,
    allows attackers to cause a Denial of Service or other unspecified impacts. (CVE-2021-38092)

  - Integer Overflow vulnerability in function filter_robert in libavfilter/vf_convolution.c in Ffmpeg 4.2.1,
    allows attackers to cause a Denial of Service or other unspecified impacts. (CVE-2021-38093)

  - Integer Overflow vulnerability in function filter_sobel in libavfilter/vf_convolution.c in Ffmpeg 4.2.1,
    allows attackers to cause a Denial of Service or other unspecified impacts. (CVE-2021-38094)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190735");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HVCB2YATP2LRWUBIGFYZQUFV52VSFT2B/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a695b09");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-20902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38094");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'ffmpeg-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ffmpeg-private-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec57-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavcodec57-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice57-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavdevice57-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter6-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavfilter6-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat57-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavformat57-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample3-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavresample3-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil55-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libavutil55-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc54-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpostproc54-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample2-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswresample2-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale-devel-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale4-3.4.2-11.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libswscale4-32bit-3.4.2-11.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg / ffmpeg-private-devel / libavcodec-devel / libavcodec57 / etc');
}
