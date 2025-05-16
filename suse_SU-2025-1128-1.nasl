#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1128-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233840);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id(
    "CVE-2020-22037",
    "CVE-2024-12361",
    "CVE-2024-35368",
    "CVE-2024-36613",
    "CVE-2025-0518",
    "CVE-2025-22919",
    "CVE-2025-22921",
    "CVE-2025-25473"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1128-1");
  script_xref(name:"IAVB", value:"2025-B-0060");

  script_name(english:"SUSE SLES15 Security Update : ffmpeg-4 (SUSE-SU-2025:1128-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:1128-1 advisory.

    - CVE-2020-22037: Fixed unchecked return value of the init_vlc function (bsc#1186756)
    - CVE-2024-12361: Fixed null pointer dereference (bsc#1237358)
    - CVE-2024-35368: Fixed double free via the rkmpp_retrieve_frame function within libavcodec/rkmppdec.c
    (bsc#1234028)
    - CVE-2024-36613: Fixed integer overflow in the DXA demuxer of the libavformat library (bsc#1235092)
    - CVE-2025-0518: Fixed memory leak due to unchecked sscanf return value (bsc#1236007)
    - CVE-2025-22919: Fixed denial of service (DoS) via opening a crafted AAC file (bsc#1237371)
    - CVE-2025-22921: Fixed segmentation violation in NULL pointer dereference via the component
    /libavcodec/jpeg2000dec.c (bsc#1237382)
    - CVE-2025-25473: Fixed memory leak in avformat_free_context() (bsc#1237351)

    Other fixes:

    - Build with SVT-AV1 3.0.0.

    - Update to release 4.4.5:
    * Adjust bconds to build the package in SLFO without xvidcore.
    * Add 0001-libavcodec-arm-mlpdsp_armv5te-fix-label-format-to-wo.patch (bsc#1229338)
    * Add ffmpeg-c99.patch so that the package conforms to the C99 standard and builds on i586 with GCC 14.
    * No longer build against libmfx; build against libvpl (bsc#1230983, bsc#1219494)
    * Drop libmfx dependency from our product (jira #PED-10024)
    * Update patch to build with glslang 14
    * Disable vmaf integration as ffmpeg-4 cannot handle vmaf>=3
    * Copy codec list from ffmpeg-6
    * Resolve build failure with binutils >= 2.41. (bsc#1215945)

    - Update to version 4.4.4:
      * avcodec/012v: Order operations for odd size handling
      * avcodec/alsdec: The minimal block is at least 7 bits
      * avcodec/bink:
        - Avoid undefined out of array end pointers in
          binkb_decode_plane()
        - Fix off by 1 error in ref end
      * avcodec/eac3dec: avoid float noise in fixed mode addition to
        overflow
      * avcodec/eatgq: : Check index increments in tgq_decode_block()
      * avcodec/escape124:
        - Fix signdness of end of input check
        - Fix some return codes
      * avcodec/ffv1dec:
        - Check that num h/v slices is supported
        - Fail earlier if prior context is corrupted
        - Restructure slice coordinate reading a bit
      * avcodec/mjpegenc: take into account component count when
        writing the SOF header size
      * avcodec/mlpdec: Check max matrix instead of max channel in
        noise check
      * avcodec/motionpixels: Mask pixels to valid values
      * avcodec/mpeg12dec: Check input size
      * avcodec/nvenc:
        - Fix b-frame DTS behavior with fractional framerates
        - Fix vbv buffer size in cq mode
      * avcodec/pictordec: Remove mid exit branch
      * avcodec/pngdec: Check deloco index more exactly
      * avcodec/rpzaenc: stop accessing out of bounds frame
      * avcodec/scpr3: Check bx
      * avcodec/scpr: Test bx before use
      * avcodec/snowenc: Fix visual weight calculation
      * avcodec/speedhq: Check buf_size to be big enough for DC
      * avcodec/sunrast: Fix maplength check
      * avcodec/tests/snowenc:
        - Fix 2nd test
        - Return a failure if DWT/IDWT mismatches
        - Unbreak DWT tests
      * avcodec/tiff: Ignore tile_count
      * avcodec/utils:
        - Allocate a line more for VC1 and WMV3
        - Ensure linesize for SVQ3
        - Use 32pixel alignment for bink
      * avcodec/videodsp_template: Adjust pointers to avoid undefined
        pointer things
      * avcodec/vp3: Add missing check for av_malloc
      * avcodec/wavpack:
        - Avoid undefined shift in get_tail()
        - Check for end of input in wv_unpack_dsd_high()
      * avcodec/xpmdec: Check size before allocation to avoid
        truncation
      * avfilter/vf_untile: swap the chroma shift values used for plane
        offsets
      * avformat/id3v2: Check taglen in read_uslt()
      * avformat/mov: Check samplesize and offset to avoid integer
        overflow
      * avformat/mxfdec: Use 64bit in remainder
      * avformat/nutdec: Add check for avformat_new_stream
      * avformat/replaygain: avoid undefined / negative abs
      * swscale/input: Use more unsigned intermediates
      * swscale/output: Bias 16bps output calculations to improve non
        overflowing range
      * swscale: aarch64: Fix yuv2rgb with negative stride
      * Use https for repository links

    - Update to version 4.4.3:
      * Stable bug fix release, mainly codecs, filter and format fixes.

    - Add patch to detect SDL2 >= 2.1.0 (bsc#1202848):

    - Update to version 4.4.2:
      * Stable bug fix release, mainly codecs, filter and format fixes.

    - Add conflicts for ffmpeg-5's tools
    - Enable Vulkan filters
    - Fix OS version check, so nvcodec is enabled for Leap too.
    - Disamble libsmbclient usage (can always be built with
      --with-smbclient): the usecase of ffmpeg directly accessing
      smb:// shares is quite constructed (most users will have their
      smb shares mounted).

    - Update to version 4.4.1:
      * Stable bug fix release, mainly codecs and format fixes.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237382");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038897.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-22037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-12361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-25473");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-22037");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-0518");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec58_134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavformat58_76");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil56_70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc55_9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample3_9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libavcodec58_134-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libavformat58_76-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libavutil56_70-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libpostproc55_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libswresample3_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libavcodec58_134-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libavcodec58_134-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libavformat58_76-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libavformat58_76-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libavutil56_70-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libavutil56_70-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libpostproc55_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libpostproc55_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libswresample3_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libswresample3_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libavcodec58_134-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libavcodec58_134-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libavformat58_76-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libavformat58_76-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libavutil56_70-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libavutil56_70-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libpostproc55_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libpostproc55_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libswresample3_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libswresample3_9-4.4.5-150400.3.46.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libavcodec58_134-4.4.5-150400.3.46.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libavformat58_76-4.4.5-150400.3.46.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libavutil56_70-4.4.5-150400.3.46.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libpostproc55_9-4.4.5-150400.3.46.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libswresample3_9-4.4.5-150400.3.46.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libavcodec58_134 / libavformat58_76 / libavutil56_70 / etc');
}
