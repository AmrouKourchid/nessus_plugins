#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0862-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232751);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id(
    "CVE-2023-49502",
    "CVE-2023-50010",
    "CVE-2023-51793",
    "CVE-2023-51794",
    "CVE-2023-51798",
    "CVE-2024-7055",
    "CVE-2024-12361",
    "CVE-2024-31578",
    "CVE-2024-32230",
    "CVE-2024-35368",
    "CVE-2024-36613",
    "CVE-2025-0518",
    "CVE-2025-22919",
    "CVE-2025-22921",
    "CVE-2025-25473"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0862-1");
  script_xref(name:"IAVB", value:"2025-B-0060");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : ffmpeg-4 (SUSE-SU-2025:0862-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2025:0862-1 advisory.

    - CVE-2025-22921: Fixed segmentation violation in NULL pointer dereference via the component
    /libavcodec/jpeg2000dec.c (bsc#1237382).
    - CVE-2025-25473: Fixed memory leak in avformat_free_context() (bsc#1237351).
    - CVE-2025-0518: Fixed unchecked sscanf return value which leads to memory data leak (bsc#1236007).
    - CVE-2025-22919: Fixed denial of service (DoS) via opening a crafted AAC file (bsc#1237371).
    - CVE-2024-12361: Fixed NULL Pointer Dereference (bsc#1237358).
    - CVE-2024-35368: Fixed Double Free via the rkmpp_retrieve_frame function within libavcodec/rkmppdec.c
    (bsc#1234028).
    - CVE-2024-36613: Fixed Integer overflow in ffmpeg (bsc#1235092).
    - CVE-2023-50010: Fixed arbitrary code execution via the set_encoder_id function in /fftools/ffmpeg_enc.c
    component (bsc#1223256).
    - CVE-2023-51794: Fixed heap-buffer-overflow at libavfilter/af_stereowiden.c (bsc#1223437).
    - CVE-2023-51793: Fixed heap buffer overflow in the image_copy_plane function in libavutil/imgutils.c
    (bsc#1223272).
    - CVE-2023-49502: Fixed heap buffer overflow via the ff_bwdif_filter_intra_c function in
    libavfilter/bwdifdsp.c (bsc#1223235).
    - CVE-2023-51798: Fixed floating point exception(FPE) via the interpolate function in
    libavfilter/vf_minterpolate.c (bsc#1223304).
    - CVE-2024-31578: Fixed heap use-after-free via the av_hwframe_ctx_init function (bsc#1223070).
    - CVE-2024-7055: Fixed heap-based buffer overflow in pnmdec.c (bsc#1229026).
    - CVE-2024-32230: Fixed buffer overflow due to negative-size-param bug at libavcodec/mpegvideo_enc.c in
    load_input_picture (bsc#1227296).

    Other fixes:
    - Updated to version 4.4.5.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237382");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020516.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?857e7020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-50010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-12361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-25473");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7055");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-32230");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-4-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec58_134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavdevice58_13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavfilter7_110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavformat58_76");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil56_70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc55_9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample3_9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale5_9");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libavcodec58_134-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libavcodec58_134-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libavformat58_76-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libavformat58_76-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libavutil56_70-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libavutil56_70-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libswresample3_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libswresample3_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libswscale5_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libswscale5_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'ffmpeg-4-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libavcodec-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libavdevice-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libavfilter-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libavformat-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libavresample-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libavutil-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libpostproc-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libswresample-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-libswscale-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-private-devel-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavcodec58_134-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavcodec58_134-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavdevice58_13-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavdevice58_13-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavfilter7_110-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavfilter7_110-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavformat58_76-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavformat58_76-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavresample4_0-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavresample4_0-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavutil56_70-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libavutil56_70-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libpostproc55_9-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libpostproc55_9-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libswresample3_9-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libswresample3_9-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libswscale5_9-32bit-4.4.5-150600.13.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libswscale5_9-4.4.5-150600.13.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ffmpeg-4-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libavcodec-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libavdevice-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libavfilter-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libavformat-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libavresample-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libavutil-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libpostproc-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libswresample-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-libswscale-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'ffmpeg-4-private-devel-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavcodec58_134-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavdevice58_13-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavfilter7_110-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavformat58_76-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavresample4_0-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavutil56_70-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libpostproc55_9-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libswresample3_9-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libswscale5_9-4.4.5-150600.13.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'libavcodec58_134-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libavcodec58_134-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libavformat58_76-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libavformat58_76-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libavutil56_70-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libavutil56_70-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libswresample3_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libswresample3_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libswscale5_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libswscale5_9-4.4.5-150600.13.16.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ffmpeg-4 / ffmpeg-4-libavcodec-devel / ffmpeg-4-libavdevice-devel / etc');
}
