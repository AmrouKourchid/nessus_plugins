#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3184-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(131756);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id(
    "CVE-2018-13301",
    "CVE-2019-12730",
    "CVE-2019-17542",
    "CVE-2019-9718"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ffmpeg (SUSE-SU-2019:3184-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for ffmpeg fixes the following issues :

Security issues fixed :

CVE-2019-17542: Fixed a heap-buffer overflow in vqa_decode_chunk due
to an out-of-array access (bsc#1154064).

CVE-2019-12730: Fixed an uninitialized use of variables due to an
improper check (bsc#1137526).

CVE-2019-9718: Fixed a denial of service in the subtitle decode
(bsc#1129715).

CVE-2018-13301: Fixed a denial of service while converting a crafted
AVI file to MPEG4 (bsc#1100352).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1129715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1137526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13301/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12730/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17542/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9718/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193184-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43c72c88");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP1:zypper in -t patch
SUSE-SLE-Product-WE-15-SP1-2019-3184=1

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2019-3184=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-3184=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-3184=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-3184=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-3184=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-3184=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17542");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ffmpeg-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec57-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavcodec57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavdevice57-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavdevice57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavfilter6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavfilter6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavformat57-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavresample3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil55-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavutil55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc54-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpostproc54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libswscale4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavcodec57-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavcodec57-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavdevice57-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavdevice57-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavfilter6-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavfilter6-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavformat57-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavformat57-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavresample3-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavresample3-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavutil55-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libavutil55-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpostproc54-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpostproc54-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libswresample2-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libswresample2-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libswscale4-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libswscale4-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ffmpeg-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ffmpeg-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ffmpeg-debugsource-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ffmpeg-private-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavcodec57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavcodec57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavdevice-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavdevice57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavdevice57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavfilter-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavfilter6-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavfilter6-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavutil-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavutil55-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libavutil55-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpostproc-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpostproc54-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpostproc54-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libswresample-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libswresample2-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libswresample2-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libswscale-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libswscale4-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libswscale4-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ffmpeg-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ffmpeg-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ffmpeg-debugsource-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ffmpeg-private-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavcodec57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavcodec57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavdevice-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavdevice57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavdevice57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavfilter-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavfilter6-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavfilter6-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavutil-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavutil55-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavutil55-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpostproc-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpostproc54-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpostproc54-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libswresample-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libswresample2-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libswresample2-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libswscale-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libswscale4-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libswscale4-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavcodec57-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavcodec57-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavdevice57-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavdevice57-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavfilter6-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavfilter6-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavformat57-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavformat57-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavresample3-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavresample3-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavutil55-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libavutil55-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpostproc54-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpostproc54-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libswresample2-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libswresample2-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libswscale4-32bit-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libswscale4-32bit-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ffmpeg-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ffmpeg-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ffmpeg-debugsource-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ffmpeg-private-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavcodec57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavcodec57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavdevice-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavdevice57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavdevice57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavfilter-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavfilter6-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavfilter6-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavutil-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavutil55-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libavutil55-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpostproc-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpostproc54-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpostproc54-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libswresample-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libswresample2-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libswresample2-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libswscale-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libswscale4-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libswscale4-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ffmpeg-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ffmpeg-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ffmpeg-debugsource-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ffmpeg-private-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavcodec57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavcodec57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavdevice-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavdevice57-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavdevice57-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavfilter-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavfilter6-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavfilter6-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavutil-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavutil55-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavutil55-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpostproc-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpostproc54-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpostproc54-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libswresample-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libswresample2-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libswresample2-debuginfo-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libswscale-devel-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libswscale4-3.4.2-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libswscale4-debuginfo-3.4.2-4.27.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg");
}
