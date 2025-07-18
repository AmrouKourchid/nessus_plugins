#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1293-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(136787);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id(
    "CVE-2020-11758",
    "CVE-2020-11760",
    "CVE-2020-11761",
    "CVE-2020-11762",
    "CVE-2020-11763",
    "CVE-2020-11764",
    "CVE-2020-11765"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openexr (SUSE-SU-2020:1293-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for openexr provides the following fix :

Security issues fixed :

CVE-2020-11765: Fixed an off-by-one error in use of the ImfXdr.h read
function by DwaCompressor:Classifier:Classifier (bsc#1169575).

CVE-2020-11764: Fixed an out-of-bounds write in copyIntoFrameBuffer in
ImfMisc.cpp (bsc#1169574).

CVE-2020-11763: Fixed an out-of-bounds read and write, as demonstrated
by ImfTileOffsets.cpp (bsc#1169576).

CVE-2020-11762: Fixed an out-of-bounds read and write in
DwaCompressor:uncompress in ImfDwaCompressor.cpp when handling the
UNKNOWN compression case (bsc#1169549).

CVE-2020-11761: Fixed an out-of-bounds read during Huffman
uncompression, as demonstrated by FastHufDecoder:refill in
ImfFastHuf.cpp (bsc#1169578).

CVE-2020-11760: Fixed an out-of-bounds read during RLE uncompression
in rleUncompress in ImfRle.cpp (bsc#1169580).

CVE-2020-11758: Fixed an out-of-bounds read in
ImfOptimizedPixelReading.h (bsc#1169573).

Non-security issue fixed :

Enable tests when building the package on x86_64. (bsc#1146648)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11758/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11760/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11761/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11762/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11763/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11764/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11765/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201293-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cee210de");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-1293=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-1293=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11765");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-2_2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-2_2-23-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImf-2_2-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImfUtil-2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImfUtil-2_2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImfUtil-2_2-23-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libIlmImfUtil-2_2-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openexr-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libIlmImf-2_2-23-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libIlmImf-2_2-23-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libIlmImfUtil-2_2-23-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libIlmImfUtil-2_2-23-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openexr-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openexr-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openexr-debugsource-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openexr-devel-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openexr-doc-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libIlmImf-2_2-23-32bit-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libIlmImfUtil-2_2-23-32bit-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libIlmImf-2_2-23-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libIlmImf-2_2-23-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libIlmImfUtil-2_2-23-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libIlmImfUtil-2_2-23-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openexr-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openexr-debuginfo-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openexr-debugsource-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openexr-devel-2.2.1-3.14.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openexr-doc-2.2.1-3.14.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openexr");
}
