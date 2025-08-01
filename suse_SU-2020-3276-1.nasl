#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3276-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143763);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/05");

  script_cve_id("CVE-2020-8695", "CVE-2020-8698");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ucode-intel (SUSE-SU-2020:3276-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for ucode-intel fixes the following issues :

Intel CPU Microcode updated to 20201027 prerelease

CVE-2020-8695: Fixed Intel RAPL sidechannel attack (SGX) (bsc#1170446)

CVE-2020-8698: Fixed Fast Store Forward Predictor INTEL-SA-00381
(bsc#1173594)

# New Platforms: | Processor | Stepping | F-M-S/PI | Old Ver | New Ver
| Products
|:---------------|:---------|:------------|:---------|:---------|:----
----- | TGL | B1 | 06-8c-01/80 | | 00000068 | Core Gen11 Mobile |
CPX-SP | A1 | 06-55-0b/bf | | 0700001e | Xeon Scalable Gen3 | CML-H |
R1 | 06-a5-02/20 | | 000000e0 | Core Gen10 Mobile | CML-S62 | G1 |
06-a5-03/22 | | 000000e0 | Core Gen10 | CML-S102 | Q0 | 06-a5-05/22 |
| 000000e0 | Core Gen10 | CML-U62 V2 | K0 | 06-a6-01/80 | | 000000e0 |
Core Gen10 Mobile # Updated Platforms: | Processor | Stepping |
F-M-S/PI | Old Ver | New Ver | Products
|:---------------|:---------|:------------|:---------|:---------|:----
----- | GKL-R | R0 | 06-7a-08/01 | 00000016 | 00000018 | Pentium
J5040/N5030, Celeron J4125/J4025/N4020/N4120 | SKL-U/Y | D0 |
06-4e-03/c0 | 000000d6 | 000000e2 | Core Gen6 Mobile | SKL-U23e | K1 |
06-4e-03/c0 | 000000d6 | 000000e2 | Core Gen6 Mobile | APL | D0 |
06-5c-09/03 | 00000038 | 00000040 | Pentium N/J4xxx, Celeron N/J3xxx,
Atom x5/7-E39xx | APL | E0 | 06-5c-0a/03 | 00000016 | 0000001e | Atom
x5-E39xx | SKL-H/S | R0/N0 | 06-5e-03/36 | 000000d6 | 000000e2 | Core
Gen6; Xeon E3 v5 | HSX-E/EP | Cx/M1 | 06-3f-02/6f | 00000043 |
00000044 | Core Gen4 X series; Xeon E5 v3 | SKX-SP | B1 | 06-55-03/97
| 01000157 | 01000159 | Xeon Scalable | SKX-SP | H0/M0/U0 |
06-55-04/b7 | 02006906 | 02006a08 | Xeon Scalable | SKX-D | M1 |
06-55-04/b7 | 02006906 | 02006a08 | Xeon D-21xx | CLX-SP | B0 |
06-55-06/bf | 04002f01 | 04003003 | Xeon Scalable Gen2 | CLX-SP | B1 |
06-55-07/bf | 05002f01 | 05003003 | Xeon Scalable Gen2 | ICL-U/Y | D1
| 06-7e-05/80 | 00000078 | 000000a0 | Core Gen10 Mobile | AML-Y22 | H0
| 06-8e-09/10 | 000000d6 | 000000de | Core Gen8 Mobile | KBL-U/Y | H0
| 06-8e-09/c0 | 000000d6 | 000000de | Core Gen7 Mobile | CFL-U43e | D0
| 06-8e-0a/c0 | 000000d6 | 000000e0 | Core Gen8 Mobile | WHL-U | W0 |
06-8e-0b/d0 | 000000d6 | 000000de | Core Gen8 Mobile | AML-Y42 | V0 |
06-8e-0c/94 | 000000d6 | 000000de | Core Gen10 Mobile | CML-Y42 | V0 |
06-8e-0c/94 | 000000d6 | 000000de | Core Gen10 Mobile | WHL-U | V0 |
06-8e-0c/94 | 000000d6 | 000000de | Core Gen8 Mobile | KBL-G/H/S/E3 |
B0 | 06-9e-09/2a | 000000d6 | 000000de | Core Gen7; Xeon E3 v6 |
CFL-H/S/E3 | U0 | 06-9e-0a/22 | 000000d6 | 000000de | Core Gen8
Desktop, Mobile, Xeon E | CFL-S | B0 | 06-9e-0b/02 | 000000d6 |
000000de | Core Gen8 | CFL-H/S | P0 | 06-9e-0c/22 | 000000d6 |
000000de | Core Gen9 | CFL-H | R0 | 06-9e-0d/22 | 000000d6 | 000000de
| Core Gen9 Mobile | CML-U62 | A0 | 06-a6-00/80 | 000000ca | 000000e0
| Core Gen10 Mobile

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8695/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8698/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203276-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d8efbc5");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3276=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8698");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ucode-intel-20201027-3.33.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ucode-intel-20201027-3.33.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ucode-intel");
}
