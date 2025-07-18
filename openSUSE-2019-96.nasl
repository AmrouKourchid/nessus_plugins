#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-96.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121462);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/25");

  script_cve_id(
    "CVE-2018-0886",
    "CVE-2018-1000852",
    "CVE-2018-8784",
    "CVE-2018-8785",
    "CVE-2018-8786",
    "CVE-2018-8787",
    "CVE-2018-8788",
    "CVE-2018-8789"
  );

  script_name(english:"openSUSE Security Update : freerdp (openSUSE-2019-96)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for freerdp fixes the following issues :

Security issues fixed :

  - CVE-2018-0886: Fix a remote code execution vulnerability
    (CredSSP) (bsc#1085416, bsc#1087240, bsc#1104918)

  - CVE-2018-8789: Fix several denial of service
    vulnerabilities in the in the NTLM Authentication module
    (bsc#1117965)

  - CVE-2018-8785: Fix a potential remote code execution
    vulnerability in the zgfx_decompress function
    (bsc#1117967)

  - CVE-2018-8786: Fix a potential remote code execution
    vulnerability in the update_read_bitmap_update function
    (bsc#1117966)

  - CVE-2018-8787: Fix a potential remote code execution
    vulnerability in the gdi_Bitmap_Decompress function
    (bsc#1117964)

  - CVE-2018-8788: Fix a potential remote code execution
    vulnerability in the nsc_rle_decode function
    (bsc#1117963)

  - CVE-2018-8784: Fix a potential remote code execution
    vulnerability in the zgfx_decompress_segment function
    (bsc#1116708)

  - CVE-2018-1000852: Fixed a remote memory access in the
    drdynvc_process_capability_request function
    (bsc#1120507)

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120507");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0886");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"freerdp-2.0.0~git.1463131968.4e66df7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-debuginfo-2.0.0~git.1463131968.4e66df7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-debugsource-2.0.0~git.1463131968.4e66df7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-devel-2.0.0~git.1463131968.4e66df7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreerdp2-2.0.0~git.1463131968.4e66df7-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreerdp2-debuginfo-2.0.0~git.1463131968.4e66df7-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-debugsource / freerdp-devel / etc");
}
