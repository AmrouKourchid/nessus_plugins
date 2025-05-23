#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1824.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(127737);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id("CVE-2019-11068", "CVE-2019-5419");

  script_name(english:"openSUSE Security Update : rmt-server (openSUSE-2019-1824)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for rmt-server to version 2.3.1 fixes the following 
issues :

  - Fix mirroring logic when errors are encountered
    (bsc#1140492)

  - Refactor RMT::Mirror to download metadata/licenses in
    parallel

  - Check repo metadata GPG signatures during mirroring
    (bsc#1132690)

  - Add rmt-server-config subpackage with nginx configs
    (fate#327816, bsc#1136081)

  - Fix dependency to removed boot_cli_i18n file
    (bsc#1136020) 

  - Add `rmt-cli systems list` command to list registered
    systems

  - Fix create UUID when system_uuid file empty
    (bsc#1138316)

  - Fix duplicate nginx location in rmt-server-pubcloud
    (bsc#1135222)

  - Mirror additional repos that were enabled during
    mirroring (bsc#1132690)

  - Make service IDs consistent across different RMT
    instances (bsc#1134428)

  - Make SMT data import scripts faster (bsc#1134190)

  - Fix incorrect triggering of registration sharing
    (bsc#1129392)

  - Fix license mirroring issue in some non-SUSE
    repositories (bsc#1128858)

  - Update dependencies to fix vulnerabilities in rails
    (CVE-2019-5419, bsc#1129271) and nokogiri
    (CVE-2019-11068, bsc#1132160)

  - Allow RMT registration to work under HTTP as well as
    HTTPS.

  - Offline migration from SLE 15 to SLE 15 SP1 will add
    Python2 module 

  - Online migrations will automatically add additional
    modules to the client systems depending on the base
    product

  - Supply log severity to journald

  - Breaking Change: Added headers to generated CSV files

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140492");
  script_set_attribute(attribute:"see_also", value:"https://features.opensuse.org/327816");
  script_set_attribute(attribute:"solution", value:
"Update the affected rmt-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rmt-server-pubcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-2.3.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-config-2.3.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-debuginfo-2.3.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-debugsource-2.3.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rmt-server-pubcloud-2.3.1-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rmt-server / rmt-server-config / rmt-server-debuginfo / etc");
}
