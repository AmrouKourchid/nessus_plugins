#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1014.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138674);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id("CVE-2020-8903", "CVE-2020-8907", "CVE-2020-8933");

  script_name(english:"openSUSE Security Update : google-compute-engine (openSUSE-2020-1014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for google-compute-engine fixes the following issues :

  - Don't enable and start google-network-daemon.service
    when it's already installed (bsc#1169978)

  + Do not add the created user to the adm (CVE-2020-8903),
    docker (CVE-2020-8907), or lxd (CVE-2020-8933) groups if
    they exist (bsc#1173258)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173258");
  script_set_attribute(attribute:"solution", value:
"Update the affected google-compute-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8933");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:google-compute-engine-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:google-compute-engine-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:google-compute-engine-oslogin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:google-compute-engine-oslogin-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:google-compute-engine-oslogin-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:google-compute-engine-oslogin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"google-compute-engine-debugsource-20190801-lp152.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"google-compute-engine-init-20190801-lp152.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"google-compute-engine-oslogin-20190801-lp152.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"google-compute-engine-oslogin-debuginfo-20190801-lp152.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"google-compute-engine-oslogin-32bit-20190801-lp152.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"google-compute-engine-oslogin-32bit-debuginfo-20190801-lp152.5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "google-compute-engine-debugsource / google-compute-engine-init / etc");
}
