#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1039.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123164);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id("CVE-2018-0495", "CVE-2018-12384", "CVE-2018-12404");

  script_name(english:"openSUSE Security Update : mozilla-nspr and mozilla-nss (openSUSE-2019-1039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for mozilla-nss and mozilla-nspr fixes the following
issues :

Issues fixed in mozilla-nss :

  - Update to NSS 3.40.1 (bsc#1119105)

  - CVE-2018-12404: Fixed a cache side-channel variant of
    the Bleichenbacher attack (bsc#1119069)

  - CVE-2018-12384: Fixed an issue in the SSL handshake. NSS
    responded to an SSLv2-compatible ClientHello with a
    ServerHello that had an all-zero random. (bsc#1106873)

  - CVE-2018-0495: Fixed a memory-cache side-channel attack
    with ECDSA signatures (bsc#1097410)

  - Fixed a decryption failure during FFDHE key exchange

  - Various security fixes in the ASN.1 code

Issues fixed in mozilla-nspr :

  - Update mozilla-nspr to 4.20 (bsc#1119105)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119105");
  script_set_attribute(attribute:"solution", value:
"Update the affected mozilla-nspr and mozilla-nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12404");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libfreebl3-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfreebl3-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsoftokn3-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsoftokn3-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nspr-4.20-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nspr-debuginfo-4.20-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nspr-debugsource-4.20-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nspr-devel-4.20-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-certs-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-certs-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-debugsource-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-devel-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-sysinit-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-sysinit-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-tools-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mozilla-nss-tools-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libfreebl3-32bit-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsoftokn3-32bit-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.20-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nspr-32bit-debuginfo-4.20-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nss-32bit-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.40.1-lp150.2.10.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-debuginfo-3.40.1-lp150.2.10.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-nspr-32bit / mozilla-nspr-32bit-debuginfo / mozilla-nspr / etc");
}
