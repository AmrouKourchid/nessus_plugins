#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4084-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212540);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2024-40866",
    "CVE-2024-44185",
    "CVE-2024-44187",
    "CVE-2024-44244",
    "CVE-2024-44296"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4084-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : webkit2gtk3 (SUSE-SU-2024:4084-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:4084-1 advisory.

    Update to version 2.46.3 (bsc#1232747):

    - CVE-2024-44244: Processing maliciously crafted web content may lead to an unexpected process crash.
    - CVE-2024-44296: Processing maliciously crafted web content may prevent Content Security Policy from
    being enforced.
    - CVE-2024-40866: Visiting a malicious website may lead to address bar spoofing.

    New references to version 2.46.0 (boo#1231039):

    - CVE-2024-44187: A cross- origin issue existed with iframe elements. This was addressed with
    improved tracking of security origins.
    - CVE-2024-44185: Processing maliciously crafted web content may lead to an unexpected process crash.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232747");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019850.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3831317c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44296");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:WebKitGTK-4.0-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:WebKitGTK-4.1-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:WebKitGTK-6.0-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-6_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkitgtk-6_0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-6_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit-6_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKitWebProcessExtension-6_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_1-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-soup2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkitgtk-6_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'WebKitGTK-4.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'WebKitGTK-4.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'WebKitGTK-4.1-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'WebKitGTK-4.1-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'WebKitGTK-6.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'WebKitGTK-6.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libjavascriptcoregtk-6_0-1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libjavascriptcoregtk-6_0-1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libwebkit2gtk-4_0-37-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libwebkit2gtk-4_0-37-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libwebkit2gtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libwebkit2gtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libwebkitgtk-6_0-4-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libwebkitgtk-6_0-4-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKitWebProcessExtension-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'typelib-1_0-WebKitWebProcessExtension-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk3-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk3-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk3-soup2-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk3-soup2-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk4-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkit2gtk4-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkitgtk-6_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'webkitgtk-6_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'WebKitGTK-4.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'WebKitGTK-4.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'WebKitGTK-4.1-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'WebKitGTK-4.1-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'WebKitGTK-6.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'WebKitGTK-6.0-lang-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libjavascriptcoregtk-6_0-1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libjavascriptcoregtk-6_0-1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libwebkit2gtk-4_0-37-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libwebkit2gtk-4_0-37-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libwebkit2gtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libwebkit2gtk-4_1-0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libwebkitgtk-6_0-4-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libwebkitgtk-6_0-4-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKitWebProcessExtension-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'typelib-1_0-WebKitWebProcessExtension-6_0-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk3-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk3-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk3-soup2-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk3-soup2-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk4-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkit2gtk4-devel-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkitgtk-6_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'webkitgtk-6_0-injected-bundles-2.46.3-150600.12.16.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'WebKitGTK-4.0-lang-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'WebKitGTK-4.1-lang-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'WebKitGTK-6.0-lang-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.46.3-150600.12.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libjavascriptcoregtk-4_1-0-32bit-2.46.3-150600.12.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libjavascriptcoregtk-6_0-1-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libwebkit2gtk-4_0-37-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libwebkit2gtk-4_0-37-32bit-2.46.3-150600.12.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libwebkit2gtk-4_1-0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libwebkit2gtk-4_1-0-32bit-2.46.3-150600.12.16.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libwebkitgtk-6_0-4-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-JavaScriptCore-6_0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-WebKit-6_0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'typelib-1_0-WebKitWebProcessExtension-6_0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit-jsc-4-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit-jsc-4.1-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit-jsc-6.0-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk3-devel-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk3-minibrowser-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk3-soup2-devel-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk3-soup2-minibrowser-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk4-devel-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkit2gtk4-minibrowser-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'webkitgtk-6_0-injected-bundles-2.46.3-150600.12.16.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'WebKitGTK-4.0-lang / WebKitGTK-4.1-lang / WebKitGTK-6.0-lang / etc');
}
