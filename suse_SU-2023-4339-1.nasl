#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4339-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(184340);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/15");

  script_cve_id(
    "CVE-2023-32393",
    "CVE-2023-35074",
    "CVE-2023-37450",
    "CVE-2023-39434",
    "CVE-2023-39928",
    "CVE-2023-40451",
    "CVE-2023-41074",
    "CVE-2023-41993"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/16");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4339-1");

  script_name(english:"SUSE SLES15 Security Update : webkit2gtk3 (SUSE-SU-2023:4339-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:4339-1 advisory.

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 9.3, tvOS 16.3,
    macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. Processing web content may lead to arbitrary code execution.
    (CVE-2023-32393)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 17, Safari 17, watchOS
    10, iOS 17 and iPadOS 17, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-35074)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, Safari
    16.5.2, tvOS 16.6, macOS Ventura 13.5, watchOS 9.6. Processing web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been actively exploited. (CVE-2023-37450)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 17 and
    iPadOS 17, watchOS 10, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-39434)

  - A use-after-free vulnerability exists in the MediaRecorder API of Webkit WebKitGTK 2.40.5. A specially
    crafted web page can abuse this vulnerability to cause memory corruption and potentially arbitrary code
    execution. A user would need to to visit a malicious webpage to trigger this vulnerability.
    (CVE-2023-39928)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in Safari 17. An
    attacker with JavaScript execution may be able to execute arbitrary code. (CVE-2023-40451)

  - The issue was addressed with improved checks. This issue is fixed in tvOS 17, Safari 17, watchOS 10, iOS
    17 and iPadOS 17, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-41074)

  - The issue was addressed with improved checks. This issue is fixed in Safari 17, iOS 16.7 and iPadOS 16.7,
    macOS Sonoma 14. Processing web content may lead to arbitrary code execution. Apple is aware of a report
    that this issue may have been actively exploited against versions of iOS before iOS 16.7. (CVE-2023-41993)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216483");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-November/032584.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-37450");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-41074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-41993");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41993");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libwebkit2gtk3-lang-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libwebkit2gtk3-lang-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3', 'SUSE-Manager-Proxy-release-4.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3', 'SUSE-Manager-Proxy-release-4.2']},
    {'reference':'libwebkit2gtk3-lang-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3', 'SUSE-Manager-Proxy-release-4.2']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libwebkit2gtk3-lang-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libwebkit2gtk3-lang-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libwebkit2gtk-4_0-37-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'webkit2gtk3-devel-2.42.1-150200.87.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjavascriptcoregtk-4_0-18 / libwebkit2gtk-4_0-37 / etc');
}
