#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4928-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(187145);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id(
    "CVE-2023-6204",
    "CVE-2023-6205",
    "CVE-2023-6206",
    "CVE-2023-6207",
    "CVE-2023-6208",
    "CVE-2023-6209",
    "CVE-2023-6212",
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-6865",
    "CVE-2023-6867"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4928-1");
  script_xref(name:"IAVA", value:"2023-A-0702-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaFirefox (SUSE-SU-2023:4928-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2023:4928-1 advisory.

  - On some systemsdepending on the graphics settings and driversit was possible to force an out-of-bounds
    read and leak memory data into the images created on the canvas element. This vulnerability affects
    Firefox < 120, Firefox ESR < 115.5.0, and Thunderbird < 115.5. (CVE-2023-6204)

  - It was possible to cause the use of a MessagePort after it had already been freed, which could potentially
    have led to an exploitable crash. This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and
    Thunderbird < 115.5. (CVE-2023-6205)

  - The black fade animation when exiting fullscreen is roughly the length of the anti-clickjacking delay on
    permission prompts. It was possible to use this fact to surprise users by luring them to click where the
    permission grant button would be about to appear. This vulnerability affects Firefox < 120, Firefox ESR <
    115.5.0, and Thunderbird < 115.5. (CVE-2023-6206)

  - Ownership mismanagement led to a use-after-free in ReadableByteStreams This vulnerability affects Firefox
    < 120, Firefox ESR < 115.5.0, and Thunderbird < 115.5. (CVE-2023-6207)

  - When using X11, text selected by the page using the Selection API was erroneously copied into the primary
    selection, a temporary storage not unlike the clipboard. *This bug only affects Firefox on X11. Other
    systems are unaffected.* This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and Thunderbird
    < 115.5. (CVE-2023-6208)

  - Relative URLs starting with three slashes were incorrectly parsed, and a path-traversal /../ part in the
    path could be used to override the specified host. This could contribute to security problems in web
    sites. This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and Thunderbird < 115.5.
    (CVE-2023-6209)

  - Memory safety bugs present in Firefox 119, Firefox ESR 115.4, and Thunderbird 115.4. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and
    Thunderbird < 115.5. (CVE-2023-6212)

  - The WebGL `DrawElementsInstanced` method was susceptible to a heap buffer overflow when used on systems
    with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and sandbox
    escape. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6856)

  - When resolving a symlink, a race may occur where the buffer passed to `readlink` may actually be smaller
    than necessary. *This bug only affects Firefox on Unix-based operating systems (Android, Linux, MacOS).
    Windows is unaffected.* This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox <
    121. (CVE-2023-6857)

  - Firefox was susceptible to a heap buffer overflow in `nsTextFragment` due to insufficient OOM handling.
    This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. This vulnerability
    affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6859)

  - The `VideoBridge` allowed any content process to use textures produced by remote decoders. This could be
    abused to escape the sandbox. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6860)

  - The `nsWindow::PickerOpen(void)` method was susceptible to a heap buffer overflow when running in headless
    mode. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6861)

  - A use-after-free was identified in the `nsDNSService::Init`. This issue appears to manifest rarely during
    start-up. This vulnerability affects Firefox ESR < 115.6 and Thunderbird < 115.6. (CVE-2023-6862)

  - The `ShutdownObserver()` was susceptible to potentially undefined behavior due to its reliance on a
    dynamic type that lacked a virtual destructor. This vulnerability affects Firefox ESR < 115.6, Thunderbird
    < 115.6, and Firefox < 121. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6864)

  - `EncryptingOutputStream` was susceptible to exposing uninitialized data. This issue could only be abused
    in order to write data to a local disk which may have implications for private browsing mode. This
    vulnerability affects Firefox ESR < 115.6 and Firefox < 121. (CVE-2023-6865)

  - The timing of a button click causing a popup to disappear was approximately the same length as the anti-
    clickjacking delay on permission prompts. It was possible to use this fact to surprise users by luring
    them to click where the permission grant button would be about to appear. This vulnerability affects
    Firefox ESR < 115.6 and Firefox < 121. (CVE-2023-6867)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217974");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-December/017506.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22f447fa");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6212");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6867");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6864");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SLE_RT-release-15.4']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SLE_HPC-release-15.4', 'SLE_RT-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SLE_RT-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SLE_RT-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-branding-upstream-115.6.0-150200.152.120.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaFirefox-branding-upstream-115.6.0-150200.152.120.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'MozillaFirefox-devel-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'MozillaFirefox-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'MozillaFirefox-translations-common-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'MozillaFirefox-translations-other-115.6.0-150200.152.120.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-branding-upstream / etc');
}
