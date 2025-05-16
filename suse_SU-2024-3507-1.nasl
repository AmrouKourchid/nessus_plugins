#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3507-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(208022);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2024-6600",
    "CVE-2024-6601",
    "CVE-2024-6602",
    "CVE-2024-6603",
    "CVE-2024-6604",
    "CVE-2024-6606",
    "CVE-2024-6607",
    "CVE-2024-6608",
    "CVE-2024-6609",
    "CVE-2024-6610",
    "CVE-2024-6611",
    "CVE-2024-6612",
    "CVE-2024-6613",
    "CVE-2024-6614",
    "CVE-2024-6615",
    "CVE-2024-7518",
    "CVE-2024-7519",
    "CVE-2024-7520",
    "CVE-2024-7521",
    "CVE-2024-7522",
    "CVE-2024-7525",
    "CVE-2024-7526",
    "CVE-2024-7527",
    "CVE-2024-7528",
    "CVE-2024-7529",
    "CVE-2024-8381",
    "CVE-2024-8382",
    "CVE-2024-8384",
    "CVE-2024-8385",
    "CVE-2024-8386",
    "CVE-2024-8387",
    "CVE-2024-8394"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3507-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaThunderbird (SUSE-SU-2024:3507-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:3507-1 advisory.

    - Mozilla Thunderbird 128.2.3
      MFSA 2024-43 (bsc#1229821)
      * CVE-2024-8394: Crash when aborting verification of OTR chat.
      * CVE-2024-8385: WASM type confusion involving ArrayTypes.
      * CVE-2024-8381: Type confusion when looking up a property name in a 'with' block.
      * CVE-2024-8382: Internal event interfaces were exposed to web content when browser EventHandler
    listener callbacks
        ran.
      * CVE-2024-8384: Garbage collection could mis-color cross-compartment objects in OOM conditions.
      * CVE-2024-8386: SelectElements could be shown over another site if popups are allowed.
      * CVE-2024-8387: Memory safety bugs fixed in Firefox 130, Firefox ESR 128.2, and Thunderbird 128.2.
      MFSA 2024-37 (bsc#1228648)
      * CVE-2024-7518: Fullscreen notification dialog can be obscured by document content.
      * CVE-2024-7519: Out of bounds memory access in graphics shared memory handling.
      * CVE-2024-7520: Type confusion in WebAssembly.
      * CVE-2024-7521: Incomplete WebAssembly exception handing.
      * CVE-2024-7522: Out of bounds read in editor component.
      * CVE-2024-7525: Missing permission check when creating a StreamFilter.
      * CVE-2024-7526: Uninitialized memory used by WebGL.
      * CVE-2024-7527: Use-after-free in JavaScript garbage collection.
      * CVE-2024-7528: Use-after-free in IndexedDB.
      * CVE-2024-7529: Document content could partially obscure security prompts.
      MFSA 2024-32 (bsc#1226316)
      * CVE-2024-6606: Out-of-bounds read in clipboard component.
      * CVE-2024-6607: Leaving pointerlock by pressing the escape key could be prevented.
      * CVE-2024-6608: Cursor could be moved out of the viewport using pointerlock.
      * CVE-2024-6609: Memory corruption in NSS.
      * CVE-2024-6610: Form validation popups could block exiting full-screen mode.
      * CVE-2024-6600: Memory corruption in WebGL API.
      * CVE-2024-6601: Race condition in permission assignment.
      * CVE-2024-6602: Memory corruption in NSS.
      * CVE-2024-6603: Memory corruption in thread creation.
      * CVE-2024-6611: Incorrect handling of SameSite cookies.
      * CVE-2024-6612: CSP violation leakage when using devtools.
      * CVE-2024-6613: Incorrect listing of stack frames.
      * CVE-2024-6614: Incorrect listing of stack frames.
      * CVE-2024-6604: Memory safety bugs fixed in Firefox 128, Firefox ESR 115.13, Thunderbird 128, and
    Thunderbird
        115.13.
      * CVE-2024-6615: Memory safety bugs fixed in Firefox 128 and Thunderbird 128.

    Bug fixes:
    - Recommend libfido2-udev in order to try to get security keys (e.g. Yubikeys) working out of the box.
    (bsc#1184272)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229821");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-October/019538.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbd7d3e5");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8394");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'MozillaThunderbird-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'MozillaThunderbird-translations-common-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'MozillaThunderbird-translations-other-128.2.3-150200.8.177.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
