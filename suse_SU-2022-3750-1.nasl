#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3750-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181673);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/20");

  script_cve_id(
    "CVE-2021-41411",
    "CVE-2021-42740",
    "CVE-2021-43138",
    "CVE-2022-0860",
    "CVE-2022-31129"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3750-1");

  script_name(english:"SUSE SLES15 Security Update : SUSE Manager Proxy 4.3 (SUSE-SU-2022:3750-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3750-1 advisory.

  - The shell-quote package before 1.7.3 for Node.js allows command injection. An attacker can inject
    unescaped shell metacharacters through a regex designed to support Windows drive letters. If the output of
    this package is passed to a real shell as a quoted argument to a command with exec(), an attacker can
    inject arbitrary commands. This is because the Windows drive letter regex character class is {A-z] instead
    of the correct {A-Za-z]. Several shell metacharacters exist in the space between capital letter Z and
    lower case letter a, such as the backtick character. (CVE-2021-42740)

  - In Async before 2.6.4 and 3.x before 3.2.2, a malicious user can obtain privileges via the mapValues()
    method, aka lib/internal/iterator.js createObjectIterator prototype pollution. (CVE-2021-43138)

  - moment is a JavaScript date library for parsing, validating, manipulating, and formatting dates. Affected
    versions of moment were found to use an inefficient parsing algorithm. Specifically using string-to-date
    parsing in moment (more specifically rfc2822 parsing, which is tried by default) has quadratic (N^2)
    complexity on specific inputs. Users may notice a noticeable slowdown is observed with inputs above 10k
    characters. Users who pass user-provided strings without sanity length checks to moment constructor are
    vulnerable to (Re)DoS attacks. The problem is patched in 2.29.4, the patch can be applied to all affected
    versions with minimal tweaking. Users are advised to upgrade. Users unable to upgrade should consider
    limiting date lengths accepted from user input. (CVE-2022-31129)

  - drools <=7.59.x is affected by an XML External Entity (XXE) vulnerability in KieModuleMarshaller.java. The
    Validator class is not used correctly, resulting in the XXE injection vulnerability. (CVE-2021-41411)

  - Improper Authorization in GitHub repository cobbler/cobbler prior to 3.3.2. (CVE-2022-0860)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204208");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012699.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6abe831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41411");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31129");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42740");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:drools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:image-sync-formula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:inter-server-sync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:locale-formula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-urlgrabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-uyuni-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reprepro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:saltboot-formula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base-minimal-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-utils-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subscription-matcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-build-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-build-keys-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-docs_en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-docs_en-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-schema-utility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-sls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-sync-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-tftpsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-tftpsync-recv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-config-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-reportdb-schema");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'mgr-daemon-4.3.6-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'python3-spacewalk-certs-tools-4.3.15-150400.3.6.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-spacewalk-check-4.3.12-150400.3.6.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'python3-spacewalk-client-setup-4.3.12-150400.3.6.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'python3-spacewalk-client-tools-4.3.12-150400.3.6.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-uyuni-common-libs-4.3.6-150400.3.6.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacecmd-4.3.15-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-base-minimal-4.3.24-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-base-minimal-config-4.3.24-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-certs-tools-4.3.15-150400.3.6.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-check-4.3.12-150400.3.6.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-client-setup-4.3.12-150400.3.6.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-client-tools-4.3.12-150400.3.6.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-build-keys-15.4.3-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-build-keys-web-15.4.3-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-tftpsync-recv-4.3.7-150400.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'cobbler-3.3.3-150400.5.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'drools-7.17.0-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'image-sync-formula-0.1.1661440542.6cbe0da-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'inter-server-sync-0.2.3-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'locale-formula-0.3-150400.3.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-magic-5.32-150000.7.16.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-schema-0.6.7-150400.10.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-urlgrabber-4.1.0-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-uyuni-common-libs-4.3.6-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'reprepro-5.4.0-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'saltboot-formula-0.1.1661440542.6cbe0da-150400.3.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-admin-4.3.10-150400.3.3.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-app-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-applet-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-config-files-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-config-files-common-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-config-files-tool-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-iss-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-iss-export-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-package-push-server-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-server-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-sql-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-sql-postgresql-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-tools-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-xml-export-libs-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-xmlrpc-4.3.16-150400.3.6.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-base-4.3.24-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-html-4.3.24-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-4.3.38-150400.3.8.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-config-4.3.38-150400.3.8.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-lib-4.3.38-150400.3.8.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-postgresql-4.3.38-150400.3.8.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-search-4.3.7-150400.3.6.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-setup-4.3.12-150400.3.8.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-taskomatic-4.3.38-150400.3.8.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-utils-4.3.14-150400.3.6.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-utils-extras-4.3.14-150400.3.6.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'subscription-matcher-0.29-150400.3.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-4.3.19-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-docs_en-4.3-150400.9.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-docs_en-pdf-4.3-150400.9.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-schema-4.3.14-150400.3.6.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-schema-utility-4.3.14-150400.3.6.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-sls-4.3.25-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-sync-data-4.3.9-150400.3.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-tftpsync-4.3.2-150400.3.3.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-tools-4.3.19-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'uyuni-config-modules-4.3.25-150400.3.6.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'uyuni-reportdb-schema-4.3.6-150400.3.3.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cobbler / drools / image-sync-formula / inter-server-sync / etc');
}
