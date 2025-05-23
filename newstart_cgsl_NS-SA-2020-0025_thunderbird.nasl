#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0025. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136909);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id(
    "CVE-2020-6792",
    "CVE-2020-6793",
    "CVE-2020-6794",
    "CVE-2020-6795",
    "CVE-2020-6798",
    "CVE-2020-6800"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2020-0025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - When processing an email message with an ill-formed
    envelope, Thunderbird could read data from a random
    memory location. This vulnerability affects Thunderbird
    < 68.5. (CVE-2020-6793)

  - When processing a message that contains multiple S/MIME
    signatures, a bug in the MIME processing code caused a
    null pointer dereference, leading to an unexploitable
    crash. This vulnerability affects Thunderbird < 68.5.
    (CVE-2020-6795)

  - When deriving an identifier for an email message,
    uninitialized memory was used in addition to the message
    contents. This vulnerability affects Thunderbird < 68.5.
    (CVE-2020-6792)

  - If a template tag was used in a select tag, the parser
    could be confused and allow JavaScript parsing and
    execution when it should not be allowed. A site that
    relied on the browser behaving correctly could suffer a
    cross-site scripting vulnerability as a result. In
    general, this flaw cannot be exploited through email in
    the Thunderbird product because scripting is disabled
    when reading mail, but is potentially a risk in browser
    or browser-like contexts. This vulnerability affects
    Thunderbird < 68.5, Firefox < 73, and Firefox < ESR68.5.
    (CVE-2020-6798)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 72 and Firefox ESR 68.4.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. In
    general, these flaws cannot be exploited through email
    in the Thunderbird product because scripting is disabled
    when reading mail, but are potentially risks in browser
    or browser-like contexts. This vulnerability affects
    Thunderbird < 68.5, Firefox < 73, and Firefox < ESR68.5.
    (CVE-2020-6800)

  - If a user saved passwords before Thunderbird 60 and then
    later set a master password, an unencrypted copy of
    these passwords is still accessible. This is because the
    older stored password file was not deleted when the data
    was copied to a new format starting in Thunderbird 60.
    The new master password is added only on the new file.
    This could allow the exposure of stored password data
    outside of user expectations. This vulnerability affects
    Thunderbird < 68.5. (CVE-2020-6794)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0025");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "thunderbird-68.5.0-1.el7.centos",
    "thunderbird-debuginfo-68.5.0-1.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "thunderbird-68.5.0-1.el7.centos",
    "thunderbird-debuginfo-68.5.0-1.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
