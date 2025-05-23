#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0137. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154596);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2020-6463",
    "CVE-2020-6514",
    "CVE-2020-12405",
    "CVE-2020-12406",
    "CVE-2020-12410",
    "CVE-2020-12417",
    "CVE-2020-12418",
    "CVE-2020-12419",
    "CVE-2020-12420",
    "CVE-2020-12421",
    "CVE-2020-15652",
    "CVE-2020-15659",
    "CVE-2020-15664",
    "CVE-2020-15669"
  );
  script_xref(name:"IAVA", value:"2020-A-0238-S");
  script_xref(name:"IAVA", value:"2020-A-0344-S");
  script_xref(name:"IAVA", value:"2020-A-0287-S");
  script_xref(name:"IAVA", value:"2020-A-0391-S");
  script_xref(name:"IAVA", value:"2020-A-0314-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : firefox Multiple Vulnerabilities (NS-SA-2021-0137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has firefox packages installed that are affected
by multiple vulnerabilities:

  - When browsing a malicious page, a race condition in our SharedWorkerService could occur and lead to a
    potentially exploitable crash. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox
    ESR < 68.9. (CVE-2020-12405)

  - Mozilla Developer Iain Ireland discovered a missing type check during unboxed objects removal, resulting
    in a crash. We presume that with enough effort that it could be exploited to run arbitrary code. This
    vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox ESR < 68.9. (CVE-2020-12406)

  - Mozilla developers reported memory safety bugs present in Firefox 76 and Firefox ESR 68.8. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and
    Firefox ESR < 68.9. (CVE-2020-12410)

  - Due to confusion about ValueTags on JavaScript Objects, an object may pass through the type barrier,
    resulting in memory corruption and a potentially exploitable crash. *Note: this issue only affects Firefox
    on ARM64 platforms.* This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and Thunderbird <
    68.10.0. (CVE-2020-12417)

  - Manipulating individual parts of a URL object could have caused an out-of-bounds read, leaking process
    memory to malicious JavaScript. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12418)

  - When processing callbacks that occurred during window flushing in the parent process, the associated
    window may die; causing a use-after-free condition. This could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12419)

  - When trying to connect to a STUN server, a race condition could have caused a use-after-free of a pointer,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox ESR <
    68.10, Firefox < 78, and Thunderbird < 68.10.0. (CVE-2020-12420)

  - When performing add-on updates, certificate chains terminating in non-built-in-roots were rejected (even
    if they were legitimately added by an administrator.) This could have caused add-ons to become out-of-date
    silently without notification to the user. This vulnerability affects Firefox ESR < 68.10, Firefox < 78,
    and Thunderbird < 68.10.0. (CVE-2020-12421)

  - By observing the stack trace for JavaScript errors in web workers, it was possible to leak the result of a
    cross-origin redirect. This applied only to content that can be parsed as script. This vulnerability
    affects Firefox < 79, Firefox ESR < 68.11, Firefox ESR < 78.1, Thunderbird < 68.11, and Thunderbird <
    78.1. (CVE-2020-15652)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 78 and Firefox ESR
    78.0. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 79, Firefox
    ESR < 68.11, Firefox ESR < 78.1, Thunderbird < 68.11, and Thunderbird < 78.1. (CVE-2020-15659)

  - By holding a reference to the eval() function from an about:blank window, a malicious webpage could have
    gained access to the InstallTrigger object which would allow them to prompt the user to install an
    extension. Combined with user confusion, this could result in an unintended or malicious extension being
    installed. This vulnerability affects Firefox < 80, Thunderbird < 78.2, Thunderbird < 68.12, Firefox ESR <
    68.12, Firefox ESR < 78.2, and Firefox for Android < 80. (CVE-2020-15664)

  - When aborting an operation, such as a fetch, an abort signal may be deleted while alerting the objects to
    be notified. This results in a use-after-free and we presume that with enough effort it could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 68.12 and Thunderbird < 68.12.
    (CVE-2020-15669)

  - Use after free in ANGLE in Google Chrome prior to 81.0.4044.122 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6463)

  - Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a
    privileged network position to potentially exploit heap corruption via a crafted SCTP stream.
    (CVE-2020-6514)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0137");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12405");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12406");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12410");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12417");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12418");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12419");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12420");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12421");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15652");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15659");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15664");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15669");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-6463");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-6514");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15659");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6463");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'firefox-68.12.0-1.el7.centos',
    'firefox-debuginfo-68.12.0-1.el7.centos'
  ],
  'CGSL MAIN 5.05': [
    'firefox-68.12.0-1.el7.centos',
    'firefox-debuginfo-68.12.0-1.el7.centos'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
