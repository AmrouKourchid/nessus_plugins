#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0177. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154471);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2020-15685",
    "CVE-2020-16044",
    "CVE-2020-26976",
    "CVE-2021-23953",
    "CVE-2021-23954",
    "CVE-2021-23960",
    "CVE-2021-23964",
    "CVE-2021-23968",
    "CVE-2021-23969",
    "CVE-2021-23973",
    "CVE-2021-23978"
  );
  script_xref(name:"IAVA", value:"2021-A-0040-S");
  script_xref(name:"IAVA", value:"2021-A-0005-S");
  script_xref(name:"IAVA", value:"2020-A-0575-S");
  script_xref(name:"IAVA", value:"2021-A-0051-S");
  script_xref(name:"IAVA", value:"2021-A-0107-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : thunderbird Multiple Vulnerabilities (NS-SA-2021-0177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - Use after free in WebRTC in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted SCTP packet. (CVE-2020-16044)

  - When a HTTPS pages was embedded in a HTTP page, and there was a service worker registered for the former,
    the service worker could have intercepted the request for the secure page despite the iframe not being a
    secure context due to the (insecure) framing. This vulnerability affects Firefox < 84. (CVE-2020-26976)

  - If a user clicked into a specifically crafted PDF, the PDF reader could be confused into leaking cross-
    origin information, when said information is served as chunked data. This vulnerability affects Firefox <
    85, Thunderbird < 78.7, and Firefox ESR < 78.7. (CVE-2021-23953)

  - Using the new logical assignment operators in a JavaScript switch statement could have caused a type
    confusion, leading to a memory corruption and a potentially exploitable crash. This vulnerability affects
    Firefox < 85, Thunderbird < 78.7, and Firefox ESR < 78.7. (CVE-2021-23954)

  - Performing garbage collection on re-declared JavaScript variables resulted in a user-after-poison, and a
    potentially exploitable crash. This vulnerability affects Firefox < 85, Thunderbird < 78.7, and Firefox
    ESR < 78.7. (CVE-2021-23960)

  - Mozilla developers reported memory safety bugs present in Firefox 84 and Firefox ESR 78.6. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 85, Thunderbird < 78.7, and
    Firefox ESR < 78.7. (CVE-2021-23964)

  - If Content Security Policy blocked frame navigation, the full destination of a redirect served in the
    frame was reported in the violation report; as opposed to the original frame URI. This could be used to
    leak sensitive information contained in such URIs. This vulnerability affects Firefox < 86, Thunderbird <
    78.8, and Firefox ESR < 78.8. (CVE-2021-23968)

  - As specified in the W3C Content Security Policy draft, when creating a violation report, User agents need
    to ensure that the source file is the URL requested by the page, pre-redirects. If that's not possible,
    user agents need to strip the URL down to an origin to avoid unintentional leakage. Under certain types
    of redirects, Firefox incorrectly set the source file to be the destination of the redirects. This was
    fixed to be the redirect destination's origin. This vulnerability affects Firefox < 86, Thunderbird <
    78.8, and Firefox ESR < 78.8. (CVE-2021-23969)

  - When trying to load a cross-origin resource in an audio/video context a decoding error may have resulted,
    and the content of that error may have revealed information about the resource. This vulnerability affects
    Firefox < 86, Thunderbird < 78.8, and Firefox ESR < 78.8. (CVE-2021-23973)

  - Mozilla developers reported memory safety bugs present in Firefox 85 and Firefox ESR 78.7. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 86, Thunderbird < 78.8, and
    Firefox ESR < 78.8. (CVE-2021-23978)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0177");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15685");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16044");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26976");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23953");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23954");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23960");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23964");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23968");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23969");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23973");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23978");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23978");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:thunderbird");
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
    'thunderbird-78.8.0-1.el7.centos'
  ],
  'CGSL MAIN 5.05': [
    'thunderbird-78.8.0-1.el7.centos'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
