#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-26.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(190762);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2024-0741",
    "CVE-2024-0742",
    "CVE-2024-0743",
    "CVE-2024-0744",
    "CVE-2024-0745",
    "CVE-2024-0746",
    "CVE-2024-0747",
    "CVE-2024-0748",
    "CVE-2024-0749",
    "CVE-2024-0750",
    "CVE-2024-0751",
    "CVE-2024-0752",
    "CVE-2024-0753",
    "CVE-2024-0754",
    "CVE-2024-0755"
  );
  script_xref(name:"IAVA", value:"2024-A-0174-S");

  script_name(english:"GLSA-202402-26 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-26 (Mozilla Firefox: Multiple Vulnerabilities)

  - An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially
    exploitable crash. This vulnerability affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7.
    (CVE-2024-0741)

  - It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by
    the user due to an incorrect timestamp used to prevent input after page load. This vulnerability affects
    Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0742)

  - An unchecked return value in TLS handshake code could have caused a potentially exploitable crash. This
    vulnerability affects Firefox < 122. (CVE-2024-0743)

  - In some circumstances, JIT compiled code could have dereferenced a wild pointer value. This could have led
    to an exploitable crash. This vulnerability affects Firefox < 122. (CVE-2024-0744)

  - The WebAudio `OscillatorNode` object was susceptible to a stack buffer overflow. This could have led to a
    potentially exploitable crash. This vulnerability affects Firefox < 122. (CVE-2024-0745)

  - A Linux user opening the print preview dialog could have caused the browser to crash. This vulnerability
    affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0746)

  - When a parent page loaded a child in an iframe with `unsafe-inline`, the parent Content Security Policy
    could have overridden the child Content Security Policy. This vulnerability affects Firefox < 122, Firefox
    ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0747)

  - A compromised content process could have updated the document URI. This could have allowed an attacker to
    set an arbitrary URI in the address bar or history. This vulnerability affects Firefox < 122.
    (CVE-2024-0748)

  - A phishing site could have repurposed an `about:` dialog to show phishing content with an incorrect origin
    in the address bar. This vulnerability affects Firefox < 122 and Thunderbird < 115.7. (CVE-2024-0749)

  - A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user
    into granting permissions. This vulnerability affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird
    < 115.7. (CVE-2024-0750)

  - A malicious devtools extension could have been used to escalate privileges. This vulnerability affects
    Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0751)

  - A use-after-free crash could have occurred on macOS if a Firefox update were being applied on a very busy
    system. This could have resulted in an exploitable crash. This vulnerability affects Firefox < 122.
    (CVE-2024-0752)

  - In specific HSTS configurations an attacker could have bypassed HSTS on a subdomain. This vulnerability
    affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0753)

  - Some WASM source files could have caused a crash when loaded in devtools. This vulnerability affects
    Firefox < 122. (CVE-2024-0754)

  - Memory safety bugs present in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 122, Firefox ESR < 115.7, and
    Thunderbird < 115.7. (CVE-2024-0755)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-26");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=924844");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-115.7.0:esr
        
All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-115.7.0:esr
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-122.0:rapid
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-122.0:rapid");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 115.7.0", "lt 115.0.0"),
    'vulnerable' : make_list("lt 115.7.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("lt 116.0", "ge 122.0"),
    'vulnerable' : make_list("ge 116.0", "lt 122.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 115.7.0", "lt 115.0.0"),
    'vulnerable' : make_list("lt 115.7.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("lt 116.0", "ge 122.0"),
    'vulnerable' : make_list("ge 116.0", "lt 122.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Firefox');
}
