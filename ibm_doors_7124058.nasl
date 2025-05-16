#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191754);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id(
    "CVE-2018-17960",
    "CVE-2019-10072",
    "CVE-2020-1935",
    "CVE-2020-1938",
    "CVE-2020-9281",
    "CVE-2020-11996",
    "CVE-2020-13934",
    "CVE-2020-13943",
    "CVE-2020-14338",
    "CVE-2020-17527",
    "CVE-2020-27193",
    "CVE-2020-36518",
    "CVE-2021-23926",
    "CVE-2021-25122",
    "CVE-2021-26271",
    "CVE-2021-27568",
    "CVE-2021-29425",
    "CVE-2021-33037",
    "CVE-2021-33829",
    "CVE-2021-37533",
    "CVE-2021-37695",
    "CVE-2021-41079",
    "CVE-2021-41164",
    "CVE-2021-41165",
    "CVE-2021-43980",
    "CVE-2021-46877",
    "CVE-2022-24728",
    "CVE-2022-24729",
    "CVE-2022-25762",
    "CVE-2022-29885",
    "CVE-2022-32532",
    "CVE-2022-36944",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-42252",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2023-1370",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916",
    "CVE-2023-24998",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538",
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-28525",
    "CVE-2023-28949",
    "CVE-2023-32001",
    "CVE-2023-34453",
    "CVE-2023-34454",
    "CVE-2023-34455",
    "CVE-2023-35116",
    "CVE-2023-38039",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-41080",
    "CVE-2023-42795",
    "CVE-2023-43642",
    "CVE-2023-44487",
    "CVE-2023-45648",
    "CVE-2023-46604",
    "CVE-2023-50305",
    "CVE-2023-50306",
    "CVE-2024-21733"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/11/23");
  script_xref(name:"IAVA", value:"2024-A-0124");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"IBM Engineering Requirements Management DOORS 9.7.2.x < 9.7.2.8 Multiple Vulnerabilities (7124058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Engineering Requirements Management DOORS (formerly IBM Rational DOORS) installed on the remote
host is 9.7.2.x prior to 9.7.2.8. It is, therefore, affected by multiple vulnerabilities as referenced in the 7124058
advisory.

  - Apache Shiro before 1.9.1, A RegexRequestMatcher can be misconfigured to be bypassed on some servlet
    containers. Applications using RegExPatternMatcher with `.` in the regular expression are possibly
    vulnerable to an authorization bypass. (CVE-2022-32532)

  - The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow
    a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary
    shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client
    or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade
    both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.
    (CVE-2023-46604)

  - Scala 2.13.x before 2.13.9 has a Java deserialization chain in its JAR file. On its own, it cannot be
    exploited. There is only a risk in conjunction with Java object deserialization within an application. In
    such situations, it allows attackers to erase contents of arbitrary files, make network connections, or
    possibly run arbitrary code (specifically, Function0 functions) via a gadget chain. (CVE-2022-36944)

  - IBM Engineering Requirements Management DOORS 9.7.2.7 is vulnerable to cross-site request forgery which
    could allow an attacker to execute malicious and unauthorized actions transmitted from a user that the
    website trusts. IBM X-Force ID: 251216. (CVE-2023-28949)

  - A cross-site scripting (XSS) vulnerability in the HTML Data Processor for CKEditor 4.0 before 4.14 allows
    remote attackers to inject arbitrary web script through a crafted protected comment (with the
    cke_protected syntax). (CVE-2020-9281)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7124058");
  script_set_attribute(attribute:"solution", value:
"Upgrade IBM DOORS based upon the guidance specified in 7124058.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32532");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-46604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache ActiveMQ Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_doors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_doors_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/IBM DOORS");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'IBM DOORS', win_local:TRUE);

var constraints = [
  { 'min_version' : '9.7.2', 'fixed_version' : '9.7.2.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
