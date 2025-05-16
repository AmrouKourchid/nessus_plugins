#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190126);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id(
    "CVE-2023-37527",
    "CVE-2023-37528",
    "CVE-2023-37529",
    "CVE-2023-37530",
    "CVE-2023-37531",
    "CVE-2023-38545",
    "CVE-2024-23552",
    "CVE-2024-23553"
  );
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"HCL BigFix Server 9.5.x < 9.5.24 / 10.0.x < 10.0.10 / 11.0.x < 11.0.1  Multiple Vulnerabilities (KB0110209)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of HCL BigFix Server installed on the remote host is 9.5.x prior to 9.5.24, 10.0.x prior to 10.0.10 or
11.x prior to 11.0.1. It is, therefore, affected by multiple vulnerabilities as referenced in the KB0110209 advisory.

  - Heap-based buffer overflow vulnerability in the SOCKS5 proxy handshake in libcurl and curl.  When curl
    is given a hostname to pass along to a SOCKS5 proxy that is greater than 255 bytes in length, it will
    switch to local name resolution in order to resolve the address before passing it on to the SOCKS5
    proxy. However, due to a bug introduced in 2020, this local name resolution could fail due to a
    slow SOCKS5 handshake, causing curl to pass on the hostname greater than 255 bytes in length into the
    target buffer, leading to a heap overflow.  The advisory for CVE-2023-38545 gives an example exploitation
    scenario of a malicious HTTPS server redirecting to a specially crafted URL. While it might seem that an
    attacker would need to influence the slowness of the SOCKS5 handshake, the advisory states that server
    latency is likely slow enough to trigger this bug. (CVE-2023-38545)

  - A cross-site scripting (XSS) vulnerability in the Web Reports component of HCL BigFix Platform can
    possibly allow an attack to exploit an application parameter during execution of the Save Report.
    (CVE-2023-37528)

  - A reflected cross-site scripting (XSS) vulnerability in the Web Reports component of HCL BigFix Platform
    can possibly allow an attacker to execute malicious javascript code in the application session or in
    database, via remote injection, while rendering content in a web page. (CVE-2023-37527)

  - A cross-site scripting (XSS) vulnerability in the Web Reports component of HCL BigFix Platform exists due
    to missing a specific http header attribute. (CVE-2024-23553)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0110209
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9950c295");
  script_set_attribute(attribute:"solution", value:
"Upgrade HCL BigFix Server based upon the guidance specified in KB0110209.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hcltech:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hcl_bigfix_server_win_installed.nbin");
  script_require_keys("installed_sw/HCL BigFix Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'HCL BigFix Server', win_local:TRUE);

var constraints = [
  { 'min_version' : '9.5', 'fixed_version' : '9.5.24' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.10' },
  { 'min_version' : '11.0', 'fixed_version' : '11.0.1' }
];

var flags  = NULL;
if (!empty_or_null(app_info.BESWebReportsServer))
  flags = {'xss':TRUE};

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:flags
);
