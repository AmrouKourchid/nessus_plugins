#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81002);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/19");

  script_cve_id(
    "CVE-2003-1418",
    "CVE-2011-1944",
    "CVE-2011-3607",
    "CVE-2013-0338",
    "CVE-2013-2877",
    "CVE-2013-5704",
    "CVE-2013-6438",
    "CVE-2014-0098",
    "CVE-2014-0191",
    "CVE-2014-0226",
    "CVE-2014-6571",
    "CVE-2015-0372",
    "CVE-2015-0386",
    "CVE-2015-2808",
    "CVE-2016-2183"
  );
  script_bugtraq_id(
    48056,
    50494,
    58180,
    61050,
    66303,
    66550,
    67233,
    68678,
    72143,
    72183,
    72193,
    73684,
    92630
  );
  script_xref(name:"EDB-ID", value:"34133");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (January 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by multiple vulnerabilities in the Web Listener
subcomponent :

  - An integer overflow condition exists in libxml2 within
    file xpath.c, related to XPath expressions when adding a
    new namespace note. An unauthenticated, remote attacker
    can exploit this, via a crafted XML file, to cause a
    denial of service condition or the execution of arbitary
    code. (CVE-2011-1944)

  - An integer overflow condition exists in the HTTP server,
    specifically in the ap_pregsub() function within file
    server/util.c, when the mod_setenvif module is enabled.
    A local attacker can exploit this to gain elevated
    privileges by using an .htaccess file with a crafted
    combination of SetEnvIf directives and HTTP request
    headers. (CVE-2011-3607)

  - A flaw exists in libxml2, known as the 'internal entity
    expansion' with linear complexity issue, that allows
    specially crafted XML files to consume excessive CPU and
    memory resources. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    by using a specially crafted XML file containing an
    entity declaration with long replacement text and many
    references to this entity. (CVE-2013-0338)

  - An out-of-bounds read error exists in libxml2 within
    file parser.c due to a failure to check for the
    XML_PARSER_EOF state. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    document that ends abruptly, to cause a denial of
    service condition. (CVE-2013-2877)

  - A flaw exists within the mod_headers module in the
    HTTP server which allows bypassing the 'RequestHeader
    unset' directives. An unauthenticated, remote attacker
    can exploit this to inject arbitrary headers. This is
    done by placing a header in the trailer portion of data
    being sent using chunked transfer encoding.
    (CVE-2013-5704)

  - A flaw exists in the dav_xml_get_cdata() function in
    file main/util.c within the HTTP server mod_dav module
    due to incorrect stripping of whitespace characters from
    the CDATA sections. An unauthenticated, remote attacker
    via a specially crafted DAV WRITE request, can exploit
    this to cause a denial of service condition.
    (CVE-2013-6438)

  - A flaw exists in the log_cookie() function in file
    mod_log_config.c within the HTTP server mod_log_config
    module due to improper handling of specially crafted
    cookies during truncation. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition via a segmentation fault. (CVE-2014-0098)

  - A flaw exists in libxml2, specifically in the
    xmlParserHandlePEReference() function in file parser.c,
    due to loading external parameter entities even when
    entity substitution is disabled. An unauthenticated,
    remote attacker can exploit this issue, via a specially
    crafted XML file, to conduct XML External Entity (XXE)
    attacks that exhaust CPU and memory resources, resulting
    in a denial of service condition. (CVE-2014-0191)

  - A race condition exists in the HTTP server within the
    mod_status module when using a threaded Multi-Processing
    Module (MPM). If an unauthenticated, remote attacker is
    able to access status pages served by mod_status, the
    attacker can exploit this issue, by sending specially
    crafted requests, to cause the httpd child process to
    crash or possibly execute arbitrary code with the
    privileges of the user running the web server.
    (CVE-2014-0226)

  - An unspecified flaw exists in the Web Listener
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality, integrity, and
    availability. (CVE-2014-6571)

  - An unspecified flaw exists in the J2EE subcomponent that
    allows an unauthenticated, remote attacker to disclose
    potentially sensitive information. (CVE-2015-0372)

  - An unspecified flaw exists in the Web Listener
    subcomponent that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2015-0386)");
  # https://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75c6cafb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5704");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
patches['10.1.3.5'] = make_array('fix_ver', '10.1.3.5.150120', 'patch', '19952538');
patches['11.1.1.7'] = make_array('fix_ver', '11.1.1.7.150120', 'patch', '19948000');
patches['12.1.2.0'] = make_array('fix_ver', '12.1.2.0.150120', 'patch', '19948089');
patches['12.1.3.0'] = make_array('fix_ver', '12.1.3.0.141218', 'patch', '19948154');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
