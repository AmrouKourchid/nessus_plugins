#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192237);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/20");

  script_cve_id("CVE-2023-38545", "CVE-2023-38546");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Fortinet FortiProxy curl and libcurl Multiple Vulnerabilities (FG-IR-23-385)");

  script_set_attribute(attribute:"synopsis", value:
"The version of FortiProxy installed on the remote host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiProxy installed on the remote host is 7.0.x, 7.2.x prior to 7.2.8, or 7.4.x prior to
7.4.2. It is, therefore, affected by multiple vulnerabilities as referenced in the FG-IR-23-385 advisory.

  - This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to
    pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting
    done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected
    to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due
    to this bug, the local variable that means 'let the host resolve the name' could get the wrong value
    during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target
    buffer instead of copying just the resolved address there. The target buffer being a heap based buffer,
    and the host name coming from the URL that curl has been told to operate with. (CVE-2023-38545)

  - This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the
    specific series of conditions are met. libcurl performs transfers. In its API, an application creates
    'easy handles' that are the individual handles for single transfers. libcurl provides a function call that
    duplicates en easy handle called 'curl_easy_duphandle'. If a transfer has cookies enabled when the handle
    is duplicated, the cookie-enable state is also cloned - but without cloning the actual cookies. If the
    source handle did not read any cookies from a specific file on disk, the cloned version of the handle
    would instead store the file name as `none` (using the four ASCII letters, no quotes). Subsequent use of
    the cloned handle that does not explicitly set a source to load cookies from would then inadvertently load
    cookies from a file named `none` - if such a file exists and is readable in the current directory of the
    program using libcurl. And if using the correct file format of course. (CVE-2023-38546)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-015");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiProxy version 7.2.8, 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/FortiProxy/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'FortiProxy';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/FortiProxy/version');
vcf::fortios::verify_product_and_model(product_name:app_name, model_check:"FortiProxy-VM64");

var constraints = [
  { 'min_version' : '7.0', 'max_version' : '7.0.99', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.2', 'max_version' : '7.2.7',  'fixed_display' : '7.2.8' },
  { 'min_version' : '7.4', 'max_version' : '7.4.1',  'fixed_display' : '7.4.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
