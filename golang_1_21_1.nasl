#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181472);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id(
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39321",
    "CVE-2023-39322"
  );
  script_xref(name:"IAVB", value:"2023-B-0068-S");
  script_xref(name:"IAVB", value:"2023-B-0080-S");

  script_name(english:"Golang < 1.20.8 / 1.21.x < 1.21.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Golang Go installed on the remote host is affected by multiple vulnerabilities, including the following:

  - QUIC connections do not set an upper bound on the amount of data buffered when reading post-handshake messages,
    allowing a malicious QUIC connection to cause unbounded memory growth. With fix, connections now consistently reject
    messages larger than 65KiB in size. (CVE-2023-39322)

  - Processing an incomplete post-handshake message for a QUIC connection can cause a panic. (CVE-2023-39321)

  - The html/template package does not properly handle HTML-like double quote comment tokens, nor hashbang #! comment
    tokens, in <script> contexts. This may cause the template parser to improperly interpret the contents of <script>
    contexts, causing actions to be improperly escaped. This may be leveraged to perform an XSS attack. (CVE-2023-39318)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://groups.google.com/g/golang-dev/c/2C5vbR-UNkI/m/L1hdrPhfBAAJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f755735e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.20.8, 1.21.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '1.20.8' },
  { 'min_version' : '1.21', 'fixed_version' : '1.21.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{ 'xss':TRUE });
