#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234627);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2025-32433");
  script_xref(name:"IAVA", value:"2025-A-0286");

  script_name(english:"Erlang/OTP SSH RCE (OTP-19595)");

  script_set_attribute(attribute:"synopsis", value:
"The Erlang/OTP SSH applicaiton installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Erlang/OTP SSH applicaiton installed on the remote host is 4.15.x < 4.15.3.12, 5.1.x < 5.1.4.8, 5.2.x < 5.2.10.
Therefore, it is affected by a remote code execution vulnerability due to a flaw in the SSH protocol message handling.
An unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2");
  script_set_attribute(attribute:"see_also", value:"https://erlang.org/download/OTP-25.3.2.20.README");
  script_set_attribute(attribute:"see_also", value:"https://erlang.org/download/OTP-26.2.5.11.README");
  script_set_attribute(attribute:"see_also", value:"https://erlang.org/download/OTP-27.3.3.README.md");
  script_set_attribute(attribute:"see_also", value:"https://www.erlang.org/doc/apps/ssh/notes.html#ssh-5-2-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.15.3.12, 5.1.4.8, 5.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32433");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:erlang:erlang%2fotp_ssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:erlang:erlang%2fotp");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("erlang_otp_ssh_detect.nbin");
  script_require_keys("installed_sw/Erlang-OTP SSH Application");

  exit(0);
}

include('vcf.inc');

var app = 'Erlang-OTP SSH Application';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
    { 'min_version' : '4.15', 'fixed_version' : '4.15.3.12'},
    { 'min_version' : '5.1', 'fixed_version' : '5.1.4.8'},
    { 'min_version' : '5.2', 'fixed_version' : '5.2.10'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
