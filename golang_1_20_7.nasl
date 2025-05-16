#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180412);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/15");

  script_cve_id("CVE-2023-29409");
  script_xref(name:"IAVB", value:"2023-B-0064-S");

  script_name(english:"Golang < 1.19.12 / 1.20.x < 1.20.7 DoS");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Golang Go installed on the remote host is affected by denial of service vulnerability. Extremely large
RSA keys in certificate chains can cause a client/server to expend significant CPU time verifying signatures. With fix,
the size of RSA keys transmitted during handshakes is restricted to <= 8192 bits. Based on a survey of publicly trusted
RSA keys, there are currently only three certificates in circulation with keys larger than this, and all three appear to
be test certificates that are not actively deployed. It is possible there are larger keys in use in private PKIs, but we
target the web PKI, so causing breakage here in the interests of increasing the default safety of users of crypto/tls
seems reasonable.


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/61460");
  # https://groups.google.com/g/golang-announce/c/X0b6CsSAaYI/m/Efv5DbZ9AwAJ?pli=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dbe0884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.19.12, 1.20.7, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/31");

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
  { 'fixed_version' : '1.19.12' },
  { 'min_version' : '1.20', 'fixed_version' : '1.20.7' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
