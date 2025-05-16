#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186691);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2023-45287");
  script_xref(name:"IAVB", value:"2023-B-0096-S");

  script_name(english:"Golang < 1.20 Observable Discrepancy");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an Observable Discrepancy vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Before Go 1.20, the RSA based TLS key exchanges used the math/big library, which is not constant time. RSA blinding
was applied to prevent timing attacks, but analysis shows this may not have been fully effective. In particular it
appears as if the removal of PKCS#1 padding may leak timing information, which in turn could be used to recover
session key bits. In Go 1.20, the crypto/tls library switched to a fully constant time RSA implementation, which we
do not believe exhibits any timing side channels.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://pkg.go.dev/vuln/GO-2023-2375");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-announce/c/QMK8IQALDvA");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.20, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '1.20' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);