#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185933);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/21");

  script_cve_id("CVE-2023-36043");
  script_xref(name:"IAVA", value:"2023-A-0637");

  script_name(english:"Security Updates for Microsoft Open Management Infrastructure (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Open Management Infrastructure server affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Open Management Infrastructure on the remote host is missing a security update. It is,
therefore, affected by the following vulnerability:

  - An unauthenticated, remote attacker can exploit this to disclose
    potentially sensitive information. (CVE-2023-36043)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-36043
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c201c0e9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for System Center Operations Manager 2016, 2019, and 2022.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36043");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:open_management_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_omi_nix_installed.nbin");
  script_require_keys("installed_sw/omi");

  exit(0);
}

include('vcf.inc');

vcf::add_separator('-'); # used in parsing version for vcf
var app_info = vcf::combined_get_app_info(app:'omi');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '1.7.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
