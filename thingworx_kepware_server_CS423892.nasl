#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206276);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2024-6098");
  script_xref(name:"IAVB", value:"2024-B-0120");

  script_name(english:"ThingWorx Kepware Server DoS (CS423892)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"When performing an online tag generation to devices which communicate using the ControlLogix protocol, a
machine-in-the-middle, or a device that is not configured correctly, could deliver a response leading to unrestricted
or unregulated resource allocation. This could cause a denial-of-service condition and crash the Kepware application.
By default, these functions are turned off, yet they remain accessible for users who recognize and require their
advantages.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ptc.com/en/support/article/CS423892");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6098");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ptc:thingworx_kepware_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("thingworx_kepware_server_win_installed.nbin");
  script_require_keys("installed_sw/ThingWorx Kepware Server", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'ThingWorx Kepware Server', win_local:TRUE);

# we can't check if the target software is in a vulnerable state.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'min_version':'6.0', 'max_version' : '6.16', 'fixed_display' : 'Refer to vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
