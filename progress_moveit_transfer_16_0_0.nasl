#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
##

include('compat.inc');

if (description)
{
  script_id(198143);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2024-4563");
  script_xref(name:"IAVA", value:"2024-A-0310");

  script_name(english:"Ipswitch MOVEit DMZ < 2024.0.0 (16_0_0) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated because the affected software (MOVEit Automation)
is not currently supported.");
  # https://community.progress.com/s/article/MOVEit-Automation-Vulnerability-CVE-2024-4563-May-22-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de16e968");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4563");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_transfer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:moveit_transfer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Ipswitch MOVEit DMZ");

  exit(0);
}
exit(0, 'This plugin has been deprecated.');
