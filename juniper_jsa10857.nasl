#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(111204);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/03");

  script_cve_id("CVE-2018-0024");
  script_bugtraq_id(104718);
  script_xref(name:"JSA", value:"JSA10857");

  script_name(english:"Juniper Junos Privilege Escalation (JSA10857)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a privilege escalation vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10857
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?075586cf");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10857.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0024");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# 12.1X46 versions prior to 12.1X46-D45 on SRX Series;
# 12.3X48 versions prior to 12.3X48-D20 on SRX Series;
# 12.3 versions prior to 12.3R11 on EX Series;
# 14.1X53 versions prior to 14.1X53-D30 on EX2200/VC, EX3200, EX3300/VC, EX4200, EX4300, EX4550/VC, EX4600, EX6200, EX8200/VC (XRE), QFX3500, QFX3600, QFX5100;
# 15.1X49 versions prior to 15.1X49-D20 on SRX Series. 

fixes = make_array();
if (model =~ '^SRX')
{
  fixes['12.1X46'] = '12.1X46-D45';
  fixes['12.3X48'] = '12.3X48-D20';
  fixes['15.1X49'] = '15.1X49-D20';
}
else if (model =~ '^EX')
{
  fixes['12.3'] = '12.3R11';
  if (model =~ '^EX(32|42|43|46|62)00' || model =~ '^EX(220|330|455|820)0\\.VC')
    fixes['14.1X53'] = '14.1X53-D30';
}
else if (model =~ '^QFX(35|36|51)00')
  fixes['14.1X53'] = '14.1X53-D30';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
