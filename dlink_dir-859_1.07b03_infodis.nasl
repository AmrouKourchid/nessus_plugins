#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187211);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2019-20213");

  script_name(english:"DLink DIR-859 < 1.07B03 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DLink installed on the remote host is prior to 1.07b03. It is, therefore, affected by an 
information disclosure vulnerability as referenced in the vendor advisory.  A remote, unauthenticated 
attacker can explioit this exposure by sending a carefully crafted paypload with a AUTHORIZED_GROUP=1%0a
value as demonstrated by vpnconfig.php to the remote server. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10146
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0583e6e");
  # https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10147
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec7efd10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.07b03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dlink:dir");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'DLink DIR'); 

var constraints = [
  { 'DIR-859': 
    {'constraints': [
        {'fixed_version' : '1.07B03' }
      ]
    }
  }
];

var tmp = NULL;
if(!empty_or_null(app_info.model))
{
  for (var i=0; i<max_index(constraints); i++)
  {
    tmp = constraints[i][app_info.model]['constraints'];

    if (!empty_or_null(tmp))
      vcf::check_version_and_report(app_info:app_info, constraints:tmp, severity:SECURITY_WARNING);
    else vcf::audit();
  }
}
else exit(0, 'DLink DIR device model not detected');