#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186904);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id("CVE-2023-46751");
  script_xref(name:"IAVB", value:"2023-B-0097-S");

  script_name(english:"Artifex Ghostscript < 10.2.1 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"An issue was discovered in the function gdev_prn_open_printer_seekable() in Artifex Ghostscript through 10.02.0 
that allows remote attackers to crash the application via a dangling pointer.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://ghostscript.readthedocs.io/en/gs10.02.1/News.html?utm_source=ghostscript&utm_medium=website&utm_content=inline-link
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72b795d4");
  # https://git.ghostscript.com/?p=ghostpdl.git;a=commit;h=dcdbc595c13c9d11d235702dff46bb74c80f7698
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d34cb60d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Artifex Ghostscript 10.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46751");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include('vcf.inc');

var app = 'Ghostscript';

var constraints = [{'fixed_version' : '10.2.1'}];

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);