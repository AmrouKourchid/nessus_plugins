#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72606);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/17");

  script_cve_id("CVE-2014-0498", "CVE-2014-0499", "CVE-2014-0502");
  script_bugtraq_id(65702, 65703, 65704);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/08");

  script_name(english:"Flash Player <= 11.7.700.261 / 12.0.0.44 Multiple Vulnerabilities (APSB14-07)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on the
remote Windows host is equal or prior to 11.7.700.261 / 11.8.x / 11.9.x
/ 12.0.0.70.  It is, therefore, potentially affected multiple
vulnerabilities :

  - A stack overflow vulnerability exists that could result
    in arbitrary code execution. (CVE-2014-0498)

  - A memory leak vulnerability exists that could be used
    to aid in buffer overflow attacks by bypassing address
    space layout randomization (ASLR). (CVE-2014-0499)

  - A double free vulnerability exists that could result in
    arbitrary code execution. (CVE-2014-0502)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-040/");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.269 / 12.0.0.70 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0502");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";

# we're checking for versions less than *or equal to* the cutoff!
foreach variant (make_list("Plugin", "ActiveX", "Chrome", "Chrome_Pepper"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if (!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      ver = vers[key];

      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (
          (
            # Chrome Flash <= 12.0.0.44
            variant == "Chrome_Pepper" &&
            (iver[0] == 12 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 44)
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # < 11
             iver[0] < 11 ||
             # 11.x <= 11.7.700.261
             (
               iver[0] == 11 &&
               (
                 iver[1] < 7 ||
                 (
                   iver[1] == 7 &&
                   (
                     iver[2] < 700 ||
                     (iver[2] == 700 && iver[3] <= 261)
                   )
                 )
               )
             ) ||
             # 11.8.x
             (iver[0] == 11 && iver[1] == 8) ||
             # 11.9.x
             (iver[0] == 11 && iver[1] == 9) ||

             # 12.0.0.x <= 12.0.0.44
             (
               iver[0] == 12 &&
               (
                 iver[1] == 0 &&
                 (
                   iver[2] == 0 &&
                   (
                     iver[3] <= 44
                   )
                 )
               )
             )
           )
         )
        )
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          if (variant == "Plugin")
          {
            info += '\n  Product: Browser Plugin (for Firefox / Netscape / Opera)';
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 12.0.0.70 (Chrome PepperFlash)';
          else
          {
            if (ver =~ "^11\.7")
              fix = "11.7.700.269";
            else
              fix = "12.0.0.70";
            info += '\n  Fixed version     : '+fix;
          }
          info += '\n';
        }
      }
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
