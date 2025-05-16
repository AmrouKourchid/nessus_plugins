#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(40362);
  script_version("1.105");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/30");

  script_xref(name:"IAVA", value:"0001-A-0565");

  script_name(english:"Mozilla Foundation Unsupported Application Detection");
  script_summary(english:"Checks if any Mozilla application versions are unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more unsupported applications from the
Mozilla Foundation.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one unsupported Mozilla
application (Firefox, Thunderbird, and/or SeaMonkey) installed on the
remote host. This version of the software is no longer actively
maintained.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/organizations/faq/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/thunderbird/");
  script_set_attribute(attribute:"see_also", value:"https://www.seamonkey-project.org/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_ports("installed_sw/Mozilla Firefox", "installed_sw/Mozilla Firefox ESR", "installed_sw/Mozilla Thunderbird", "installed_sw/Mozilla Thunderbird ESR", "installed_sw/SeaMonkey");

  exit(0);
}

include('install_func.inc');
include('debug.inc');

var now = get_kb_item("/tmp/start_time");
if (empty_or_null(now))
  now = int(gettimeofday());

# Latest version data as of 29/11/2024 
var all_latest_version_data = make_array( 
  'Mozilla Firefox'        , "133.0.0",
  'Mozilla Firefox ESR'    , "128.5.0",
  'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
  'Mozilla Thunderbird ESR', "128.5.0",
  'SeaMonkey'              , "2.53.19"
);


if (now > 1736208000)# 7th January 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "134.0.0",
    'Mozilla Firefox ESR'    , "128.6.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.6.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1738627200)# 4th February 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "135.0.0",
    'Mozilla Firefox ESR'    , "128.7.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.7.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1741046400)# 4th March 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "136.0.0",
    'Mozilla Firefox ESR'    , "128.8.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.8.0",
    'SeaMonkey'              , "2.53.19"
  );
}

var thunderbird_firefox_supported_esr_version = make_list('115', '128');
# Define supported ESR branches for Thunderbird


if (now > 1743465600) # 1st April 2025, 12:00:00 AM GMT version 115 is EOL
{
  thunderbird_firefox_supported_esr_version = make_list("128");

  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "137.0.0",
    'Mozilla Firefox ESR'    , "128.9.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.9.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1745884800)# 29th April 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "138.0.0",
    'Mozilla Firefox ESR'    , "128.10.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.10.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1748304000)# 27th May 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "139.0.0",
    'Mozilla Firefox ESR'    , "128.11.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.11.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1750723200) # 24th June 2025, 12:00:00 AM GMT latest versions are 
{
  thunderbird_firefox_supported_esr_version = make_list("128", "140");

  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "140.0.0",
    'Mozilla Firefox ESR'    , "128.12.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.12.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1753142400) # 22nd July 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "141.0.0",
    'Mozilla Firefox ESR'    , "128.13.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.13.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1755561600) # 19th August 2025, 12:00:00 AM GMT version latest versions are 
{
  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "142.0.0",
    'Mozilla Firefox ESR'    , "128.14.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "128.13.0",
    'SeaMonkey'              , "2.53.19"
  );
}

if (now > 1757980800) # 16th September 2025, 12:00:00 AM GMT version 128 is EOL
{
  thunderbird_firefox_supported_esr_version = make_list("140");

  all_latest_version_data = make_array(
    'Mozilla Firefox'        , "143.0.0",
    'Mozilla Firefox ESR'    , "143.3.0",
    'Mozilla Thunderbird'    , "115.10.1", # version 131.0 is for testing purposes only for now
    'Mozilla Thunderbird ESR', "143.3.0",
    'SeaMonkey'              , "2.53.19"
  );
}

var products = make_list(
  "Mozilla Firefox",
  "Mozilla Firefox ESR",
  "Mozilla Thunderbird",
  "Mozilla Thunderbird ESR",
  "SeaMonkey"
);

# Branch on product
var product = branch(products);

# Branch on install
var install = get_single_install(app_name:product);

if (isnull(install)) exit(0, "No Installation of " + product + " found.");

var version = install['version'];
var path    = install['path'];
var eol_url, cpe_base , port, report;


var latest_version = all_latest_version_data[product];

# Determind EOL status
if (product == "Mozilla Thunderbird ESR" || product == "Mozilla Firefox ESR")
{
  # Special case for Thunderbird ESR: check if version matches supported ESR branchs
  if (thunderbird_firefox_supported_esr_version[0] != ereg_replace(pattern: "^(\d+).*", replace:'\\1' , string:version) &&
  thunderbird_firefox_supported_esr_version[1] != ereg_replace(pattern: "^(\d+).*", replace:'\\1' , string:version))
  {
    if (ver_compare(ver:version, fix:latest_version, strict:TRUE ) < 0)
    {
      if (product == "Mozilla Firefox ESR") eol_url = "https://www.mozilla.org/en-US/firefox/releases/";
      else
        eol_url = "https://www.thunderbird.net/en-US/thunderbird/releases/";
      if (report_verbosity > 0)
      {
        port = get_kb_item('SMB/transport');
        if (!port) port = 445;
        
        report =
          '\n  Product           : ' + product +
          '\n  Path              : ' + path    +
          '\n  Installed version : ' + version +
          '\n  Latest version    : ' + latest_version +
          '\n  EOL URL           : ' + eol_url +
          '\n';

        cpe_base = tolower(str_replace(string:product, find:"Mozilla ", replace:""));
        cpe_base = str_replace(string:cpe_base, find:" ", replace:"_");
  
        register_unsupported_product(
          product_name : product,
          cpe_base     : "mozilla:" + cpe_base,
          version      : version
        );

        security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
      }
    }
    else
    {
      audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
    }
  }
  else
  {
    audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
  }
}
else
{
  # Standard logic for the rest 
  if (ver_compare(ver:version, fix:latest_version, strict:TRUE ) < 0)
  {
    if (product == "Mozilla Firefox")
    {
      eol_url = "https://www.mozilla.org/en-US/firefox/releases/";
    }
    else if (product == "Mozilla Thunderbird")
    {
      eol_url = "https://www.thunderbird.net/en-US/thunderbird/releases/";
    }
    else if (product == "SeaMonkey")
    {
      eol_url = "https://www.seamonkey-project.org/releases/";
    }

    if (report_verbosity > 0)
    {
      port = get_kb_item('SMB/transport');
      if (!port) port = 445;

      report =
        '\n  Product           : ' + product +
        '\n  Path              : ' + path    +
        '\n  Installed version : ' + version +
        '\n  Latest version    : ' + latest_version +
        '\n  EOL URL           : ' + eol_url +
        '\n';

      cpe_base = tolower(str_replace(string:product, find:"Mozilla ", replace:""));
      cpe_base = str_replace(string:cpe_base, find:" ", replace:"_");

      register_unsupported_product(
        product_name : product,
        cpe_base     : "mozilla:" + cpe_base,
        version      : version
      );

      security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    }
  }
  else
  {
    audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
  }

}