#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
  script_id(55958);
  script_version("1.40");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_xref(name:"IAVA", value:"0001-A-0575");

  script_name(english:"Oracle Java JRE Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more unsupported versions of the
Oracle Java JRE.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, at least one
installation of Oracle (formerly Sun) Java JRE on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that Oracle does provide support contracts under the 'Oracle
Lifetime Support' program. If the detected JRE is supported under this
program, this may be a false positive. This plugin does not flag JRE 
versions that are still covered under Extended Support.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/java/technologies/java-se-support-roadmap.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle Java JRE that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

#
# Execution begins here
#

var jre_installs = get_kb_list_or_exit("SMB/Java/JRE/*");

var exe_check_list = make_list(jre_installs);

var errors = make_list();

# For display
var latest_versions = '1.17.x / 1.21.x / 1.24.x / 1.25.x 1.26.x';

# Preformatted:
# Oldest supported version is 17.0_00
var oldest_supp_version = '17.0.0';

# Longterm support data
var longterm_support_lists = make_array(
  "^1\.[01]\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', 'No support dates are available.'
      ),
 # https://web.archive.org/web/20031001180548/http://java.sun.com/products/jdk/1.2/
  "^1\.2\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2003-12-02 (end of life)'
      ),
  "^(?:1\.)?3\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2006-12-01 (end of life)' # Reached EOL on 1.6 release date
      ),
  "^(?:1\.)?4\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2008-10-01 (end of regular support) / 2010-02-01 (end of Premier Support) / 2013-02-01 (end of Extended Support)"
      ),
  "^(?:1\.)?5\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2009-10-01 (end of regular support) / 2011-05-01 (end of Premier Support) / 2015-05-01 (end of Extended Support)"
      ),
  "^(?:1\.)?6\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2013-02-01 (end of regular support) / 2015-12-01 (end of Premier Support) / 2018-12-01 (end of life)"
      ),
  "^(?:1\.)?7\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2019-07-01 (end of Premier Support) / 2022-07-01 (end of Extended Support)"
      ),
  "^(?:1\.)?8\.", make_array(
       'support_type' , 'extended_support',
       'support_dates', "2022-03-01 (end of Premier Support) / 2030-12-01 (end of Extended Support)"
     ),
  "^(?:1\.)?9\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2018-04-01 (end of life)"
      ),
  "^(?:1\.)?10\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2018-10-01 (end of life)"
      ),
  "^(?:1\.)?11\.", make_array(
        'support_type' , 'extended_support',
        'support_dates', "2023-9-01 (end of Premier Support) / 2026-09-01 (end of Extended Support)"
      ),
  "^(?:1\.)?12\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2019-10-01 (end of life)"
      ),
  "^(?:1\.)?13\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2020-04-01 (end of life)"
      ),
  "^(?:1\.)?14\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2020-10-01 (end of life)"
      ),
  "^(?:1\.)?15\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2021-03-01 (end of life)"
      ),
  "^(?:1\.)?16\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2021-09-01 (end of life)"
      ),
  "^(?:1\.)?17\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2026-09-01 (end of Premier Support) / 2029-09-01 (end of Extended Support)"
      ),
  "^(?:1\.)?18\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2022-09-01 (end of life)"
      ),
  "^(?:1\.)?19\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2023-03-01 (end of life)"
      ),
  "^(?:1\.)?20\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2023-06-01 (end of life)"
      ),
  "^(?:1\.)?21\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2028-09-01 (end of Premier Support) / 2031-09-01 (end of Extended Support)"
      ),
  "^(?:1\.)?22\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2024-09-01 (end of life)"
      ),
  "^(?:1\.)?23\.", make_array(
        'support_type' , 'out_of_support',
        'support_dates', "2025-03-01 (end of Premier Support)"
      ),
  "^(?:1\.)?24\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2025-09-01 (end of Premier Support)"
      ),
  "^(?:1\.)?25\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2030-09-01 (end of Premier Support) / 2033-09-01 (end of Extended Support)"
      ),
  "^(?:1\.)?26\.", make_array(
        'support_type' , 'premier_support',
        'support_dates', "2026-09-01 (end of Premier Support)"
      )

  ################## 
  # Future Releases 
  ##################

  # 24 GA 2025-03-01 (non-LTS, EOL 2025-09-01)
  # 25 GA 2025-09-01 (LTS)
  # "^(?:1\.)?24\.", make_array(
  #       'support_type' , 'premier_support',
  #       'support_dates', "2025-09-01 (end of Premier Support)"
  #     )
);

var count = 0;
var key, covered_by_premier_or_extended_support, matches, version, raw_version, dirs, dir, pattern, support_dates;
var support_type, unsupported_date_report_string, report ;
# See if any installs are unsupported...
foreach key (list_uniq(keys(jre_installs)))
{  
  covered_by_premier_or_extended_support = FALSE;

  # gather
  matches = pregmatch(string:key, pattern:'/([0-9._]+)$');
  if (!isnull(matches))
    version = matches[1];
  else
    continue;

  # prepare
  raw_version = version;
  version = str_replace(string:version, find:"._", replace:".");
  version = str_replace(string:version, find:"_", replace:".");

  # Get list of dirs for the version
  dirs = make_list(get_kb_list(key));

  foreach dir (dirs)
  {
    # It's possible we have what look like java exes, but are not part of JDK/JRE
    # We should skip these
    # e.g https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0095995
    if ('nrunjava.exe' >< dir)
      continue;

    # Before declaring a version unsupported,
    # check that it's not in Premier Support
    # and not in Extended Support
    foreach pattern (keys(longterm_support_lists))
    {      
      if (version !~ pattern) continue;

      support_type  = longterm_support_lists[pattern]['support_type'];
      support_dates = longterm_support_lists[pattern]['support_dates'];

      if (support_type == "out_of_support")
        unsupported_date_report_string = support_dates;
      else
      {
        set_kb_item(
          name:"Java/JRE/"+support_type+"/"+dir+"/"+raw_version,
          value:support_dates
        );
        covered_by_premier_or_extended_support = TRUE;
      }
      break;
    }

    if (
      !covered_by_premier_or_extended_support &&
      (
        ver_compare(ver:version, fix:oldest_supp_version, strict:FALSE) < 0 ||
        version =~ "^(?:1\.)?9\."  ||
        version =~ "^(?:1\.)?10\." ||
        version =~ "^(?:1\.)?12\." ||
        version =~ "^(?:1\.)?13\." ||
        version =~ "^(?:1\.)?14\." ||
        version =~ "^(?:1\.)?15\." ||
        version =~ "^(?:1\.)?16\." ||
        version =~ "^(?:1\.)?18\." ||
        version =~ "^(?:1\.)?19\." ||
        version =~ "^(?:1\.)?20\." ||
        version =~ "^(?:1\.)?22\."
      )
    )
    {
      count++;

      register_unsupported_product(product_name : 'Oracle Java JRE',
                                   version      : version,
                                   cpe_base     : "oracle:jre");

      report +=
        '\n  Path              : ' + dir +
        '\n  Installed version : ' + raw_version +
        '\n  Latest versions   : ' + latest_versions +
        '\n  Support dates     : ' + unsupported_date_report_string +
        '\n';
    }
  }
}

# ...then report on any that were found
var port;
if (strlen(report))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (count > 1)
    report =
      '\nThe following Java JRE installations are unsupported :\n' + report;
  else
    report =
      '\nThe following Java JRE installation is unsupported :\n' + report;

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}

var errmsg;
if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installations : \n  ' + join(errors, sep:'\n  ');
  exit(1, errmsg);
}

else
{
  if (strlen(report))
    exit(0);
  else
    audit(AUDIT_NOT_INST, "An unsupported version of Oracle Java JRE");
}
