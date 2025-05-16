##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(233963);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_name(english:"Red Hat Enterprise Linux : Custom Repository Mapping");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using one or more custom repositories to access official Red Hat repositories."
  );
  script_set_attribute(
    attribute:"description",
    value:
"By leveraging the user-generated custom repository mapping file, the scan has identified one or more custom repositories
used to access official Red Hat repositories to install packages. These repositories will be used in conjunction with Red
Hat OS package level assessment security advisories to determine whether or not relevant repositories are installed before
checking package versions for vulnerable ranges."
  );
  # https://www.redhat.com/en/blog/how-accurately-match-oval-security-data-installed-rpms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c79239a");
  # https://community.tenable.com/s/article/How-Red-Hat-Local-Security-Checks-operate
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9221764");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/metrics/repository-to-cpe.json");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/relative-url-list");

  exit(0);
}

include('json2.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var pref = get_kb_item("FLATLINE/repo_map");
if (empty_or_null(pref))
  pref = get_preference('custom_rhel_repo_mapping');
if (!pref) audit(AUDIT_MISSING_PREFERENCES, "Red Hat custom repository mappping file");

# Gather import file and retrieve lists of enabled and validated repo URLs
var relative_urls  = get_kb_item_or_exit('Host/RedHat/relative-url-list');
var import_file    = get_rhel_custom_repo_mapping();
var mapped = [];
var i, key;

# Parse import file and prepare for anaylsis
if(!empty_or_null(import_file) && strlen(import_file) > 0)
{
  dbg::detailed_log(lvl:2, msg:'Mapping file imported successfully.');
  var mapping = json_read(import_file);
}
else
  exit(1, 'Custom mapping option is enabled but failed to import the mapping file successfully.');

if (!empty_or_null(mapping))
{
  mapping = mapping[0]['CustomRepoMapping'];
  dbg::detailed_log(lvl:2, msg:'Mapping file ready: ', msg_details:{'map':{'lvl':2, 'value':mapping}});
}
else
  exit(1, 'Custom mapping file was imported but failed to be parsed successfully.');

var url;
var correlated = 0;
var prepped_urls = deserialize(relative_urls);
dbg::detailed_log(lvl:2, msg:'Relative URLs ready: ', msg_details:{'urls':{'lvl':2, 'value':prepped_urls}});

# Correlate custom repo URLs to their official counterparts
for (key in mapping)
{
  foreach url (prepped_urls)
  {
    dbg::detailed_log(lvl:2, msg:'Evaluating: ' + url + ' and ' + key + '\n');
    if (tolower(url) == tolower(key))
    {
      append_element(value:mapping[key]['official_url'], var:mapped);
      mapping[key]['correlated'] = TRUE;
      dbg::detailed_log(
        lvl:2,
        msg:'Repo match found!',
        msg_details:{
          "Official URL" : {"lvl":2, "value":mapping[key]['official_url']},
          "Internal URL" : {"lvl":2, "value":url}});
      correlated++;
    }
  }
}

# Add validated official repo URLs to Host/RedHat/valid-repo-relative-urls
if (!empty_or_null(mapped))
{
  var serialized_validated = NULL;
  serialized_validated = serialize(mapped);
  dbg::detailed_log(lvl:1, msg:'Generating list of correlated URLs:' + serialized_validated + '\n');
  if (!empty_or_null(serialized_validated))
    replace_kb_item(name:'Host/RedHat/valid-repo-relative-urls', value:serialized_validated);
}
else exit(0, 'No official Red Hat repositories were found to be enabled via custom mirrors.');

# Prepare reporting elements
var stub;
if (!empty_or_null(serialized_validated))
{
  if (correlated == 1)
    stub = 'repository has ';
  else
    stub = 'repositories have ';
}

var successful_repo_correlation = 
  'Using the internal repository mapping file imported into the scan policy, the following\n' +
  'Red Hat ' + stub + 'been determined to be enabled on the host via internal mirrors:\n\n';

var unsuccessful_repo_correlation = 
  'The following custom URLs were imported but were not identified as enabled, therefore\n' +
  'their official Red Hat repository counterpart will not be considered for this host:\n\n';

var report = '';
var mapped_chunk = '';
var unmapped_chunk = '';
var INVALID_MAP = FALSE;

var report_rhel_urls     = '  RHEL Repo Relative URL         : ';
var report_rhel_label    = '  RHEL Repo Label                : ';
var report_custom_url    = '  Internal Repo Relative URL     : ';

foreach (key in keys(mapping))
{
  if (mapping[key]['correlated'] == TRUE)
  {
    mapped_chunk += report_rhel_urls    + mapping[key]['official_url'] + '\n';
    mapped_chunk += report_rhel_label   + mapping[key]['official_label'] + '\n';
    mapped_chunk += report_custom_url   + key + '\n\n';
  }
  else
  {
    unmapped_chunk += report_rhel_urls    + mapping[key]['official_url'] + '\n';
    unmapped_chunk += report_rhel_label   + mapping[key]['official_label'] + '\n';
    unmapped_chunk += report_custom_url   + key + '\n\n';
    INVALID_MAP = TRUE;
  }
}

# Compile final report
if (!empty_or_null(mapped) && max_index(mapped) > 0)
{
  report += successful_repo_correlation + mapped_chunk;
  if (INVALID_MAP)
    report += unsuccessful_repo_correlation  + unmapped_chunk;

# Report
  if (!empty_or_null(report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : report
    );
  }
}
