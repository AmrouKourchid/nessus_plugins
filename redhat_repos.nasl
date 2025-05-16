#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149983);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_name(english:"Red Hat Enterprise Linux : Enabled Official Repositories");
  script_summary(english:"Checks .repo file output repos against a list of official RHEL repos");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using one or more official Red Hat repositories to install packages."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is using one or more official Red Hat repositories to install packages.
These repositories will be used in conjunction with Red Hat OS package level assessment security advisories to determine
whether or not relevant repositories are installed before checking package versions for vulnerable ranges."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/metrics/repository-to-cpe.json");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "redhat_custom_repos.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('lists.inc');
include('rhel.inc');
include('rhel_repos.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Check for repo list data
var host_repo_details  = get_kb_list('Host/RedHat/repo-list/*');
if (empty_or_null(host_repo_details))
{
  audit(AUDIT_NOT_INST, 'a RHEL repository or repository relative URL');
}

##
# This plugin only runs against KB items, so no point adding another debug log!
# Change to TRUE for CLI scan debugging
##
var CLI_DEBUG = FALSE;

# Adding this for flatline as a warning not to commit changes where CLI debugging is enabled
if (CLI_DEBUG)
{
  replace_kb_item(name:'FLATLINE/redhat_repos_nasl_cli_debug', value:TRUE);
}

# Initiate lists, arrays
var host_label_url_map        = [];
var host_labels_no_urls       = [];
var comp_host_labels_no_urls  = [];
var label_needs_url           = [];
var invalid_label_no_url      = [];
var validated_labels          = {};
var invalid_labels            = {};
var final_validated           = {};

var repo_detail, split_repo_detail, segment, host_label, host_url_index;
for (repo_detail in host_repo_details)
{
  split_repo_detail  = split(keep:FALSE, sep:'/' ,repo_detail);
  host_label  = split_repo_detail[3];

  # Come back to this - some labels have had their URLs computed in
  # found_rhel_os() so there maybe be multiple KBs for the same label
  host_url_index = split_repo_detail[4];

  if (preg(pattern:"\/relative-url$", string:repo_detail))
  {
    append_element(value:[host_label, host_repo_details[repo_detail], host_url_index], var:host_label_url_map);
  }
  else
  {
    # Create a separate list of labels only. There may be an entry for this label
    # in host_label_url_map that has no URL, which we will deal with later on.
    append_element(value:host_label, var:host_labels_no_urls);
  }
}

##
# Compare labels in host_labels_no_urls with labels in host_label_url_map
# and create a new list for anything we have not already mapped to a URL
##
var host_item, host_label_no_url, host_item_label;
foreach host_label_no_url (host_labels_no_urls)
{
  foreach host_item (host_label_url_map)
  {
    if (host_item[0] == host_label_no_url)
    {
      append_element(value:host_label_no_url, var:comp_host_labels_no_urls);
      break;
    }
  }
}

# No repository labels or relative URLs were found during the scan.
if (empty_or_null(host_label_url_map) && empty_or_null(host_labels_no_urls))
{
  audit(AUDIT_NOT_INST, "a RHEL repository or repository relative URL");
}

# Create a list of labels from the host KB that we did not record a URL for
label_needs_url = collib::subtract(host_labels_no_urls, comp_host_labels_no_urls);

# LABELS: figure out which labels are valid from what we found on the host
var host_map, host_map_label, host_map_url, valid_repo_details;
foreach host_map (host_label_url_map)
{
  host_map_label     = host_map[0];
  host_map_url       = host_map[1];
  valid_repo_details = RHEL_REPO_MAP[host_map_label];

  if (valid_repo_details) # label is valid
  {
    if (host_map_label)
    {
      validated_labels[host_map_label] = host_map_url;
    }
  }
  else
  {
    if (host_map_label)
    {
      invalid_labels[host_map_label]['host_url']      = host_map_url;
      invalid_labels[host_map_label]['no_valid_info'] = TRUE;
    }
  }
}

##
# URLs: Check validity of the URLs in validated_labels
# and start building the final_validated array.
##
var label_key, url_to_check, repo_map_to_check, rhel_url;
for (label_key in validated_labels)
{
  url_to_check      = validated_labels[label_key];
  repo_map_to_check = RHEL_REPO_MAP[label_key];

  foreach rhel_url (repo_map_to_check)
  {
    if (url_to_check == rhel_url)
    {
      final_validated[label_key]['rhel_valid_urls'] = url_to_check;
      final_validated[label_key]['host_valid_label']  = TRUE;
      final_validated[label_key]['host_valid_url']    = TRUE;
      break;
    }
    else
    {
      final_validated[label_key]['rhel_valid_urls'] = url_to_check;
      final_validated[label_key]['host_valid_label']  = TRUE;
      final_validated[label_key]['host_valid_url']    = FALSE;
    }
  }
  if (final_validated[label_key]['host_valid_url'] == FALSE)
  {
    final_validated[label_key]['rhel_valid_urls'] = RHEL_REPO_MAP[label_key];
    final_validated[label_key]['host_invalid_url'] = url_to_check;
  }
}

##
# LABELS: Check invalid labels that have a URL.
# Try to validate the URL via RHEL_REPO_MAP
##
var invalid_label, repo_map_key, rhel_label, rhel_url_list;
for (invalid_label in invalid_labels)
{
  url_to_check = invalid_labels[invalid_label]['host_url'];
  for (repo_map_key in RHEL_REPO_MAP)
  {
    rhel_label    = repo_map_key;
    rhel_url_list = RHEL_REPO_MAP[repo_map_key];

    foreach rhel_url (rhel_url_list)
    {
      if (url_to_check == rhel_url)
      {
        final_validated[rhel_label]['invalid_host_label'] = invalid_label;
        final_validated[rhel_label]['host_valid_label']   = FALSE;
        final_validated[rhel_label]['host_valid_url']     = TRUE;
        final_validated[rhel_label]['rhel_valid_urls']    = url_to_check;
        invalid_labels[invalid_label]['no_valid_info']    = FALSE;
        
        break;
      }
    }
  }
}

##
# LABELS: Finally, deal with labels found on the host that don't have a URL.
# If the label itself is valid, we can get the URL from RHEL_REPO_MAP.
# Otherwise, there is nothing we can do with invalid label here.
##
var NOT_APPLICABLE = 'N/A';
var host_label_only, rhel_map;
foreach host_label_only (label_needs_url)
{
  rhel_map = RHEL_REPO_MAP[host_label_only];

  if (rhel_map)
  {
    final_validated[host_label_only]['rhel_valid_urls']  = rhel_map;
    final_validated[host_label_only]['host_valid_url']   = FALSE;
    final_validated[host_label_only]['host_valid_label'] = TRUE;
    final_validated[host_label_only]['host_invalid_url'] = NOT_APPLICABLE;
  }
  else
  {
    append_element(value:host_label_only, var:invalid_label_no_url);
  }
}

##
# Declare variables for report building  blocka
##
var url_list_for_kb              = [];

var valid_host_combo_header      =
  'The following RHEL repositories were found on the target host with official labels\n' +
  'and relative URLs.\n\n';

var valid_host_label_only_header =
  'The following RHEL repositories were found on the target host with official labels paired\n'  +
  'with unofficial relative URLs, or no relative URL was detected at all. An official relative\n' +
  'URL was paired to the label using Red Hat\'s mappings from repository-to-cpe.json.\n\n';

var valid_host_url_only_header   =
  'The following RHEL repositories were found on the target host with an unofficial label\n' +
  'paired with a valid relative url. An official label was paired to the relative URL using\n'   +
  'Red Hat\'s repository-to-cpe.json mappings.\n\n';

var invalid_label_url_header     =
  'The following RHEL repository label and URL combinations were detected, but neither\n' +
  'were found to be official as per Red Hat\'s repository-to-cpe.json mappings.\n\n';

var invalid_label_only_header    = '';

var invalid_only_caveat          =
  '\nAs there were no official RHEL repository labels or relative URLs found to be enabled,\n'  +
  'vulnerability dectection plugins in the Red Hat Local Security Checks family will be\n'    +
  'unabled to tell if the fixed packages referenced by their respective advisories are\n'     +
  'enabled on this host or not. Please note that this could potentially result in false\n'    +
  'positive findings. Tenable recommends using either official labels and/or relative URLs\n' +
  'where possible, to ensure that Nessus can accurately validate one or the other.\n\n';

var valid_host_label_only_block  = '';
var valid_host_combo_block       = '';
var valid_host_url_only_block    = '';
var invalid_label_only_block     = '';
var invalid_label_url_block      = '';

var valid_host_combo_count       = 0;
var valid_host_label_only_count  = 0;
var valid_host_url_only_count    = 0;
var invalid_label_only_count     = 0;
var invalid_label_url_count      = 0;

var report_label                 = '  RHEL Repo Label                : ';
var report_host_invalid_label    = '  Host Invalid Repo Label        : ';
var report_host_invalid_url      = '  Host Invalid Repo Relative URL : ';
var report_urls                  = '  RHEL Repo Relative URL(s)      : ';

var report = '';

##
# Build report blocks part 1: Process everything in final_validated array
##
var repo_label_key, valid_repo_label, rhel_valid_urls, host_valid_label, host_valid_url;
var invalid_host_label, invalid_host_url, url, rhel_valid_url, host_invalid_url, mi_rhel_valid_urls;
for (repo_label_key in final_validated)
{
  # Decalring each array value as a variable, just for legibility
  valid_repo_label = repo_label_key;
  rhel_valid_urls  = final_validated[repo_label_key]['rhel_valid_urls'];
  host_valid_label = final_validated[repo_label_key]['host_valid_label'];
  host_valid_url = final_validated[repo_label_key]['host_valid_url'];
  host_invalid_url = final_validated[repo_label_key]['host_invalid_url'];
  invalid_host_label = final_validated[repo_label_key]['invalid_host_label'];
  invalid_host_url = final_validated[repo_label_key]['invalid_host_url'];

  # Report repos where we found both a valid label and URL on the target
  # In this scenario, there will be only one URL (string)
  if (host_valid_label && host_valid_url)
  {
    append_element(value:rhel_valid_urls, var:url_list_for_kb);
    valid_host_combo_count ++;
    valid_host_combo_block += report_label + valid_repo_label + '\n';
    valid_host_combo_block += report_urls + rhel_valid_urls + '\n';
    valid_host_combo_block += '\n';
  }

  # Report repos were we found a valid label with an invalid URL. The correct URL was retrieved from RHEL_REPO_MAP
  # In this scenario, the URLs we pulled from RHEL_REPO_MAP are always going to be in a list (1 item or more), but,
  # if the invalid label was taken from the KB, the URL will be a string.
  else if (host_valid_label && !host_valid_url)
  {
    valid_host_label_only_count ++;
    valid_host_label_only_block += report_label + valid_repo_label + '\n';
    valid_host_label_only_block += report_host_invalid_url + host_invalid_url + '\n';

    mi_rhel_valid_urls = max_index(rhel_valid_urls);
    
    if (mi_rhel_valid_urls > 1)
    {
      valid_host_label_only_block += report_urls + '\n';
    }

    foreach rhel_valid_url (rhel_valid_urls)
    {
      append_element(value:rhel_valid_url, var:url_list_for_kb);
      if (mi_rhel_valid_urls > 1)
      {
        valid_host_label_only_block += '    - ' + rhel_valid_url + '\n';
      }
      else
      {
        valid_host_label_only_block += report_urls + rhel_valid_url + '\n';
      }
    }

    valid_host_label_only_block += '\n';
  }

  # Report repos were we found a valid URL with an invalid label. The correct label was retrieved
  # from RHEL_REPO_MAP. In this scenario, there will only be a single URL (string)
  else if (invalid_host_label)
  {
    append_element(value:rhel_valid_urls, var:url_list_for_kb);
    valid_host_url_only_count ++;
    valid_host_url_only_block += report_label + valid_repo_label + '\n';
    valid_host_url_only_block += report_host_invalid_label + invalid_host_label + '\n';
    valid_host_url_only_block += report_urls + rhel_valid_urls + '\n\n';
  }
}

##
# Build report blocks part 2: Process everything in invalid_label_no_url. There isn't anything we can do
# if we only got an invalid label and no URL so we just report it as-is.
##
var plural, invalid_label_only;
if (!empty_or_null(invalid_label_no_url))
{
  if (max_index(invalid_label_no_url) > 1)
  {
    plural = 'labels were';
  }
  else
  {
    plural = 'label was';
  }

  invalid_label_only_header += 'The following invalid RHEL repo ' + plural + ' found with no accompanying relative URL.\n\n';

  foreach invalid_label_only (invalid_label_no_url)
  {
    invalid_label_only_count ++;
    invalid_label_only_block += report_host_invalid_label + invalid_label_only + '\n';
  }

  invalid_label_only_block += '\n';
}

##
# Build report bloack part 3: Take repos details from invalid_labels and report invalid URL/label combos
##
var invalid_label_url;
for (invalid_label_url in invalid_labels)
{
  if (invalid_labels[invalid_label_url]['no_valid_info'])
  {
    invalid_label_url_count ++;
    invalid_label_url_block += report_host_invalid_label + invalid_label_url + '\n';
    invalid_label_url_block += report_host_invalid_url + invalid_labels[invalid_label_url]['host_url'] +'\n';
  }
}

##
# Set Host/RedHat/valid-repo-relative-urls for VD plugins - first check if
# any internal repos were mapped via redhat_custom_repos.nasl, then compile full list
# with the URLs detected in this check
##
var prepped_custom = get_kb_item('Host/RedHat/valid-repo-relative-urls');
if (!empty_or_null(prepped_custom))
{
  var validated_custom = deserialize(prepped_custom);
  var i, custom_url;
  if (!empty_or_null(validated_custom))
  {
    foreach custom_url (validated_custom)
    {
      append_element(value:custom_url, var:url_list_for_kb);
    }
  }
}

if (!empty_or_null(url_list_for_kb))
{
  var serialized_for_kb = serialize(url_list_for_kb);
  replace_kb_item(name:'Host/RedHat/valid-repo-relative-urls', value:serialized_for_kb);
}

##
# Put the report together
##
if (valid_host_combo_count > 0)
{
  report += valid_host_combo_header + valid_host_combo_block;
}
if (valid_host_label_only_count > 0)
{
  report += valid_host_label_only_header + valid_host_label_only_block;
}
if (valid_host_url_only_count > 0)
{
  report += valid_host_url_only_header + valid_host_url_only_block;
}
if (invalid_label_only_count > 0)
{
  report += invalid_label_only_header + invalid_label_only_block;
}
if (invalid_label_url_count > 0)
{
  report += invalid_label_url_header + invalid_label_url_block;
}
if (!valid_host_combo_count && !valid_host_label_only_count && !valid_host_url_only_count)
{
  report += invalid_only_caveat;
}

# Command line scan debugging output.
if (CLI_DEBUG)
{
  display(
    '----------------------------\n',
    '- CLI DEBUGGING OUTPUT\n',
    '----------------------------\n',
    'host_label_url_map   : ', obj_rep(host_label_url_map, prettify:TRUE), '\n\n',
    'host_labels_no_urls  : ', obj_rep(host_labels_no_urls, prettify:TRUE), '\n\n',
    'validated_labels     : ', obj_rep(validated_labels, prettify:TRUE), '\n\n',
    'invalid_labels       : ', obj_rep(invalid_labels, prettify:TRUE), '\n\n',
    'label_needs_url      : ', obj_rep(label_needs_url, prettify:TRUE), '\n\n',
    'final_validated      : ', obj_rep(final_validated, prettify:TRUE), '\n\n',
    'invalid_label_no_url : ', obj_rep(invalid_label_no_url, prettify:TRUE), '\n\n',
    'len(url_list_for_kb) : ', len(url_list_for_kb), '\n\n',
    '-----------------------------------------------\n\n'
    );
}

# Report findings
if (!empty_or_null(report))
{
  security_report_v4(
  port       : 0,
  severity   : SECURITY_NOTE,
  extra      : report
  );
}

else
{
  audit(AUDIT_NOT_INST, "a RHEL repository label or repository relative URL");
}