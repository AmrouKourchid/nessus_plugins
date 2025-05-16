##
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# rhel.inc
# Revision: 1.8
##

include("compat_shared.inc");
include("debug.inc");

global_var RHEL_REPOS_NO_OVERLAP_MESSAGE = "AUDIT";

global_var RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS = 'Red Hat repository labels that ' + '\n' +
'can be used for vulnerability checks, or labels are renamed under a ' + '\n' +
'standard not consistent with Red Hat\'s own labeling';

global_var RHEL_REPO_NOT_ENABLED = 'The Red Hat repositories impacted by this advisory ' + '\n' +
'were not found to be enabled on this host.';

##
# Compare version_a to version_b
#
# @param version_a string containing the first version to compare ('7.6', '8.1')
# @param version_b string containing the second version to compare ('7.6', '8.1')
# @anonparam version_a optional string containing the first version to compare in case version_a and version_b are missing
# @anonparam version_b optional string containing the second version to compare in case version_a and version_b are missing
#
# @return -1 if version_a < version_b or major versions do not match.
#          0 if version_a == version_b,
#          1 if version_a > version_b,
#          NULL if an error condition is encountered
##
function rhel_os_level_compare(version_a, version_b)
{
  local_var split_rhel_version, split_os_version, rhel_major_version, rhel_minor_version, os_major_version, os_minor_version;
  if (max_index(_FCT_ANON_ARGS) == 2 && isnull(version_a) && isnull(version_b))
  {
    version_a = _FCT_ANON_ARGS[0];
    version_b = _FCT_ANON_ARGS[1];
  }
  split_os_version = split(version_a, sep:'.', keep:FALSE);
  split_rhel_version = split(version_b, sep:'.', keep:FALSE);
  if(isnull(split_rhel_version[0]) || isnull(split_os_version[0])) return NULL;
  rhel_major_version = int(split_rhel_version[0]);
  os_major_version = int(split_os_version[0]);
  rhel_minor_version = 0;
  os_minor_version = 0;
  if (!isnull(split_rhel_version[1])) rhel_minor_version = int(split_rhel_version[1]);
  if (!isnull(split_os_version[1])) os_minor_version = int(split_os_version[1]);

  if(os_major_version == rhel_major_version)
  {
    if (isnull(os_minor_version) || (os_minor_version == rhel_minor_version)) return 0;
    if (os_minor_version > rhel_minor_version) return 1;
    if (os_minor_version < rhel_minor_version) return -1;
    return NULL;
  }
  # version_a and version_b have mismatched major versions.
  return -1;
}

##
# Uses the given operator to compare the os_version to the given rhel_version.
#
# @param operator string to determine what operator to use ('eq', 'ge', 'gt', 'le', 'lt')
# @param os_version string containing the OS version from the host ('7.6', '8.1')
# @param rhel_version string containing the rhel_version to compare os_version against ('7.6', '8.1')
#
# @remark The operators are as follows:
#         eq - equal
#         ge - greater than or equal
#         gt - greater than
#         le - less than or equal
#         lt - less than
#
# @return TRUE if rhel_version and os_version are evaluated to true using the given operator case
#         FALSE otherwise
##
function rhel_check_release(operator, os_version, rhel_version)
{
  local_var comparison;
  comparison = rhel_os_level_compare(version_a:os_version, version_b:rhel_version);
  if (isnull(comparison)) return FALSE;
  switch (operator)
  {
    case 'eq':
      if (comparison == 0) return TRUE;
      return FALSE;
    case 'ge':
      if (comparison >= 0) return TRUE;
      return FALSE;
    case 'gt':
      if (comparison > 0) return TRUE;
      return FALSE;
    case 'le':
      if (comparison <= 0) return TRUE;
      return FALSE;
    case 'lt':
      if (comparison < 0) return TRUE;
      return FALSE;
  }
}

##
# Uses the given operator to compare the os_version to the given list of rhel_versions.
#
# @param operator string to determine what operator to use ('eq', 'ge', 'gt', 'le', 'lt')
# @param os_version string containing the OS version from the host ('7.6', '8.1')
# @param rhel_versions list containing rhel_versions to compare os_version against (['7.6', '8.1'])
#
# @remark The operators are as follows:
#         eq - equal
#         ge - greater than or equal
#         gt - greater than
#         le - less than or equal
#         lt - less than
#
# @return TRUE if any of the rhel_versions and os_version are evaluated to true using the given operator case
#         FALSE otherwise
##
function rhel_check_release_list(operator, os_version, rhel_versions)
{
  local_var rhel_version;
  if (typeof(rhel_versions) != 'array') rhel_versions = make_list(rhel_versions);
  foreach rhel_version (rhel_versions)
  {
    if(rhel_check_release(operator:operator, os_version:os_version, rhel_version:rhel_version)) return TRUE;
  }
  return FALSE;
}

##
# Determines valid repo set labels if any are available
#
# @remark Pulls Host/RedHat/valid-repos entry, checks against repositorites to see what entries overlap
#
# @return {} if there are no valid repos, else
#         RHEL_REPOS_NO_OVERLAP_MESSAGE if there are valid repos and they don't match the repositories array entries at all, else
#         array with keys indicating repo set names containing the installed valid repos which exist in repositories array
##
function rhel_get_valid_repo_sets(repositories)
{
  var valid_repos, repo_split, repo, repo_array, valid_array, repo_set;
  repo_array = {};
  valid_array = {};
  valid_repos = get_kb_item('Host/RedHat/valid-repos');
  if (!isnull(valid_repos) && strlen(valid_repos))
  {
    repo_split = deserialize(valid_repos);
    foreach repo (repo_split)
    {
      repo_array[repo] = 1;
    }
    # Check for repositories entries in repo_array
    if (isnull(repositories) || isnull(max_index(keys(repositories))))
    {
      return valid_array;
    }
    foreach repo_set (keys(repositories))
    {
      foreach repo (repositories[repo_set])
      {
        if (!isnull(repo_array[repo]))
        {
          valid_array[repo_set] = 1;
          break;
        }
      }
    }
    if (isnull(max_index(keys(valid_array))))
    {
      return RHEL_REPOS_NO_OVERLAP_MESSAGE;
    }
  }
  return valid_array;
}

##
# Determine if repos match or should be ignored
#
# @return TRUE if there are no valid repos or RHEL_REPOS_NO_OVERLAP_MESSAGE is found, implying repos should not be considered, else
#         TRUE if a valid repo set was detected matching one of the sets we're currently looking for, else
#         FALSE
##
function rhel_decide_repo_check(repo_list, repo_sets)
{
  var repo;
  if (isnull(repo_sets) || repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || isnull(max_index(keys(repo_sets))))
  {
    # All the repos are non-official labels or there are none. Pass the repo check and do package checks.
    return TRUE;
  }
  if (isnull(repo_list) || isnull(max_index(keys(repo_list))))
  {
    # The repo-list was passed badly. Pass the repo check and do package checks.
    return TRUE;
  }
  foreach repo (repo_list)
  {
    # A valid repo set was detected matching one of the sets we're currently looking for.
    if (repo_sets[repo])
    {
      return TRUE;
    }
  }
  # A valid matching repo set was not detected.
  return FALSE;
}

##
# Determine if any repo sets begin with "enterprise_linux"
#
# @return TRUE if there are any repo sets starting with "enterprise_linux", else
#         FALSE
##
function rhel_repo_sets_has_enterprise_linux(repo_sets)
{
  var repo;
  if (isnull(repo_sets) || repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || isnull(max_index(keys(repo_sets))))
  {
    # No valid repo sets to check.
    return FALSE;
  }
  foreach repo (keys(repo_sets))
  {
    if (preg(string:repo, pattern:'^enterprise_linux'))
    {
      return TRUE;
    }
  }
  return FALSE;
}

##
# Determine if any repo URLs begin with "content/dist/rhel<major_version>".
# This indicates the URL is for standard Red Hat Enterprise Linux.
#
# @return TRUE if there are any repo urls starting with "content/dist/rhel<major_version>", else
#         FALSE
##
function rhel_repo_urls_has_content_dist_rhel(repo_urls)
{
  var repo_url;
  if (isnull(repo_urls) || isnull(max_index(keys(repo_urls))))
  {
    # No valid repo URLs to check.
    return FALSE;
  }
  foreach repo_url (repo_urls)
  {
    # Red Hat changed the URL structure in RHEL 8 so we have to check for the old pattern as well (for RHEL 5-7).
    if (preg(string:repo_url, pattern:'^content/dist/(rhel[1-9]/|rhel[1-9][0-9]+|rhel/server/[5-7])'))
    {
      return TRUE;
    }
  }
  return FALSE;
}

##
# Determine if repo relative URLs match or should be ignored
#
# @return TRUE if there are no valid repos, implying repos URLs should not be considered, else
#         TRUE if a valid repo relative URL was detected matching one of the URLs we're currently looking for, else
#         FALSE
##
function rhel_decide_repo_relative_url_check(required_repo_url_list)
{
  var repo_url, valid_repo_urls, valid_repo_url_split, required_repo, required_repo_array;
  valid_repo_urls = get_kb_item('Host/RedHat/valid-repo-relative-urls');
  if (isnull(valid_repo_urls) && (!isnull(required_repo_url_list)))
  {
    # No valid repositories found during scan.  We cannot accurately determine if the host machine
    # subscribes to these repositories. Return TRUE to run package checks.
    return TRUE;
  }
  foreach required_repo (required_repo_url_list)
  {
    required_repo_array[required_repo] = 1;
  }
  valid_repo_url_split = deserialize(valid_repo_urls);
  foreach repo_url (valid_repo_url_split)
  {
    # A valid repo set was detected matching one of the sets we're currently looking for.
    if (!empty_or_null(required_repo_array[repo_url])) return TRUE;
  }
  # A valid matching repo relative URL was not detected.
  return FALSE;
}

##
# Determines if any valid repository relative URLs are enabled and applicable to the list of constraints
#
# @remark Pulls Host/RedHat/valid-repo-relative-urls entry, checks against each constraint's repo_relative_urls to see what entries overlap
#
# @return TRUE if constraints and valid-repo-relative-urls have overlapping URLs, implying the constraints are applicable.
#         RHEL_REPOS_NO_OVERLAP_MESSAGE if there are valid repository relative URLs and they don't match the constraints array entries at all, else
#         FALSE if no valid repo relative URLs exist.
##
function rhel_determine_applicable_repository_urls(constraints, appstreams)
{
  var valid_repo_urls, repo_url_split, repo_url, repo_url_array, constraint_set, rhel_module;
  repo_url_array = {};
  valid_repo_urls = get_kb_item('Host/RedHat/valid-repo-relative-urls');
  if (isnull(constraints) || isnull(max_index(keys(constraints)))) return FALSE;
  if (!empty_or_null(valid_repo_urls) && strlen(valid_repo_urls))
  {
    repo_url_split = deserialize(valid_repo_urls);
    foreach repo_url (repo_url_split)
    {
      repo_url_array[repo_url] = 1;
    }

    foreach constraint_set (constraints)
    {
      if (!empty_or_null(appstreams)) {
        # Appstream constraint arrays have an extra layer to iterate through
        foreach rhel_module (constraint_set)
        {
          foreach repo_url (rhel_module['repo_relative_urls'])
          {
            if (!empty_or_null(repo_url_array[repo_url]))
            {
              # At least one applicable repository URL was found, return TRUE.
              return TRUE;
            }
          }
        }
      } else {
        foreach repo_url (constraint_set['repo_relative_urls'])
        {
          if (!empty_or_null(repo_url_array[repo_url]))
          {
            # At least one applicable repository URL was found, return TRUE.
            return TRUE;
          }
        }
      }
    }
    # No overlapping repository relative URLs found between constraints and valid-repo-relative-urls.
    return RHEL_REPOS_NO_OVERLAP_MESSAGE;
  }
  return FALSE;
}

##
# Retrieves user-defined repository mapping file and prepares it for use by RHEL local checks
#
# @remark
# Locates the imported repo mapping file and prepares it for use by redhat_custom_repos.nasl.
#
# @return [array] Custom repo mapping to redhat_custom_repos.nasl
##
function get_rhel_custom_repo_mapping()
{
  var data, user_pref, data_ret, map;

  data = NULL;
  user_pref = 'custom_rhel_repo_mapping';
  dbg::detailed_log(lvl:2, msg:"Confirming if custom repo mapping preference is enabled...");
  if (get_preference(user_pref))
  {
    dbg::detailed_log(lvl:2, msg:"Custom repo mapping preference enabled, locating mapping file...");
    data = get_preference_file_content(user_pref);
    if (!isnull(data))
      dbg::detailed_log(lvl:2,
        msg:'Mapping file found! ',
        msg_details:{
          'raw map':{'lvl':2, 'value':data}
      });
    else if (isnull(data) && strlen(data) < 1)
    {
      dbg::detailed_log(lvl:2, msg:"Custom repo mapping preference is enabled but returned an empty file.");
      return FALSE;
    }
  }

  if (!isnull(data))
  {
    dbg::detailed_log(lvl:2, msg:"Mapping file prepared for policy...");
    return data;
  }
  return FALSE;
}
