###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# version_list.inc
#
# Revision: 1.5
#
# @include lists.inc
# @include spad_log_func.inc
###

include('lists.inc');
include('spad_log_func.inc');
include('debug.inc');
include('compat_shared.inc');

namespace version_list {
  ##
  # Default Version Matching Pattern
  # Based largely on Semantic Version 2.0.0: https://semver.org/
  #
  # This pattern must include at least one matching group. The first
  # group is used for sorting. The matching group below will look for 
  # major.minor.patch-pre-release in the string and return it as the 
  # first group which is subsequently used as the string for sorting.
  #
  # This pattern can be overridden by a plugin but must include a matching group.
  ##
  var ver_regex = strcat(
    "^",
    "v?", 
    "(",                                            # Default sorting on core and pre-release
    "\d+\.\d+\.\d+",                                # Version core
    "(?:\-(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?", # Pre-release optional
    ")",
    "(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?", # Build optional
    "$"
  );

  # Slightly adapted version regex - allows for version numbers that have more or less than 3 numerical parts
  var lax_ver_regex = strcat(
    "^",
    "v?", 
    "(",                                            
    "(?:\d+\.)+\d+",                                # Less strict - 2+ parts instead of exactly 3
    "(?:\-(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?",
    ")",
    "(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?",
    "$"
  );
  
  ##
  # Munging patterns allow you to assign custom integer values to patterns so that
  # they are properly sorted when passed to collib::version_sort(). For example, with
  # the default pattern below the pre-release version 1.0.0-alpha1 becomes 1.0.0-1.1
  # and the core version 1.1.1 without a pre-release becomes 1.1.1.999 so that it
  # is a numerically higher version than alpha or beta versions.
  #
  # See function _mung() for implementation details.
  #
  # Additional patterns can be added (e.g mung_patterns["your pattern"] = int)
  ##
  var mung_patterns = {
    "alpha": 1,
    "beta": 2,
    "^(\d+\.\d+.\d+)$": "\1.999"
  };

  ##
  # Accepts a list of version strings, parses them for validity, and returns a sorted
  # list containing only the valid strings.
  #
  # @param [list:list] List of version strings.
  # @param [regex:string] Optional. Pattern to validate version strings.
  #
  # @return Sorted list of valid string from lowest to highest version, or NULL if an error occurred.
  ##
  function sort(list, regex)
  {
    if (!list) return NULL;
    if (regex) ver_regex = regex;
    var arr, ver, tmp_list = [], ret = [];

    arr = _mung(arr:_scrub(list:list));
    foreach ver(arr)
      append_element(var:tmp_list, value:ver);
    foreach ver(collib::version_sort(tmp_list))
      append_element(var:ret, value:_find_arr_key(arr:arr, val:ver));

    return ret;
  }

  ##
  # Returns the highest version that conforms to the regex. If no regex is supplied
  # the strings in the list are checked against the default regex.
  #
  # @param [list:list] List of version strings.
  # @param [regex:string] Optional. Pattern to validate version strings.
  #
  # @return Highest version from valid strings in list, or NULL if an error occurred.
  ##
  function max(list, regex)
  {
    if (!list) return NULL;
    if (regex) ver_regex = regex;

    list = sort(list:list);
    if(list[0])
      return list[len(list) -1];
    
    return NULL;
  }

  ##
  # Remove strings from the list if they don't match a valid version
  # based on the global variable ``version_list::ver_regex``.
  #
  # @param [list:list] List of version strings from which to scrub strings.
  #
  # @return The list without the scrubbed strings, or NULL if an error occurred.
  ##
  function _scrub(list)
  {
    if (!list) return NULL;
    var match, ver, ret = {};
  
    foreach ver(list)
    {
      match = pregmatch(pattern:ver_regex, string:ver);
      if(!empty_or_null(match)) 
        ret[ver] = match[1];
      else
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "Bad version format stripped",
          msg_details: {
            "Version": {"lvl": 2, "value": ver}});
    }

    return ret;
  }

  ##
  # Mung data based on patterns and replacements in ``version_list::mung_patterns`` array.
  #
  # @param [arr:array] The array in which to mung the data.
  #
  # @return The new array with munged data, or NULL if an error occurred.
  ##
  function _mung(arr)
  {
    if (!arr) return NULL;
    var ak, mk;
    
    foreach ak(keys(arr))
      foreach mk(keys(mung_patterns))
        arr[ak] = ereg_replace(pattern:mk, replace:mung_patterns[mk] + '.', string:arr[ak]);

    foreach ak(keys(arr)) 
      arr[ak] = _alpha_to_ord(ver:arr[ak]);

    return arr;
  }

  ##
  # Replaces letters with their tolower ordinal value for sorting.
  #
  # @param [ver:string] The string in which letters should be replaced.
  #
  # @return [string] The string with converted letters.
  ##
  function _alpha_to_ord(ver)
  {
    if(!ver) return '';
    var i, ret = '', prev;
    
    for(i = 0; i < len(ver); i++)
      if(ver[i] =~ "^[A-Za-z]$") 
        ret += strcat(ord(tolower(ver[i])), '.');
      else 
        ret += ver[i];
    
    return _clean(ver:ret);
  }

  ##
  # Replaces multiple sequences of dots(.) and plusses(+) and dashes(-) with a single dot.
  #
  # @param [ver:string] The string in which characters should be replaced.
  #
  # @return [string] The cleaned up string.
  ##
  function _clean(ver)
  {
    if(!ver) return '';

    ver = ereg_replace(pattern:"\-|\+", replace:'.', string:ver);
    ver = ereg_replace(pattern:"\.{2,}", replace:'.', string:ver);
    ver = ereg_replace(pattern:"\.$", replace:'', string:ver);

    return ver;
  }

  ##
  # Search for array key by value.
  #
  # @param [arr:array] The array in which to search for the value.
  # @param [val:any] The value to search for.
  #
  # @return The key where the value was found, or NULL if the value wasn't found or an error occurred.
  ##
  function _find_arr_key(arr, val)
  {
    if(!arr || !val) return NULL;

    foreach var key(keys(arr))
      if(arr[key] == val) return key;
    
    return NULL;
  }
}
