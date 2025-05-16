###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# patches.inc
#
# Revision: 1.9
#
###

include('compat_shared.inc');
include('debug.inc');
include('lists.inc');

object version_map_handler {

  var version_map;
  var version_comparator;
  var patch_checker;
  var patched_version_handler;
  var break_on_patched;
  var ordered_versions;
  var version_filter;

  ##
  # Constructor
  #
  # @anonparam <1st> array containing the patch to version mapping data
  # @anonparam <2nd> patch checker object for checking if a version meets a specific patch requirement
  # @anonparam <3rd> patched_version_handler object that gets invoked each time a patched version is found
  ##
  function version_map_handler() {
    if (_FCT_ANON_ARGS[0]) version_map = _FCT_ANON_ARGS[0];
    if (_FCT_ANON_ARGS[1]) patch_checker = _FCT_ANON_ARGS[1];
    if (_FCT_ANON_ARGS[2]) patched_version_handler = _FCT_ANON_ARGS[2];
  }

  ##
  # - Iterates over each version and each corresponding patch check in the version map 
  # - Each check in the version map is processed by the patch checker object
  # - Each patched versionn is processed through the patched version handler
  # - A version comparator object may be used to filter versions lower than found patched versions
  ##
  public function process_version_map() {
    if (empty_or_null(version_map)) return;

    # initialze the patched version handler
    if (patched_version_handler) patched_version_handler.initialize();

    # Iterate over each version from the version map
    local_var version;
    if (isnull(ordered_versions)) ordered_versions = keys(version_map);

    foreach version (ordered_versions) {
      # Filter version through regex string
      if (version_filter && version_filter.filter(version)) continue;

      # skip versions lower than the highest patched version found using a version_comparator
      if (version_comparator && version_comparator.compare(version)) continue;

      # ensure check_list and its contentents are stored in nested lists
      local_var check_list = version_map[version];
      if (typeof(check_list) != 'array') check_list = make_nested_list(check_list);
      if (typeof(check_list[0]) != 'array') check_list = make_nested_list(check_list);

      # Iterate over each patch check associated with the current version
      local_var patch_check;
      foreach patch_check (check_list) {
        if (typeof(patch_check) != 'array') patch_check = make_list(patch_check);
        # Check if the version is patched
        if (patch_checker.is_patched(version:version, check:patch_check)) {
          # function to handle found patched versions
          if (patched_version_handler) {
            patched_version_handler.new_patched_version(version:version, patch_check:patch_check);
          }

          # If control flow variable break_on_patched is set, break when patched version found
          if (break_on_patched) break;
        }
      }
    }
  }
  ##
  # version filter setter
  #
  # @param filter - version_filter object to be set
  ##
  public function set_version_filter(filter) {
    if (isnull(filter)) filter = _FCT_ANON_ARGS[0];
    version_filter = filter;
  }

  ##
  # version_comparator setter
  #
  # @param comparator - version_comparator object to be set
  ##
  public function set_version_comparator(comparator) {
    if (isnull(comparator)) comparator = _FCT_ANON_ARGS[0];
    version_comparator = comparator;
  }

  ##
  # ordered_versions setter
  #
  # @param ver_list - list of versions to set ordered_versions
  ##
  public function set_ordered_versions(ver_list) {
    if (isnull(ver_list)) ver_list = _FCT_ANON_ARGS[0];
    ordered_versions = ver_list;
  }

  ##
  # break_on_patched setter
  #
  # @param <boolean> value, set to TRUE if you wish to break after a check results in a patched version
  ##
  public function set_break_on_patched(value) {
    if (isnull(value)) value = _FCT_ANON_ARGS[0];
    if (value) break_on_patched = TRUE;
    else break_on_patched = FALSE;
  }
}

object simple_patched_version_handler {

  var patch_version;

  ##
  # Constructor
  #
  # initializes patch_version to an empty string
  ##
  function simple_patched_version_handler() {
    initialize();
  }

  ##
  # Stores the patched version in variable patch_version
  # - Doesn't use patch_check (other patch_version handlers may use this)
  #
  # @param <string> version, the new patch version found
  # @param <array> the patch_check corresponding to the version
  ##
  public function new_patched_version(version, patch_check) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    set_patch_version(version);
    dbg::log(msg:'version: ' + version + ' is patched');
  }

  ##
  # Initializes the patched_version_handler variables to their default state
  # 
  # - sets patch version to an empty string
  ##
  public function initialize() {
    set_patch_version('');
  }

  ##
  # Patch version setter
  #
  # @param version - version to be set in patch_version
  ##
  public function set_patch_version(version) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    patch_version = version;
  }
}

object list_all_patched_version_handler {

  var patched_version_list;

  ##
  # Constructor
  #
  # initializes patch_version_list to an empty list
  ##
  function list_all_patched_version_handler() {
    initialize();
  }

  ##
  # Initializes the patched_version_handler variables to their default state
  # 
  # - sets patch_version_list to an empty list
  ##
  public function initialize() {
    patched_version_list = make_list();
  }

  ##
  # Stores all patched versions in a list
  # - Doesn't use patch_check (other patch_version handlers may use this)
  #
  # @param <string> version, the new patch version found
  # @param <array> patch_check, the patch data used to verify if the version is patched
  ##
  public function new_patched_version(version, patch_check) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    if (!collib::contains(patched_version_list, version)) add_patched_version(version);
    dbg::log(msg:'version: ' + version + ' is patched');
  }

  ##
  # Appends a version to patched_version_list
  #
  # @param version - version to append to patched_version_list
  ##
  public function add_patched_version(version) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    collib::push(version, list:patched_version_list);
  }
}


object simple_patch_checker {

  var installed_patches;

  ##
  # Constructor
  #
  # @anonparam <list> containing the installed patches
  ##
  function simple_patch_checker() {
    installed_patches = _FCT_ANON_ARGS[0];
    if (isnull(installed_patches)) installed_patches = make_list();
    if (typeof(installed_patches) != 'array')
      installed_patches = make_list(installed_patches);
  }

  ##
  # Determines if a version meets a patch requirement by checking if the patches in a given check
  # are a subset of the patches installed
  #
  # @param check - list of required patches
  # @return boolean TRUE if check is a sublist of installed_patches, else FALSE
  ##
  public function is_patched(version, check) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    if (isnull(check)) check = _FCT_ANON_ARGS[1];
    if (isnull(check)) return FALSE;
    if (typeof(check) != 'array') check = make_list(check);
    return collib::is_sublist(check, installed_patches);
  }

  ##
  # installed_patches setter
  #
  # @param patches - installed patches to be set
  ##
  public function set_installed_patches(patches) {
    if (isnull(patches)) patches = _FCT_ANON_ARGS[0];
    installed_patches = patches;
  }
}

object supersession_map_handler {

  var installed_patches;
  var supersession_map;
  var superseded_patches;

  ##
  # Constructor
  #
  # @anonparam <1st> supersession map array for mapping superseding patches
  # @anonparam <2nd> installed patches
  ##
  function supersession_map_handler() {
    supersession_map = _FCT_ANON_ARGS[0];
    installed_patches = _FCT_ANON_ARGS[1];
  }

  ###
  # Checks installed patches against the supersession map to find patches that have been superseded
  # If a patch supersedes another patch, it will be a key in the supersession_map array and it's value
  # will be the superseded patch. If one patch supersedes multiple patches, the value will be a list of patches.
  # This function copies the installed_patches list to the open_list, and the open_list is iterated until it is
  # empty. Each patch on the list is checked for superseding patches, if there are, these get added to the open_list,
  # Patches that have been checked are moved to the closed_list. The closed_list is used to ensure we don't process
  # the same patch twice, avoiding potential infinite loops.
  #
  # @return list containing superseded patches, else returns an empty list
  ##
  public function get_superseded_patches() {
    superseded_patches = make_list();
    if (empty_or_null(installed_patches)) return superseded_patches;
    if (empty_or_null(supersession_map)) return superseded_patches;
    if (typeof(installed_patches) != 'array') installed_patches = make_list(installed_patches);
    local_var open_list = collib::list_copy(installed_patches);
    local_var closed_list = make_list();
    while (!empty_or_null(open_list)) {
      local_var patch = collib::pop(list:open_list);

      # check if patch has already been processed
      if (collib::contains(closed_list, patch)) continue;
      collib::push(patch, list:closed_list);

      # check if patch superseds other patches, if so add them to the open_list
      local_var superseded_patch = supersession_map[patch];
      if (!isnull(superseded_patch)) {
        # if superseded_patch is a list of patches (type would be array)
        if (typeof(superseded_patch) == 'array') {
          open_list = make_list(open_list, superseded_patch);
          superseded_patches = make_list(superseded_patches, superseded_patch);
        }
        # if superseded_patch is not a list
        else {
          collib::push(superseded_patch, list:superseded_patches);
          collib::push(superseded_patch, list:open_list);
        }
      }
    }
    return superseded_patches;
  }


  ##
  # supersession_map setter
  #
  # @param map - supersession_map to be set
  ##
  public function set_supersession_map(map) {
    if (isnull(map)) map = _FCT_ANON_ARGS[0];
    supersession_map = map;
  }

  ##
  # installed_patches setter
  #
  # @param patches - installed_patches to be set
  ##
  public function set_installed_patches(patches) {
    if (isnull(patches)) patches = _FCT_ANON_ARGS[0];
    installed_patches = patches;
  }
}


object simple_version_comparator {

  var patched_version_handler;
  ##
  # Constructor
  #
  # @anonparam patched_version_handler
  ##
  function simple_version_comparator() {
    local_var handler = _FCT_ANON_ARGS[0];
    patched_version_handler = handler;
  }

  ##
  # Compares the patched_version stored in the patched_version handler against a given version
  #
  # @param version - version to compare against the patched_version handler's patched_version
  # @return <boolean> TRUE if the version is older or equal to the patched version stored in the patched_version_handler;
  #   if version is NULL returns TRUE; if patch_handler is NULL returns TRUE; else retruns FALSE
  ##
  public function compare(version) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    if (isnull(version)) return TRUE;
    if (isnull(patched_version_handler)) return TRUE;
    local_var patched_version = patched_version_handler.patch_version;

    if (empty_or_null(patched_version)) return FALSE;
    return ver_compare(ver:patched_version, fix:version, strict:FALSE) > -1;
  }

  ##
  # patched_version_handler setter
  #
  # @param handler - patched_version_handler to be set
  ##
  public function set_patched_version_handler(handler) {
    if (isnull(handler)) handler = _FCT_ANON_ARGS[0];
    patched_version_handler = handler;
  }
}

object regex_version_filter {

  var regex_str;
  ##
  # Constructor
  #
  # @anonparam regex_str - regex string used for filtering versions
  ##
  function regex_version_filter() {
    regex_str = _FCT_ANON_ARGS[0];
  }

  ##
  # Filter versions to be parsed by a patch mapper parser
  #
  # @param version - version to check against the regex string
  # @return <boolean> TRUE if the version doesn't match the regex string (filtered out)
  #   if version is NULL returns TRUE; if regex_str is NULL returns FALSE; else retruns FALSE
  ##
  public function filter(version) {
    if (isnull(version)) version = _FCT_ANON_ARGS[0];
    if (isnull(version)) return TRUE;
    if (isnull(regex_str)) return FALSE;
    return !(version =~ regex_str);
  }
}

###########
# Oracle #
#########
object oracle_patch_mapper {

  var version_map;
  var version_map_handler;
  var superseded_patches;
  var patch_version;

  ##
  # Constructor
  #
  # @anonparam <1st> version_map array
  # @anonparam <2nd> list with installed patches 
  # @anonparam <3rd> supersession map (optional)
  # @anonparam <4th> regex_str (optional), if set the regex string is used to filter the versions being iterated over
  ##
  function oracle_patch_mapper() {
    version_map = _FCT_ANON_ARGS[0];
    local_var installed_patches = _FCT_ANON_ARGS[1];
    local_var supersession_map = _FCT_ANON_ARGS[2];
    local_var regex_str = _FCT_ANON_ARGS[3];

    # If supersession_map is being used, appends superseded patches to installed patches
    if (supersession_map) {
      local_var supersession_map_handler = new supersession_map_handler(supersession_map, installed_patches);
      superseded_patches = supersession_map_handler.get_superseded_patches();
      installed_patches = make_list(installed_patches, superseded_patches);
    }

    local_var patch_checker = new simple_patch_checker(installed_patches);
    local_var patched_version_handler = new simple_patched_version_handler();
    version_map_handler = new version_map_handler(version_map, patch_checker, patched_version_handler);
    if (regex_str) version_map_handler.set_version_filter(new regex_version_filter(regex_str));
    version_map_handler.set_version_comparator(new simple_version_comparator(patched_version_handler));
    version_map_handler.set_break_on_patched(TRUE);

    # get patch_version
    version_map_handler.process_version_map();
    patch_version = patched_version_handler.patch_version;
  }
}

object oracle_ebusiness_patch_mapper {

  var version_map;
  var version_map_handler;
  var superseded_patches;
  var patched_version_list;

  ##
  # Constructor
  #
  # @anonparam <1st> version_map array
  # @anonparam <2nd> list with installed patches 
  # @anonparam <3rd> supersession map (can be empty array)
  # @anonparam <4th> regex_str, used to filter the versions being iterated over
  ##
  function oracle_ebusiness_patch_mapper() {
    version_map = _FCT_ANON_ARGS[0];
    local_var installed_patches = _FCT_ANON_ARGS[1];
    local_var supersession_map = _FCT_ANON_ARGS[2];
    local_var regex_str = _FCT_ANON_ARGS[3];

    # Append superseded patches to installed patches
    local_var supersession_map_handler = new supersession_map_handler(supersession_map, installed_patches);
    superseded_patches = supersession_map_handler.get_superseded_patches();
    installed_patches = make_list(installed_patches, superseded_patches);

    local_var patch_checker = new simple_patch_checker(installed_patches);
    local_var patched_version_handler = new list_all_patched_version_handler();
    version_map_handler = new version_map_handler(version_map, patch_checker, patched_version_handler);

    version_map_handler.set_version_filter(new regex_version_filter(regex_str));
    version_map_handler.set_break_on_patched(FALSE);

    # get patched versions
    version_map_handler.process_version_map();
    patched_version_list = collib::remove_duplicates(patched_version_handler.patched_version_list);
    patched_version_list = collib::version_sort(patched_version_list);
  }
}
