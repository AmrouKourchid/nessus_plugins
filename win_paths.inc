#TRUSTED 51c53483268fcd8760c3d4fece7ce391424dc5db57908ddbc234a7ad03f8901af9743740a9f2c9075cbb0b9b1b3c6698a07f792c1b6b58b360747857268e40be9ef5258ea8eeee849fa9bd70270416e7004bf93388cb1187cd6ecd76b190435b6ee52c20d670c4705fd6056900771a5d7b72a4ee945c1468c123e8be586e08f9991e81bed3522836a345372e05c695aca7bad392e24e55d7803a31b7a63627646ad0eebaac4e086090c114852ef514b8257dd3bbba824cc26380428e5c7674c21849c10495c77965bb330f1246096f54d2c72017e32a36fcdefc3a812ae5015b8507b3ce7697a9e1ccf177a10aacde00751b9aeb731f73980ace20a8117c5969d5a388bc586579780d139b49ffa6b51c2a89556448bb89787904e31ac2e96f99aedb14fd1894eb12981bc74495f9d39adf501e515242b9e4403645d2f15c31075eed2311d141b906aba504f17bc97a55c05c4be748ba2c118f75c18b7f1408a4ab9fe0a84145b615e83d3a21fb51fc487a8e38d22d7a06d21e6625e920b8cf79fd2667515c57ef2ffe346fd27e7eb8c7647d9dbb80b62f27c3eac13523bb7dbae6d30fdd53c2f1f7bcaa92ad07380a7bc4169859226127107df00755d6b4e8b374e858f0b107883ffe658ceb405abaca11904eaf392eadffe1b3a86219262cd26571444cf015c14bc9898afedf483828aacf30b8c98d09d24189ae7e0ba5c719
#TRUST-RSA-SHA256 36463193f7a338c491050bbdf48d1f7544191dffd5a555212ef2b06a8617247a3eea7b76d8bc3cc51ebd7bb3bfcfaf03a9bf0b88b8a8c97bf57017e2f4a5fd2ac1d5e70669d8e9a6f8d4c0897ac31d1d3ba6f0caee6f308ff9db2405d9544e416db0d7dbf33124c5f0eb24bb55044ce163e4a944bf27a91cb922504682c0e785dda37848ca655846bda97d7cdfd2b303996f1843e33bee350d9fc5dc2f5c7e02bdd90e2cbe69bcb1816165ff18c6c74664f8368af207e2c3fab733dd0e6124c24c14570500de1f7565ff134a20008b71692a9ef469ca7a118232f66994be4f1fc5c6b55a9e267e97e0008f73fe51076186217dab7faa92a7d812e4c255f70d5d4acae81bc129878b69958703ae8326c2e86a5e34ddf0bb0f08a5229da08f630153338082f2e75dd5478ca6539f289104b11c1309676c4e11f4c56a1b14e1dcd7641fefbe988fa08eb23c226c4a0aa112cb4db7da926c62212ed8c51143e2cb2fb57b4d907a20774629588d4e674769d0b37461425c9f9e965b70235c4c10cccae0ece0621c9d2d071df17865ca8591ee2959d4e573883633c0d72e981e23c6d3f3f39bf83137e973cdffecfc6e7e7448ae5790cb63cc4782a2cdeeba34e4166e067a4a804a2d7dc3eb1465f924a8ff15e5a4ab262f713ad137e9a249a7b245c54036546ee9be1558331fc5c52a7d8275d026c26c8402f31c308b3209f776f293

include('compat_shared.inc');
include('debug.inc');

namespace local_detection_win
{
  # This internal value is used to determine what qualifies as a dangerous character, formed as a regex.
  # Current dangerous characters are classified as ; & ' #
  # " and | are both potential escalators but they cannot appear in windows filepaths
  # # is not dangerous on its own without the others, but it's dangerous enough.
  var windows_dangerous_character_regex = ";|&|'|#";

  ##
  # Appends a new part to a path while inserting or preserving single backslashes between the appended parts as needed.
  #
  # @param path The path that is to be extended.
  # @param value The new part that is to be appended to the path.
  # @remark Example: 'path' + 'part', 'path\' + 'part', 'path' + '\part' and 'path\' + '\part' will all result in the same 'path\part'.
  # @return The new, extended path, unmodified path when value is empty/missing or NULL when the path is empty/missing.
  ##
  function append_path(path, value)
  {
    if(empty_or_null(path)) return NULL;
    if(empty_or_null(value)) return path;
    path = trim(path, rchars:'\\');
    value = trim(value, lchars:'\\');
    return strcat(path, '\\', value);
  }

  ##
  # Takes an arbitrary number of strings and constructs a path from them by appending them in the order they were passed.
  # Makes sure each part is separated from another by exactly one backslash, regardless of whether the parts itself start or end with backslashes.
  # @anonparam part Any number of strings that will be used to build the path.
  # @remark Example: construct_path('C:\', '\Users', 'Administrator\') call will result in 'C:\Users\Administrator' path.
  #
  function construct_path()
  {
    var parts = _FCT_ANON_ARGS;
    var path = _FCT_ANON_ARGS[0];
    var len = max_index(parts);
    for(var i = 1; i < len; i += 1)
    {
      path = append_path(path:path, value:parts[i]);
    }
    return path;
  }

  ##
  # Remove characters forbidden in windows filepaths
  #
  # @param [item:string] a path to remove characters from
  #
  # @return NULL if item is not a non-empty string, else
  #         item without forbidden characters
  ##
  function filepath_remove_forbidden(item)
  {
    if (empty_or_null(item) || typeof(item) !~ '(data|string)') return NULL;
    item = ereg_replace(string:item, pattern:"[\x00-\x1F]", replace:"");
    item = ereg_replace(string:item, pattern:"<|>|\/|\?|\*|\|", replace:"");
    item = ereg_replace(string:item, pattern:'"', replace:"");
    return item;
  }

  ##
  # Escape regex special characters in windows filepaths
  #
  # @param [item:string] a path to escape
  #
  # @return NULL if item is not a non-empty string, else
  #         item with escapes in front of the regex special characters
  ##
  function filepath_escape_regex_special(item)
  {
    if (empty_or_null(item) || typeof(item) !~ '(data|string)') return NULL;
    item = ereg_replace(string:item, pattern:"\\", replace:"\\");
    item = ereg_replace(string:item, pattern:"(\.|\+|\^|\$|\(|\)|\[|\]|\{|\})", replace:"\\1");
    return item;
  }

  ##
  # Remove entries from list of paths that match a second list of paths
  #
  # @param [paths_to_check:list] a list of paths to check and trim as necessary
  # @param [paths_to_exclude:list] a list of paths to check for
  # @param [exclude_identical:bool] flag to determine whether or not to remove duplicate entries
  #
  # @remark You CAN pass the same list to both arguments. You do this when you want to trim
  #         redundant entries such as C:\, C:\Testdir\, because these paths are checked recursively
  #         and adding C:\Testdir\ when C:\ is already there serves no purpose.
  # @remark When running identical check and exclude lists, leave exlude_identical as FALSE. For different lists
  #         (comparing a separate include and exclude list) set this to TRUE.
  #
  # @return NULL if paths_to_check is not a non-empty list, else
  #         paths_to_check if paths_to_exclude is not a non-empty list, else
  #         paths_to_check with all the regex escaped matches of paths_to_exclude entries removed
  ##
  function filepath_list_trim(paths_to_check, paths_to_exclude, exclude_identical)
  {
    var return_paths, path_okay, path, escaped_path, item;
    path_okay = {};
    return_paths = [];
    if (empty_or_null(paths_to_check) || typeof(paths_to_check) != 'array') return NULL;
    if (empty_or_null(paths_to_exclude) || typeof(paths_to_exclude) != 'array') return NULL;
    if (empty_or_null(exclude_identical)) exclude_identical = FALSE;

    foreach path (paths_to_check)
    {
      path_okay[path] = TRUE;
    }
    foreach path (paths_to_exclude)
    {
      escaped_path = filepath_escape_regex_special(item:path);
      foreach item (sort(keys(path_okay)))
      {
        if (item == path && !exclude_identical)
          continue;
        # Determine if item is already covered by path, example E:\ would cover E:\Testdir\
        if (preg(string:item, pattern:escaped_path, icase:TRUE))
        {
          dbg::detailed_log(
          lvl:1,
          msg:'Redundant or Excluded path has been removed',
          msg_details:{
            "Excluding Entry":{"lvl":1, "value":escaped_path},
            "Removed":{"lvl":1, "value":item}
          });
          path_okay[item] = FALSE;
        }
      }
    }
    foreach path (sort(keys(path_okay)))
    {
      if (path_okay[path] == TRUE)
      {
        append_element(var:return_paths, value:path);
      }
    }
    return return_paths;
  }

  ##
  # Determine if windows file path contains dangerous characters which could
  # lead to command injection or privilege escalation vulnerabilities
  #
  # @param [item:string] a single path to check for dangerous characters
  #
  # @return FALSE if item is empty or null, else
  #         TRUE if item contains a windows filepath dangerous character, else
  #         FALSE
  ##
  function found_windows_filepath_dangerous_characters(item)
  {
    if (empty_or_null(item) || typeof(item) !~ '(data|string)') return FALSE;
    if (preg(string:item, pattern:windows_dangerous_character_regex))
    {
      store_dangerous_windows_filepath(item:item);
      return TRUE;
    }
    return FALSE;
  }

  ##
  # Stores dangerous windows filepath in scratchpad table, writes KB
  #
  # @param [item:string] a single dangerous filepath to be logged
  #
  # @return NULL
  ##
  function store_dangerous_windows_filepath(item)
  {
    if (empty_or_null(item) || typeof(item) !~ '(data|string)') return NULL;
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Dangerous windows filepath "' + item + '" has been discovered');
    # Determine if scratchpad table for storing these entries exists.
    query_scratchpad(
      "CREATE TABLE IF NOT EXISTS windows_dangerous_filepaths(
        path text
       );");
    query_scratchpad("INSERT INTO windows_dangerous_filepaths VALUES (?);", item);
    replace_kb_item(name:'Host/Windows/dangerous_filepaths_found', value:TRUE);
    return NULL;
  }
}
