#TRUSTED 7b30b0f25159aa9ae5e63b009ed37feff95dc1708579edb7a578cf83a48734fe12d6f052ca2d13e3817d92904b478bf3f70643773b39e904b113275a19233169aeee4c3a358c833e74103410d18c4ba73c18db8735e73d00cc35146837fc9c1dab1bc5f8f39822f6633efba5b0955e7ee62ac407306f10877a9c3044ad94c8a7ba653463ee226f5e1cea8bfe3e379b4c786b30076731b523a9bd9fbf4b884102a16ca13c27a94f162a444c18305a0e9a4467409e7cf5f6639d616c75b71c8c55db455e5321cb3e5066a5e5bc7514cc4e7dd439adf998d09e716cf1675d61d1f0872d53a9b586977dfd9141c4c398479414c9cdee0f8ed62a47802c080827eb7383dc65392c6b2a2c3d6da8a97c4c56fb42521cf7cb39fbb3717717746d360d073f4c1605887803e66f0c4ee22fc130924344b5550d139e8575d1f18c8c9b3878bfdc1321f48ebbae3fea463d77138d0601303e1c2666b9fe5e85cf1017fac327c3d32792b51d4e27dbe770e725ba370e92432bb43f05a9b289b4304b8d4a08f26cf7497356e8b3ab5bc53c06a34e04dd54b38e2cb2295d01308d37a3e0d52c6008eceab0afcb41bde91de91bd69ec13d915585ffb7ba0f966c5b64ae19dc73c05ea25a0009b8c2c24fff4dc30d13d0a35966631cb4120cd49a7375dba831b0c1fe76cd3e644437f24b1e44dbadf4b0f2af4edc58b739ed87b2467a71396e1540
#TRUST-RSA-SHA256 42ff9777c4e64c055a94bf09fb7d6e7fac337d0b6d2378b7bd1a77ef1e5bdb01fd69fcf438d7f53399b5f8dcb35c8b5f65000ef8e93bc85c597eb86b42f988efc70b398b3707d240fd986768045e0d20b1fee42e625d4d9d41e54b214738f08f521b84c1ad38c69eec8eb054a729a3c024ad70e7e21bfcf62e5637496390f733d09f26341d4653078597d52d242dce88ff34a11da2e1518733c14fe077b3f439d13eccd253111e79bcc8c14c90b75ae62270dec547050a003c2236b57c421164034d0ed61a92b95e3ddd09b0bc8ad017f98bbb5b92eede0440878ac1875c8d5e78b65f2f7556160da2b5dcbe436f327a3a1fda34379e63b2ff3881196206f2773b2512b6dcfceab8a0eb209e820c94248687b8e354240b76582787877063b376af3370814240a79b7f632d43a96290243ba0d7a6ecc14f671552c64f4d26788c51bbd658fba2aaabd85c12b6bda21da28c615a2704ab1fedcd90b56daa5951ec1c73fbb706ae7afb5caf947f6340f61bbd4deb9fcf248c896999527826cf9f7967e54a41935b809da8b0f0a9957fddec334dc9338b62283e340c173b88b29e80d808b03098f0b2d7600d80b089ca4a1d0c684f2890e4d60c7667fe1f05fa76aa4ce7dfa8e9008c398f659e75c8364f33944591a9c7ad6a5edb0c336e826890f06862e2adb78cb45a31c02040da10c3349ffd1eb0b24ec2fcc0a9fc019bece3e0
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# microsoft_azure.inc
# Revision: 1.4
#
include("compat_shared.inc");
include("json.inc");

global_var AZURE_API_HOST, AZURE_API, AZURE_HOST_TAG_BASE, AZURE_KB_BASE, success, failure;

##
# Azure API Host IP 169.254.169.254
# but as of 2022-11-03 we use the WireServer IP 168.63.129.16
# because the previous IP returned 403 errors on some endpoints
##
AZURE_API_HOST = "168.63.129.16";

##
# Azure API configurations
#   Headers : required HTTP headers
#   Content : output format to be parsed
#   Items   : API items to gather
#
#   Note: the 'path' of the API should not contain '&' characters
##
AZURE_API["/metadata/instance/compute?api-version=2017-12-01"] = make_array(
  "Content", "JSON",
  "Headers", make_array(
    "Metadata", "true"),
  "Items", make_array(
    "subscriptionId", "subscriptionId",
    "resourceGroupName", "resourceGroupName",
    "vmId", "vmId")
);

AZURE_API["/metadata/latest/InstanceInfo"] = make_array(
  "Content", "JSON",
  "Items", make_array(
    "ID", "InstanceName",
    "UD", "UD",
    "FD", "FD")
);

AZURE_API["/machine?comp=goalstate"] = make_array(
  "Headers", make_array(
    "x-ms-guest-agent-name", "WaAgent-2.5.0.0 (2.7.0.0)",
    "x-ms-version", "2015-04-05"),
  "Content", "XML",
  "Items", make_array(
    "ContainerId", "ContainerId",
    "InstanceId",  "InstanceId",
    "State",       "State")
);

##
# XML Host Tag base
##
AZURE_HOST_TAG_BASE = "azure-instance";

##
# KB Base
##
AZURE_KB_BASE = "Host/Azure";

##
# Parses output
#
# @param string output to be parsed
# @param string content of the output (XML, JSON)
# @param array  items to parse out of the output
# 
# @return array like {"api_item_1" : "api_value_1", ... "api_item_N" : "api_value_N"} if API items were found
#         NULL  if an error occurred or no API items were found
##
function azure_parse_output(output, content, items)
{
  local_var item, items_found, matches, pairs, json_object, key;

  if (empty_or_null(output) || empty_or_null(content) || empty_or_null(items))
    return NULL;

  if (typeof(output) !~ '(data|string)' || typeof(content) !~ '(data|string)' || typeof(items) != 'array')
    return NULL;

  items_found = make_array();

  if (content == "XML")
  {
    # Remove newlines and return carriages we don't need them and they can cause issues
    output = str_replace(string:output, find:'\r', replace:'');
    output = str_replace(string:output, find:'\n', replace:'');

    foreach item (keys(items))
    {
      matches = pregmatch(string:output, pattern:"<"+item+">([^<]+)</"+item+">", icase:TRUE);
      if (!isnull(matches))
        items_found[item] = matches[1];
    }
  }
  else if (content == "JSON")
  {
    # Compile array of all key/value pairs (the keys are unique AFAIK)
    pairs = make_array();
    foreach json_object (json_read(output))
    {
      if (empty_or_null(json_object) || typeof(json_object) != 'array') continue;

      foreach key (keys(json_object))
        pairs[key] = json_object[key];
    }
    # Parse out the specified items and store them
    foreach item (keys(items))
    {
      if (!empty_or_null(pairs[item]))
        items_found[items[item]] = pairs[item];
    } 
  }
  # content type not supported
  else
    return NULL;

  if (!empty_or_null(items_found))
    return items_found;

  # No API items found
  return NULL;
}
