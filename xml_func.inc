#TRUSTED 6d3d08670eb7841776907cfb0474c7aaef6a9a4c20fee3828a0a0e107b9c593e34031f9f3b24d2056a05e0e70aa9221092b26c0f8ef6e3f33d07d222244d671e0b0683a8862a6e48b11f942ee0293cc14f707563bf13413c17cd5030dc33c61cc354dad70c3d017806c8a995d5d581c5468f04e790636753fed20aaa40fb64a2ce5e19fdeff063a85b50ccfc38ee8fbbc2f13509d2da4c89df2babf99259445dbe4ba5ab93f8bdcccd2d2286fbf2778cf69ed9b05064b7bff644e78f70f0f67b6c7b008ead33bbe2e4e4b59ca3db2c16d1058ecb9fb865627d1537fb544eef2c1d6218e863fc444fc80c06ff4521562685b1aa142c0032ec00f7155d3316f44e4caf58aee6a3331b529a1c2dfe8eda5e7f40a901a2efcf3f7a802658ab300185c436ece24b4e331e64abf110a02e638c4eaa477a4179e1a92b2253e050f6367dd3b51072d084054a6e942ed6c21718a63ee40b5a49f61e6daa66fb9f33b35694a991cec6c1ca73e45ad2c6b40160a94c72adef71b8842ba790edaac194be17ae14bdbb110b1041a2beb605e09feedfb25c01110d4e35bcbe1a5d4404ce6c53db22254f7be3472ebf9790e1868190cb470fa03c884c1aebc86946b2f1a5bf6ab21b2a6fbbedc3f36709d5edc47c205409553478e3a9a5e6b2cd83ef83d58d4b8d1418153a36738d8c9553c3c90c7514a204963746714bcff1c49fe8c887dae727

# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
#
# Revision: 1.3
#
##
# The purpose of this file is to make it easier to parse and analyze large
# XML structures. Note that these functions operate on tables, not directly
# on XML - the tables are the ones created by xmlparse(). 
##

include("compat_shared.inc");
include("debug.inc");

###
# A mapping between characters used in syntax and their entity names.
# e.g. & corresponds to "amp".
#
# The purpose of this list is to allow translation such as converting <
# to &lt; though the "&" and ";" are not included in the table entries.
###
global_var XML_SYNTAX_CHAR_TABLE;
XML_SYNTAX_CHAR_TABLE = make_array(
  '"', "quot",
  '&', "amp",
  "'", "apos",
  '<', "lt",
  '>', "gt"
);

##
# Retrieve the first child in the node with the given name. For example,
# in the following XML structure:
#
# <authors>
#   <author>Ron</author>
#   <author>John</author>
# </author>
#
# Calling this for the name 'author' would return a table representing the
# first author ("Ron"). 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param name  The name to retrieve.
#
# @return An XML tables representing the node, or NULL if none were found.
##
function xml_get_child(table, name)
{
  local_var child;

  if(isnull(name))
    exit(1, "Invalid 'name' value passed to xml_get_child.");

  foreach child(table['children'])
  {
    if(child['name'] == name)
      return child;
  }

  return NULL;
}

##
# Retrieve all children in the node with the given name. For example,
# in the following XML structure:
#
# <authors>
#   <author>Ron</author>
#   <author>John</author>
# </author>
#
# Calling this for the name 'author' will return an array containing two
# elements - the node for 'Ron' and the node for 'John'. 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param name  The name to retrieve.
#
# @return An array of XML tables representing the nodes, or NULL if none were
#         found. 
##
function xml_get_children(table, name)
{
  local_var child, result;

  if(isnull(name))
    exit(1, "Invalid 'name' value passed to xml_get_child.");

  result = make_list();
  foreach child(table['children'])
  {
    if(child['name'] == name)
      result[max_index(result)] = child;
  }

  return result;
}

## 
# Get a list of names of all sub-nodes. For example, in the following XML
# structure:
#
# <author>
#   <name>Ron</name>
#   <country>Canada</country>
# </author>
#
# Calling this would return a list containing 'name' and 'country'. 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @return An array of names, or an empty array if this node was empty.
##
function xml_get_children_names(table)
{
  local_var child, result;

  result = make_list();
  foreach child(table['children'])
    result = make_list(result, child['name']);

  return result;
}

## 
# Get a list of name/value pairs of all sub-nodes. For example, in the
# following XML structure:
#
# <author>
#   <name>Ron</name>
#   <country>Canada</country>
# </author>
#
# Calling this would return a list containing 'name'=>'Ron' and
# 'country'=>'Canada'.
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @return An array of names/values, or an empty array if this node was empty.
##
function xml_get_names_values(table)
{
  local_var child, result;

  result = make_array();
  foreach child(table['children'])
    result[child['name']] = child['value'];

  return result;
}

##
# Attempt to turn the XML table back into an XML string. This isn't 100%
# effective - for example, it doesn't properly encode symbols - so at the
# moment it's best to use this for debugging purposes only.
#
# @param table   An XML table, returned by xmlparse() or any of the various
#                xml_get_* functions. 
# @param _indent An internal variable used for recursion.
# @return A string representing the XML data. 
##
function _xml_table_to_string(table, _indent)
{
  local_var _indent_str, result, attribute, child;

  if(isnull(_indent))
    _indent = 0;
  _indent_str = crap(data:' ', length:_indent * 2);

  # Do the opening tag
  result = _indent_str + "<" + table['name'];
  foreach attribute(keys(table['attributes']))
    result = result + (' ' + attribute + '="' + table['attributes'][attribute] + '"');  

  # If the string is all space/newline, it's basically blank
  if(preg(string:table['value'], pattern:'^[ \n]*$', multiline:TRUE))
    table['value'] = NULL;

  # Handle a 'value' field
  if(!isnull(table['value']) && table['value'] != '')
  {
    result = result + '>' + table['value'] + "</" + table['name'] + '>\n';
  }
  # Handle the case where there are no children
  else if(max_index(table['children']) == 0)
  {
    result = result + '\\>\n';
  }
  # Handle the case where there are children
  else
  {
    result = result + '>\n';

    foreach child(table['children'])
    {
      result = result + _xml_table_to_string(table:child, _indent:_indent + 1);
    }
    result = result + _indent_str + "</" + table['name'] + '>\n';
  }

  return result;
}

##
# Replace syntactical characters with XML entities such that it is safe
# to use the given string in attribute values and content.
#
# @anonparam str The string to replace the characters in.
#
# @remark Non-idempotent; this function will re-escape already escaped strings.
#
# @return a string suitable for an attribute value or textual content.
##
function xml_escape()
{
  local_var char, replacement, str;

  str = _FCT_ANON_ARGS[0];

  # Substitute "&" first so we don't escape any we add.
  foreach char (list_uniq(make_list("&", keys(XML_SYNTAX_CHAR_TABLE))))
  {
    replacement = "&" + XML_SYNTAX_CHAR_TABLE[char] + ";";
    str = str_replace(string:str, find:char, replace:replacement);
  }

  return str;
}

##
# Retrieve the specified xml node in the xml hierarchy.
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param path  The path to the xml node being retrieved.
#
# @remark path parameter resembles "author.country.city"
#         <author>
#           <name>Ron</name>
#           <country>Canada</country>
#             <city>vancouver</city>
#         </author>
#
# In this example, the table needs to be a XML table, returned by xmlparse() or any of the various
# xml_get_* functions, representing the "author" node. The XML object returned by this function represents the "city" node.
#
# @return a XML object representing the target node, or NULL if target node is not found.
#
##
function xml_get_target_node(table, path)
{
  local_var max_index, xml_table, nodes, match;

  if(isnull(table)) exit(1, "Missing required parameter 'table'.");

  if(isnull(path))
    exit(1, "Missing required parameter 'path'.");

  match = pregmatch(pattern:"^(\w+)(\.\w+)*$", string:path);
  if(isnull(match))
    exit(1, 'The path parameter takes the following form: NODE1.NODE2.NODEn. '+
            'The last node is the target node that is of interest.');
  
  nodes = split(path, sep:".", keep:FALSE);
  max_index = max_index(nodes);
  if(max_index > 1)
  {
    # table reprents the xml object starting from the root node, i.e. NODE1
    # so we will start from the second node (nodes[1])
    xml_table = xml_get_child(table:table, name:nodes[1]);
    if(isnull(xml_table))
    {
      dbg::log(src:SCRIPT_NAME, msg:"Error: xml_get_child() failed to parse the table, or the target node does not exist.");
      return NULL;
    }
  }

  # continuing down the hierarchy if the target node has not been reached
  # else returning a XML object representing the target node 
  if(xml_table['name'] != nodes[max_index-1])
    return xml_get_target_node(table:xml_table, path:path - nodes[0] - ".");
  else
    return xml_table;
}
