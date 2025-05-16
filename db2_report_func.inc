###
# (C) Tenable Network Security, Inc.
#
# Revision: 1.4
###

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");

##
# Build the report for a DB2 install
#
# @param [port:int] The port on which the install was found
# @param [severity:string] The report severity
# @param [platform_name:string] The platform name on which DB2 was found
# @param [fixed_level:string] The fixed level of the product
# @param [installed_level:string] The detected installed level
# @param [instance:string] The DB2 instance
# @param [product:string] The product's name
# @param [node:string] The DB2 node
# @param [path:string] The product's install path
# @param [special_fix:string] The fixed special version
# @param [special_installed:string] The detected special version
# @param [installed_version:string] The detected installed version
# @param [fixed_version:string] The fixed version of the product
# @param [info:string] Extra information to add to the report
#
##
function report_db2(port, severity, platform_name, fixed_level, installed_level, instance, product, node, path, special_fix, special_installed, installed_version, fixed_version, info)
{
  local_var report = '';
  local_var path_encode;
  var path_no_slash;

  if(path)
  {
    path_encode = base64(str:path);
    path_encode = str_replace(string:path_encode, find:'=', replace:'$');
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "Encoded the given path",
      msg_details: {
        "path_encode": {"lvl": 3, "value": path_encode}});
    # if path starts with /, remove the / so that // doesn't appear in get_kb_item() (engine warns on // in kb item)
    # Unless the path is just /, in which case leave it since the warning is internal only
    path_no_slash = path;
    if (path_no_slash[0] == '/' && path != '/')
       path_no_slash -= '/';
  }
  if(!product && port)
    product = get_kb_item("DB2/"+port+"/Product");
  if(!product && path_no_slash)
    product = get_kb_item("DB2/"+path_no_slash+"/Product");
  if(!product && path_encode)
    product = get_kb_item("DB2/"+path_encode+"/Product");
  if(!node && port)
    node = get_kb_item("DB2/"+port+"/Node");
  if(!node && path_no_slash)
    node = get_kb_item("DB2/"+path_no_slash+"/Node");
  if(!node && path_encode)
    node = get_kb_item("DB2/"+path_encode+"/Node");
  if(!path && port)
    path = get_kb_item("DB2/"+port+"/Path");
  if(path_no_slash && !instance)
    instance = get_kb_item("DB2/"+path_no_slash+"/Instances");
  else if(!path && !instance && port)
    instance = get_kb_item("DB2/"+port+"/Instances");
  if(path_encode && !instance)
    instance = get_kb_item("DB2/"+path_encode+"/Instances");
  if(empty_or_null(port))
    port = 0;

  if(platform_name)
    report += '\n  Platform                : ' + platform_name;
  if(installed_level)
    report += '\n  Installed level         : ' + installed_level;
  if(installed_version)
    report += '\n  Installed version       : ' + installed_version;
  if(path)
    report += '\n  Path                    : ' + path; # sanitization needed here
  if(instance)
    report += '\n  Instance                : ' + instance;
  if(product)
    report += '\n  Product                 : ' + product;
  if(node)
    report += '\n  Node                    : ' + node;
  if(special_installed)
    report += '\n  Installed Special Build : ' + special_installed;
  if(special_fix)
    report += '\n  Fixed Special Build     : ' + special_fix;
  if(fixed_level)
    report += '\n  Fixed level             : ' + fixed_level;
  if(fixed_version)
    report += '\n  Fixed version           : ' + fixed_version;
  if(info)
    report += '\n' + info;

  report += '\n';

  security_report_v4(port:port, severity:severity, extra:report);
}
