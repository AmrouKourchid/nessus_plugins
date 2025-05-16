###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# Revision: 1.5
###
include('compat_shared.inc');
include('install_func.inc');
include('spad_log_func.inc');
include('debug.inc');
include('lists.inc');
include('sets.inc');

##
# Returns an array containing the Spring Projects to detect.
#
# @return Array containing the Spring Projects to detect.
##
function get_spring_projects_array()
{
  return
  {
    'boot':                   ['Spring Boot',           'cpe:/a:pivotal_software:spring_boot'],
    'data-commons':           ['Spring Data Commons',   'cpe:/a:pivotal_software:spring_data_commons'],
    'data-jpa':               ['Spring Data JPA',       'cpe:/a:pivotal_software:spring_java_persistance_api'],
    'data-rest-core':         ['Spring Data REST',      'cpe:/a:pivotal_software:spring_data_rest'],
    'security-core':          ['Spring Security',       'cpe:/a:pivotal_software:spring_security'],
    'security-oauth2-core':   ['Spring Security OAuth', 'cpe:/a:pivotal_software:spring_security_oauth'],
    'amqp':                   ['Spring AMQP',           'cpe:/a:pivotal_software:spring_advanced_message_queuing_protocol'],
    'batch-core':             ['Spring Batch',          'cpe:/a:pivotal_software:spring_batch'],
    'integration-core':       ['Spring Integration',    'cpe:/a:pivotal_software:spring_integration'],
    'cloud-function-context': ['Spring Cloud Function', 'cpe:/a:vmware:spring_cloud_function'],
    'cloud-gateway-server':   ['Spring Cloud Gateway',  'cpe:/a:vmware:spring_cloud_gateway'],
    'cloud-config-server':    ['Spring Cloud Config',   'cpe:/a:vmware:spring_cloud_config']
  };
}

##
# Get a list of all jar files that match the Spring Projects 
# naming convention in splitable format
#
# @param [filelist:list] List of files to check for Spring Projects.
# @param [parent_archive:string]  Optional paramater.
#
# @return [list] List of Spring Projects. Empty list if none found.
##
function parse_spring_projects(filelist, parent_archive)
{
  var project;
  var projects = make_list();
  var lines = split(filelist, sep:'\n', keep:FALSE);
  var i = 0;
  foreach var line (lines) {
    project = is_spring_project_jar(filename:line);
    if(!project) continue;

    if(parent_archive) projects[i] = parent_archive;
    else projects[i] = '';

    projects[i] += '|' + project['name'] + '|' + project['version'] + '|' + project['path'];
    i++;
  }
  return projects;
}

##
# Checks if a filename matches the Spring Projects naming convention.
#
# @param [filename:string] File name to check for Spring Projects naming convention.
#
# @return If file matches, returns an array containing name, version and path. Otherwise returns false.
##
function is_spring_project_jar(filename)
{
  if('.jar' >!< filename) return FALSE;
  var pattern = "^.*spring-(.+)-(\d+(?:\.\d+)*)(?:[.-].*)?\.jar$";
  var match = pregmatch(pattern:pattern, string:filename, multiline:TRUE);
  if(!match) return FALSE;
  return {
    'path': match[0],
    'name': match[1],
    'version': match[2]
  };
}

##
# Creates the Spring Projects scratchpad table
##
function create_spring_projects_table()
{
  query_scratchpad(
    'CREATE TABLE IF NOT EXISTS spring_projects(
      name text,
      path text,
      version text,
      archive_path text,
      cpe text);'
    );
}

##
# Inserts a Spring Project into the spring_projects table
#
# @param [name:string] Spring Projects name.
# @param [path:string] Path where the Spring Projects file exists on disk.
# @param [version:string] Version of the Spring Project.
# @param [archive_path:string] Location of the Spring Project in the packaged jar.
# @param [cpe:list] CPE of the Spring Project.
##
function insert_spring_project(name, path, version, archive_path, cpe)
{
  local_var query = query_scratchpad('INSERT INTO spring_projects VALUES (?,?,?,?,?);', name, path, version, archive_path, cpe);
  dbg::detailed_log(
    src:FUNCTION_NAME,
    lvl: 3,
    msg:"ScratchPad Insert::Spring Projects::",
    msg_details:{
      "Name": {"lvl":3, "value": name},
      "Path": {"lvl":3, "value": path},
      "Version": {"lvl":3, "value": version},
      "Archive Path": {"lvl":3, "value": archive_path}});
}

##
# Queries the scratchpad for a single Spring Project name.
#
# @param [name:string] Name of Spring Project to query.
#
# @return [array] Array containing returned rows.
##
function select_spring_projects(name)
{
  return query_scratchpad('SELECT * FROM spring_projects WHERE name=?', name);
}

##
# Checks if a given Spring Project exists in the scratchpad and registers
# the install if true.
#
# @param [name:string] Name of the Spring Project to check.
#
# @return [boolean] TRUE if at least one install was registered, otherwise FALSE.
##
function register_spring_project_installs(name)
{
  var is_installed = FALSE;
  var res = select_spring_projects(name:name);
  foreach var r(res)
  {
    is_installed = TRUE;
    register_install(
        app_name: r['name'],
        version:  r['version'],
        path:     r['path'],
        cpe:      r['cpe'],
        extra:    {'Archive Path': r['archive_path']});
  }
  return is_installed;
}

##
# Registers and reports installations of a given Spring Project
#
# @param [name:string] Spring Project name.
#
# @return [boolean] TRUE if at least one install was reported, otherwise FALSE.
##
function register_and_report_spring_project_installs(name)
{
  if(register_spring_project_installs(name:name))
  {
    report_installs();
    return TRUE;
  }
  return FALSE;
}

##
# Reports all known Spring Projects from the scratchpad.
#
# @remark This function calls ``security_report_v4()``.
##
function spring_projects_security_report_v4()
{
  var report = 'Spring Projects Installed';
  var spring_projects = query_scratchpad('SELECT * FROM spring_projects');
  foreach var sp (spring_projects)
  {
    report += '\n\nProduct      : ' + sp['name'] +
              '\nVersion      : ' + sp['version'] +
              '\nPath         : ' + sp['path'] +
              '\nArchive Path : ' + sp['archive_path'];
  }
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
