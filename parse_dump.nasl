#TRUSTED a9842bfe1b9671f560363f320b34fb1b1d7980b53f1edf057159963f8beb3f3cb90d57636669ca2c949658e88f34e81627c623993d42db1b46e6728d224eebbf5164f6f15f7465664e69da1e25ba9a3ba953aa340aae6ca379d5f28f40285cc2ca5e990fef23103897fef9cd7d5fdc940f471d0eb0703d2585319e6ee433159fb067e7b819483bf2d838694e78f8adcfc5ef948280602aa50ce191ded44cabfd03a8d1e48f90908f677f7aab9dac34048740ff8a12d822128c5c6afc6d9d5b65613730a4b1b11b03fa091a943616fb843b85019972d98526be2317655b316d16e93cb756da93ea8e5f97020df7419095e9e977db52d44a01fc4a1e686d1072616757fb29256afc7c64dcb018bbb0eda4fc2da20bc7549d992723deda357e23fce22b75c17f4734d023e6aeff55cd0f69a5a24e1b8071bf3dddc1acbb601d015b9312be675ea01a890e67caf59141c16c59cd9ba7b026fdfdf30d28340296222d61569cbc5383b251cd4a8c9050625829aa63629b5749b2a38c07680f5620ebc84b22fa85be7703316c3f6d0fa2f4460807657883191cf0b8e7ba1341379a4cb5d56897b4d649c3a9cd0df9baffe07203603ef50fa2373626c1714dcdf1bc256bd7539f76aacece2f0f64a355c476b6af9883f46dec97d89c053f4d050178e9eaa100367729f1619a942b331ec12dce6fd29169ad16b1b3c794f6539e6f43bacb
#TRUST-RSA-SHA256 97da574b066ee6970db67ec3b416df0c9e28ef1148429bd07e744ca2ac6e1b0d480902a36d802550c2cb51cd3a90f5370d8775fe703e2bb214e88d9de8df9e00593efe1111759c3ff0a578a01344ceb71a66e7b73fa48cc49c53b678d400b25c71145cf6d2e4597c4f94d41ea7352b36575a0082fff069e829e65e4735fb847f4b24b87fe3c8848945835b679bfdc32d4b5c69b20f637762c6fd47f0677aeb7721342143f85f75dbf7d1f15b72612dfb008989dc0e6aeda5aae6a68d9492149f4ed7f5096f6e801222e0b151ad1ca42bc71525bd56c2a3c1412d2ee6e96a7b100065bc2be55d72adf392fe670ed9b6eed6c03f81fd38c23ae162e2d098a937c682d999a5a70410b1c9bc212b881210a02ef3acc2c1532fd3a856301f94f268164ce37d91eb492f2f9e2d5140ba03c4568df72de2eb72f044c3b474d73cea37bcf4a9d4ee828894ca218795791f338a725c1431b5fe56e896d9a0b0ed9f832163cd1a05a59e0db58b676ac5033f5bf9df0d72e7f6c5b10e41a45588486ffaf98e346126edb669e8948ac1843b034a723fdb6442dff80e05cd1eae5d6802b405dc3eaa987183f1a0f6a3e4d83ed37d6a7af46201adbdf246f9d5eacfc4120f3844c1bce1911086b113c7576f1a6a3ae5a5380b3905ca7281700c75d2ee7960ca43c3b6eec70f84668d7b5166d9a64747b1f60e2e81cfe67be89ca4cb66f17ea5df
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117530);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_name(english: "Errors in nessusd.dump");
  script_summary(english:"Parses out errors occuring in the nessusd.dump file.");
  script_set_attribute(attribute:"synopsis", value:
"This plugin parses information from the nessusd.dump log
file and reports on errors.");
  script_set_attribute(attribute:"description", value:
"This plugin parses information from the nessusd.dump log
file and reports on errors.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");

  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_timeout(5*60);
  script_require_keys("global_settings/enable_plugin_debugging");
  script_exclude_keys("Host/msp_scanner");

  exit(0);
}

include("datetime.inc");
include("global_settings.inc");
include("nessusd_logs.inc");
include("nessusd_product_info.inc");

get_kb_item_or_exit('global_settings/enable_plugin_debugging');

# Suppress plugin on T.io
if (get_kb_item("Host/msp_scanner"))
{
  exit(0, "This plugin does not run on T.io scanner systems.");
}

# This is here to prevent license issues on SC and TIO.
# Because this plugin could count against SC/TIO license we makes
# sure that ports have been detected on the target client which
# tells us the target is a valid asset
tcp_ports = get_kb_list("Ports/tcp/*");
udp_ports = get_kb_list("Ports/udp/*");
if (!nessusd_is_agent() && isnull(tcp_ports) && isnull(udp_ports))
{
  exit(0, "No ports available, port detection prevents reporting on targets with no host-based scan results.");
}

host_dict = make_array();

MAX_ATTACHMENT_SIZE = 1024*1024*35;

nessus_dir = nessus_get_dir(N_LOG_DIR);
dirslash = '/';
if(platform() == 'WINDOWS')
  dirslash = "\";

dumpfile = nessus_dir + dirslash + 'nessusd.dump';
messages = nessus_dir + dirslash + 'nessusd.messages';

start = '';
scan_uuid = get_preference("report_task_id");
if(isnull(scan_uuid))
  exit(0, "This plugin is not for use with command line scans.");

if(isnull(file_stat(messages)))
    exit(1, "The nessus messages log at: " + messages + ", does not exist.");

pid_tid_regex = NESSUSD_LOG_TID_PID_REGEX;
if(is_nessusd_pre_7_2())
{
  pid_tid_regex = NESSUSD_LOG_PRE_7_2_TID_PID_REGEX;
}

fd_message = file_open(name:messages, mode:'r');

# Loops through the nessusd.messages files storing target hosts by pid/tid pairs
# and collecting scan start times.  The scan id is used to identify the current
# and the current scan start time is stored to help filter dump messages.
last_buf = '';
while ( message_contents = file_read(fp:fd_message, length:1024) )
{
  message_contents = message_contents;

  messages = split(last_buf + message_contents);
  message_count = max_index(messages);

  last_buf = '';
  # We don't save the last line segment or it won't get processed and only have to
  # bring over the last segment as a line fragment if the part of the stream we
  # read is not line terminated.
  if(strlen(message_contents) == 1024 && message_contents[strlen(message_contents)-1] != '\n')
  {
    message_count --;
    last_buf = messages[message_count];
  }

  for(i = 0; i < message_count; i++)
  {
    message = messages[i];
    if( scan_uuid >< message)
    {
      if("starts a new scan" >< message || "starting with Target" >< message)
      {
        start_match = pregmatch(pattern:NESSUSD_LOG_TIME_REGEX, string:message);
        if(start_match && start_match[1])
          start = start_match[1];
      }

      if(start)
      {
        pid_tid_match = pregmatch(pattern:pid_tid_regex, string:message);

        if(pid_tid_match && pid_tid_match[1] && pid_tid_match[2])
          host_dict[pid_tid_match[1]] = pid_tid_match[2];
      }
    }
  }
}
file_close(fd_message);
start_unixtime = logtime_to_unixtime(timestr:start);
if(isnull(start_unixtime))
  exit(0, "No valid start time for this scan was found in the messages log." );

if(isnull(file_stat(dumpfile)))
    exit(1, "The nessus dump log at: " + messages + ", does not exist.");

fd_dump = file_open(name:dumpfile, mode:'r');
dumps = '';
dump_size = 0;
dumping_plugins = make_array();
collect = FALSE;

# Loops through the nessusd.dump log and starts collecting messages
# at the start of the current scan as determined by the prior loop
# through nessusd.messages.  Dump messages are mapped by tid/pid to their
# target host and are filtered by scan id.
last_buf = '';
while( dump_contents = file_read(fp:fd_dump, length:1024) )
{
  dump_contents = dump_contents;

  lines = split(last_buf + dump_contents);
  dump_count = max_index(lines);

  last_buf = '';
  # We don't save the last line segment or it won't get processed and only have to
  # bring over the last segment as a line fragment if the part of the stream we
  # read is not line terminated.
  if(strlen(dump_contents) == 1024 && dump_contents[strlen(dump_contents)-1] != '\n')
  {
    dump_count --;
    last_buf = lines[dump_count];
  }

  for(i = 0; i < dump_count; i++)
  {
    line = lines[i];

    if(!collect)
    {
      datematch = pregmatch(pattern:NESSUSD_LOG_TIME_REGEX, string:line);
      if(datematch && datematch[1])
        date = datematch[1];
      else
        continue;

      time = logtime_to_unixtime(timestr:date);
      if( !isnull(time) && time >= start_unixtime )
        collect = TRUE;
    }

    if(collect)
    {
      dump_has_scan_id = FALSE;
      plugin_match = pregmatch(pattern:NESSUSD_DUMP_LOG_REGEX, string:line);
      if(plugin_match && plugin_match[1] && plugin_match[2])
      {
        scan_id_match = pregmatch(pattern:"\[scan=([a-z0-9-]+)\]", string:line);
        if(scan_id_match && scan_id_match[1])
          dump_has_scan_id = TRUE;

        host = host_dict[plugin_match[1]];
        if(!host)
        {
          host = pregmatch(pattern:"\[target=([0-9.]+)\]", string:line);
            if(host && host[1])
              host = host[1];
            else
              continue;
        }

        #Prior to Nessus 7.2, nessusd.dump log entries did not have enough information to separate
        #messages from concurrent scans against the same host.
        if(host == get_host_ip() && (!dump_has_scan_id || scan_id_match[1] == scan_uuid))
        {
          plugin = plugin_match[2];
          if(dumping_plugins[plugin])
            dumping_plugins[plugin]++;
          else
            dumping_plugins[plugin] = 1;

          if("Recursive foreach" >< line)
            report_xml_tag(tag:"recursive-foreach", value:plugin);
          if("Bad enumerator" >< line)
            report_xml_tag(tag:"bad-enumerator", value:plugin);

          dump_size += strlen(line);
          if(dump_size <= MAX_ATTACHMENT_SIZE)
              dumps += line;

          if(i + 1 < dump_count &&  "call stack:" >< lines[i + 1])
          {
            do
            {
              i++;
              line = lines[i];
              dump_size += strlen(line);
              if(dump_size <= MAX_ATTACHMENT_SIZE)
                  dumps += line;
            } while(i + 1 < dump_count &&
                    (preg(pattern:"^\s*-+\s*$", string:lines[i + 1]) ||
                     preg(pattern:"^\s*\[[0-9a-fA-F]+:[0-9a-fA-F]+\]",string:lines[i + 1])));
          }
        }
      }
    }
  }
}
file_close(fd_dump);

report = '';
if(max_index(keys(dumping_plugins)))
{
  report = 'The nessusd.dump log file contained errors from the following plugins:\n\n';
  foreach plugin (keys(dumping_plugins))
  {
    plural = '';
    num = dumping_plugins[plugin];
    if(num > 1)
      plural = 's';
    report += '  - '+plugin+' reported '+num+ ' error'+plural+'\n';
  }

  if(dump_size > MAX_ATTACHMENT_SIZE)
      report += '\nnote: The dump file has been truncated to 35MB due to its size.';

  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text";
  attachments[0]["name"] = "nessusd.dump";
  attachments[0]["value"] = dumps;

  security_report_with_attachments(
          port        : 0,
          level       : 0,
          extra       : report,
          attachments : attachments
          );
}
