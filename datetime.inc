#TRUSTED 142a641e1f98659ca7ceda34e384dc61f18139e65af22b4f05bb5a2fe7bd6f2a22a55faf641ca047cfb5bc16b2511a09c3507d85a5ecf32868c86f9a20196093d3389f5af7139f62ff4b420dc6372e60c6a74515431ebb469d72f96c1055c9d80439217938ab6c72ef5f1fac242655b41711278b06ffd1ad9036315238f0d72b8e36a79b8d4ce0cfebdf35b0693d26641f35bf0ecffde037cee569e19adc846a8a6fc6eed6511be3d24635bd228d9e5aba72da35ded498ecf596a9397cef9334cd7c0a6594a16179ed59d1439ed0c231dafd08adf8ee1fbb9049f039d766a4d06ef8e1b584bcf84b551cf41712be0972b07ee167561bf63c52c821b14d7e4ac8adcae21f1f4eb4db052141f24e454e5ca6a26eb04ba183edfcc0148e206879776670654c8f4f5dc73922d5337d0bd21d739aef19575c3db9b483b58af0e4d6cdddb92f1d4849fe75eb804e91648f4023d16fa3d11b5439e46027ac9b9253558dcd072f027bbc1bf3a390dc852dbea1621a4ece0f186ae86c6c0a81a650d8f2d2fc2a0fe30aff8c77f0c0a4b8080977942bd839ff9714c743db30ba428a13528a91fc1ac55d35f58d1050a436a43b73cd950de32f2f7ce8c66da74a836163909203409c5eb2f7e9808097bc87bdd286bc691926b1c05f54003aed9cc8421ec20c599d55da99c5ffd227b1f7e4840e9381db7892178dcdb31ff3686337864658d7
#TRUST-RSA-SHA256 4d5b97aa23a5240f87018bfc554dba2c33211ac2e7b5fbf9f1c94934d61d610a7d995255fbb56768d9bf5642220df46795c1222ff3451396501143c864dd5c793682321a5d1b1b2cc3bbd5278d2691928b37c25ebf1f65c22f69fa1765d8ccf7cb24b37a636bc4506fc939038c242001aaabe0b6f07e7e600572222054541eb801f7c691323b6a7f8da34709e4ac7eaff1bb06ae1f0eb3df499aa18eab4afa512a423a3d84253fb4d23cf7dfeb1396d20e4f1aabbd7eb09efa75c8eee7ec5c745e80d8872a9619bdd3d19ef59ebdabf696da92aa582ee02cc30f97f226115d0d4eaddac104dbf506b508c09e8b147cd09c106b4ba4cdf6f57c37d970414de5f603bd13bc20d1100e93e348296f6db79a65d6c4b95da0b366ebfd375bc8b7eac7dd35ee1112ecfa0c2f8457cc04b05217fd4507c37b768e9fde8b55efe28702e325de3684adbfba03d0b559f4d21119f2c41560767ff1d9713ddc2e019a73e418f1cd962620e929817602189e751e47991160d6e5bb9e5c9ec753551b6187e84ea17382e6dfafb7394a61b5c716613aca69f031fa335cb6d3e04934e6b3e3225f085682f65335d200a4d6daaee0fe38e78dfd13460d750bb5e679b1d36b412b1e853e8739930f385de4b76b54cd1e12a2eef7f4b67319c29c7cc53fc1e526113136bbe2c7707d877cd06d3a8c9401dcd60c2673cc9e1cdc8d9e3188895150c434
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# datetime.inc
# Revision: 1.20
#

include("compat_shared.inc");

global_var _months_num, _months_str, _weekday_num, _months_abrev;

_months_num = make_list(
  "January", "February", "March", "April", "May", "June", "July",
  "August", "September", "October", "November", "December"
);

_months_str = make_array(
  "January", 0,
  "February", 1,
  "March", 2,
  "April", 3,
  "May", 4,
  "June", 5,
  "July", 6,
  "August", 7,
  "September", 8,
  "October", 9,
  "November", 10,
  "December", 11
);

_months_abrev = make_array(
  "Jan", "January",
  "Feb", "February",
  "Mar", "March",
  "Apr", "April",
  "May", "May",
  "Jun", "June",
  "Jul", "July",
  "Aug", "August",
  "Sep", "September",
  "Oct", "October",
  "Nov", "November",
  "Dec", "December"
);

_weekday_num = make_list(
  "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
  "Saturday"
);

### FILETIME Constants ###
global_var FILETIME_TICK, FILETIME_BIAS;
FILETIME_TICK = 10000000;
FILETIME_BIAS = "11644473600";

##
# Returns the name associated with a month given its number.
#
# @anonparam num The number representing the month.
#
# @param base The base at which the months are numbered, default is 0.
# @param short Whether to return the three-letter short version of the
#              month name, false by default.
#
# @return The name associated with the specified number.
##
function month_name_by_num(base, short)
{
  local_var name, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;
  if (isnull(short))
    short = FALSE;

  num = _FCT_ANON_ARGS[0];

  # Find the specified month.
  name = _months_num[num - base];
  if (isnull(name))
    return NULL;

  # Shorten if requested.
  if (short)
    name = substr(name, 0, 2);

  return name;
}


##
# Returns a UNIX timestamp from the date format used in Nessus logs
# such a nessusd.dump and nessusd.messages
#
# @param timestr time string formatted as "DayOfWeekStr MonthStr DayOfMonth HH:MM:SS Year"
#
# @return The unixtime associated with the formatted date.
##
function logtime_to_unixtime(timestr)
{
  var parts, month, day, time, year, hours, minutes, seconds;
  if(isnull(timestr)) return NULL;

  timestr = str_replace(string:timestr, find:'  ', replace:' ');
  parts = split(timestr, sep:' ', keep:FALSE);
  if(max_index(parts) != 5) return NULL;

  month = parts[1];
  month = _months_abrev[month];
  month = month_num_by_name(month, base:1);
  day = int(parts[2]);
  time = parts[3];
  year = int(parts[4]);
  parts = split(time, sep:':', keep:FALSE);
  if(max_index(parts) != 3) return NULL;
  hours = int(parts[0]);
  minutes = int(parts[1]);
  seconds = int(parts[2]);
  return mktime(year:year, mon:month, mday:day, hour:hours, min:minutes, sec:seconds);
}

##
# Returns the number associated with a month given its name.
#
# @anonparam name The full, capitalized name of the month, in English.
#
# @param base The base at which the months are numbered, default is 0.
#
# @return The number associated with the named month.
##
function month_num_by_name(base)
{
  local_var month, name;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;

  name = _FCT_ANON_ARGS[0];

  # Try and find a month that matches the name or abbreviation given.
  foreach month (keys(_months_str))
  {
    if (month =~ "^" + name)
      return base + _months_str[month];
  }

  return NULL;
}

##
# Compare two dates.
#
# @anonparam then A date in "M D H:M:S Y TZ" format.
#
# @param base_date Optional base unix timestamp to compare against. Default is now.
#
# @return Returns an integer indicating the difference between the
#         dates.
##
function date_cmp(base_date)
{
  local_var now, then, time;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  then = _FCT_ANON_ARGS[0];

  then = split(then, sep:" ", keep:FALSE);
  now = localtime(utc:1);
  if(!isnull(base_date)) now = localtime(base_date, utc:1);
  # If the year is earlier than the year this function was updated,
  # then the clock is wrong.
  if (now["year"] < 2012)
    return NULL;

  if (then[3] != now["year"])
    return int(now["year"]) - int(then[3]);

  if (month_num_by_name(then[0], base:1) != now["mon"])
    return int(now["mon"]) - month_num_by_name(then[0], base:1);

  if (int(then[1]) != now["mday"])
    return int(now["mday"]) - int(then[1]);

  time = split(then[2], sep:":", keep:FALSE);

  if (int(time[0]) != now["hour"])
    return int(now["hour"]) - int(time[0]);

  if (int(time[1]) != now["min"])
    return int(now["min"]) - int(time[1]);

  if (int(time[2]) != now["sec"])
    return int(now["sec"]) - int(time[2]);

  return 0;
}

##
# Returns the name associated with a day of the week given its number.
#
# @anonparam num The number representing the day of the week.
#
# @param base The base at which the days of the week are numbered,
#             default is 0.
# @param short Whether to return the three-letter short version of the
#              day of the week's name, false by default.
#
# @return The name associated with the specified number.
##
function weekday_name_by_num(base, short)
{
  local_var name, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(base))
    base = 0;
  if (isnull(short))
    short = FALSE;

  num = _FCT_ANON_ARGS[0];

  # Find the specified weekday.
  name = _weekday_num[num - base];
  if (isnull(name))
    return NULL;

  # Shorten if requested.
  if (short)
    name = substr(name, 0, 2);

  return name;
}

##
# Prefixes an integer as necessary to be a certain size.
#
# @anonparam num The number to be formatted.
#
# @param prefix The string to prefix the number with, zero by default.
# @param size The minimum length of the string, two by default.
#
# @return The number as a string, prefixed if necessary.
##
function prefix_num(prefix, size)
{
  local_var len, num;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
    return NULL;

  # Set defaults.
  if (isnull(prefix))
    prefix = 0;

  if (isnull(size))
    size = 2;

  num = string(_FCT_ANON_ARGS[0]);
  prefix = string(prefix);

  len = strlen(num);
  if (len < size)
    num = crap(data:prefix, length:size - len) + num;

  return num;
}

##
# Formats a Unix epoch timestamp like strftime(3).
#
# %A is replaced by national representation of the full weekday name.
#
# %a is replaced by national representation of the abbreviated weekday
#    name.
#
# %B is replaced by national representation of the full month name.
#
# %b is replaced by national representation of the abbreviated month
#    name.
#
# %d is replaced by the day of the month as a decimal number (01-31).
#
# %e is replaced by the day of the month as a decimal number (1-31);
#    single digits are preceded by a blank.
#
# %F is equivalent to "%Y-%m-%d".
#
# %H is replaced by the hour (24-hour clock) as a decimal number
#    (00-23).
#
# %I is replaced by the hour (12-hour clock) as a decimal number
#    (01-12).
#
# %k is replaced by the hour (24-hour clock) as a decimal number
#    (0-23); single digits are preceded by a blank.
#
# %l is replaced by the hour (12-hour clock) as a decimal number
#    (1-12); single digits are preceded by a blank.
#
# %M is replaced by the minute as a decimal number (00-59).
#
# %m is replaced by the month as a decimal number (01-12).
#
# %N is equivalent to "%b. %e, %Y at %T GMT"; this is a Nessus
#    extension, not the normal behavior of strftime(3).
#
# %S is replaced by the second as a decimal number (00-60).
#
# %T is equivalent to "%H:%M:%S".
#
# %Y is replaced by the year with century as a decimal number.
#
# %y is replaced by the year without century as a decimal number
#    (00-99).
#
# @anonparam fmt The format string for the output, "%N" by default.
# @anonparam when Either an array (in [builtin#localtime] format), or
#                 a 32-bit epoch timestamp. The current time is used
#                 by default.
#
# @return The formatted version of the time and date.
##
function strftime()
{
  local_var field, fmt, i, len, when;

  # Sanity check parameters.
  len = max_index(_FCT_ANON_ARGS);
  if (len == 0)
  {
    fmt = "%N";
    when = localtime(utc:TRUE);
  }
  else if (len == 1)
  {
    fmt = "%N";
    when = _FCT_ANON_ARGS[0];
  }
  else if (len == 2)
  {
    fmt = _FCT_ANON_ARGS[0];
    when = _FCT_ANON_ARGS[1];
  }
  else
  {
    return NULL;
  }

  if (typeof(when) == "int")
  {
    if ( when < 0 || when >= 2147483647 ) return NULL;
    else when = localtime(when, utc:TRUE);
  }

  # Add in a key that represents the hour on a twelve-hour clock.
  if (when["hour"] == 0)
    when["12hr"] = 12;
  else if (when["hour"] > 12)
    when["12hr"] = when["hour"] - 12;
  else
    when["12hr"] = when["hour"];

  while (TRUE)
  {
    # Find a format specifier.
    field = pregmatch(string:fmt, pattern:"(%[a-zA-Z])");
    if (isnull(field))
      break;
    field = field[1];

    if (field == "%A")
    {
      fmt = str_replace(string:fmt, find:field, replace:weekday_name_by_num(when["wday"], short:FALSE));
    }
    else if (field == "%a")
    {
      fmt = str_replace(string:fmt, find:field, replace:weekday_name_by_num(when["wday"], short:TRUE));
    }
    else if (field == "%B")
    {
      fmt = str_replace(string:fmt, find:field, replace:month_name_by_num(when["mon"], base:1, short:FALSE));
    }
    else if (field == "%b")
    {
      fmt = str_replace(string:fmt, find:field, replace:month_name_by_num(when["mon"], base:1, short:TRUE));
    }
    else if (field == "%d")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mday"]));
    }
    else if (field == "%e")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mday"], prefix:" "));
    }
    else if (field == "%F")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%Y-%m-%d");
    }
    else if (field == "%H")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["hour"]));
    }
    else if (field == "%I")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["12hr"]));
    }
    else if (field == "%k")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["hour"], prefix:" "));
    }
    else if (field == "%l")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["12hr"], prefix:" "));
    }
    else if (field == "%M")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["min"]));
    }
    else if (field == "%m")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["mon"]));
    }
    else if (field == "%N")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%b. %e, %Y at %T GMT");
    }
    else if (field == "%S")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["sec"]));
    }
    else if (field == "%T")
    {
      fmt = str_replace(string:fmt, find:field, replace:"%H:%M:%S");
    }
    else if (field == "%Y")
    {
      fmt = str_replace(string:fmt, find:field, replace:when["year"]);
    }
    else if (field == "%y")
    {
      fmt = str_replace(string:fmt, find:field, replace:prefix_num(when["year"] % 100));
    }
    else
    {
      # Remove unrecognized specifiers to prevent infinite loops.
      fmt = str_replace(string:fmt, find:field, replace:"");
    }
  }

  return fmt;
}

##
# Converts a Windows FILETIME value into Unix Epoch time.
#
# @param  string filetime in hex representation
#
# @return int unixtime as integer
##
function filetime_to_unixtime(filetime)
{
  local_var output;

  if (isnull(filetime)) filetime = _FCT_ANON_ARGS[0];
  if (isnull(filetime))
  {
    err_print("filetime_to_unixtime(): missing required arg 'filetime'");
    return -1;
  }

  # Convert input to raw data.
  output = bn_hex2raw(filetime);
  # Divide filetime by FILETIME_TICK (100 ns unless something changed)
  output = bn_div(output, bn_dec2raw(FILETIME_TICK));
  # Subtract FILETIME_BIAS since Windows FILETIME starts in 1601.
  output = bn_sub(output, bn_dec2raw(FILETIME_BIAS));
  # Convert to decimal representation.
  output = bn_raw2dec(output);

  # Return as 32-bit integer.
  return int(output);
}


##
#  Converts calendar time to unix epoch time.  This function deliberately does not use the
#  nessus engine's mktime function because that function caused a denial of service condition
#  in a customer's scanner.  Adapted from: http://howardhinnant.github.io/date_algorithms.html
#
#  @param <year:int> The year
#  @param <mon:int>  Month of the year starting at 1 for Jan
#  @param <day:int>  Day of the month
#  @param <hour:int> Hour 0-23
#  @param <min:int>  Minutes 0-59
#  @param <sec:int>  Seconnds 0-59
#  @return Returns a big number representing the number of seconds since Jan 1, 1970
##
function calendar_to_bn_epoch(year, mon, day, hour, min, sec)
{
   local_var epoch_bn;

   #Make it bulletproof
   if(isnull(year) || typeof(year) != 'int' || year < 0) year = 0;
   if(isnull(mon) || typeof(mon) != 'int' || mon <= 0) mon = 1;
   if(isnull(day) || typeof(day) != 'int' || day <= 0) day= 1;
   if(isnull(hour) || typeof(hour) != 'int' || hour < 0) hour= 0;
   if(isnull(min) || typeof(min) != 'int' || min < 0) min= 0;
   if(isnull(sec) || typeof(sec) != 'int' || sec < 0) sec= 0;

   #Normalize the inputs - this allows date/time differences to be calculated
   if(sec >= 60)
   {
     min += sec / 60;
     sec = sec % 60;
   }

   if(min >= 60)
   {
     hour += min / 60;
     min = min % 60;
   }

   if(hour >= 24)
   {
     day += hour / 24;
     hour = hour % 24;
   }

   if(mon >= 12)
   {
     year += mon / 12;
     mon = mon % 12;
   }

   var days = 0;
   if(mon <= 2)
     year--;
   if(year < 0)
     year = year - 399;

   var era = year/400;
   var yoe = year - era * 400;

   var m = 9;
   if(mon > 2)
     m = -3;
   var doy = (153*(mon + m) + 2)/5 + day - 1;

   var doe = yoe * 365 + yoe/4 - yoe/100 + doy;
   doe = era * 146097 + int(doe) - 719468;

   # Days
   epoch_bn = bn_dec2raw(doe);

   # To hours
   epoch_bn = bn_mul(epoch_bn, bn_dec2raw(24));
   epoch_bn = bn_add(epoch_bn, bn_dec2raw(hour));

   # To minutes
   epoch_bn = bn_mul(epoch_bn, bn_dec2raw(60));
   epoch_bn = bn_add(epoch_bn, bn_dec2raw(min));

   # To seconds
   epoch_bn = bn_mul(epoch_bn, bn_dec2raw(60));
   epoch_bn = bn_add(epoch_bn, bn_dec2raw(sec));

   return epoch_bn;
}


##
# Converts an ASN1 UTCTIME value into Unix Epoch time.
#
# @param  string UTCTIME in UTCTIME representation
#
# @return int unixtime as integer
##
function utctime_to_unixtime(utctime)
{
  local_var output, year, month, day, hour, minute, second;

  if (isnull(utctime)) utctime = _FCT_ANON_ARGS[0];
  if (isnull(utctime))
  {
    err_print("utctime_to_unixtime(): missing required arg 'utctime'");
    return -1;
  }

  # YYMMDDhhmm[ss]Z
  # 150928230106Z

  year = int(substr(utctime, 0, 1));
  if (year > 50)
    year += 1900;
  else
    year += 2000;

  month = int(substr(utctime, 2, 3));
  day = int(substr(utctime, 4, 5));
  hour = int(substr(utctime, 6, 7));
  minute = int(substr(utctime, 8, 9));
  second = int(substr(utctime, 10, 11));

  output = mktime(
    year:year,
    mon:month,
    mday:day,
    hour:hour,
    min:minute,
    sec:second
  );

  return output;
}

##
# Reports the time difference of local time zone compared to UTC 
# 
# @param [seconds:int] Offset between local time and UTC time in seconds
# 
# @return [string] (UTC [+/-]hh:mm)
# 
# @remark
# The return value is specifically formatted for use with scan_info.nasl.
# Minutes are always expected to be '00' or '30' (30 minute increments only)
# Example return values:
# ```
# (UTC +01:00)
# (UTC +01:30)
# (UTC +11:00)
# (UTC +11:30)
# (UTC -04:00)
# (UTC -11:30)
# ```
## 
function report_utc_offset (seconds)
{
  var half_hours, hours, mins, time, plus_minus, zero, report;
  zero = '';
  
  if (seconds < 0)
  {
    plus_minus = '-';
    seconds = seconds * -1;
  }
  else
  {
    plus_minus = '+';
  }

  hours = seconds / 3600;
  if (hours < 9)
  {
    zero = '0';
  }

  half_hours = seconds / 1800;
  
  mins = half_hours % 2;
  if (mins == 0)
  {
    mins = '00';
  }
  else 
    mins = '30';

  report = strcat('(UTC ', plus_minus, zero, hours, ':', mins, ')');

  return report;
}

namespace datetime
{
  ##
  # Return difference of two times from gettimeofday()
  #
  # @param [begin:string] begin time returned from gettimeofday()
  # @param [end:string] end time returned from gettimeofday()
  #
  # @remark gettimeofday() example: 1543599842.084270
  #
  # @return [string] time difference in the format seconds.microseconds
  ##
  function timeofday_diff(begin, end)
  {
    var integer_digits, fractional_digits;

    if (isnull(begin) || isnull(end))
    {
      err_print(FUNCTION_NAME + "(): missing argument 'begin' or 'end'");
      return -1;
    }

    begin = split(begin, sep:'.', keep:FALSE);
    end   = split(end, sep:'.', keep:FALSE);

    integer_digits    = int(end[0]) - int(begin[0]);
    fractional_digits = int(end[1]) - int(begin[1]);

    # Convert negative to positive
    if (fractional_digits < 0)
    {
      fractional_digits += 1000000;
      integer_digits--;
    }

    # Prefix fractional digits with zeroes (e.g. 084270, 000372)
    fractional_digits = crap(data:'0', length:6 - strlen(string(fractional_digits))) + fractional_digits;

    return integer_digits + "." + fractional_digits;
  }
  
  ##
  # Converts a human readable date to a unix timestamp.
  #
  # @param [datestr:string] Human readable date string.
  # @param [format:string] Format of the incoming string (e.g. yyyy/mm/dd)
  #
  # @return Unix timestamp.
  ##
  function to_unixtime(datestr, format)
  {
    var parts, mon;

    if(format =~ "yyyy[\/\-]mm[\/\-]dd") {
      parts = pregmatch(string:datestr, pattern:"^(\d{4})[\/\-](\d\d)[\/\-](\d\d)$");
      if(empty_or_null(parts)) return NULL;
      return mktime(year:parts[1], mon:parts[2], mday:parts[3]);
    };
    
    if(format =~ "mm[\/\-]dd[\/\-]yyyy") {
      parts = pregmatch(string:datestr, pattern:"^(\d\d)[\/\-](\d\d)[\/\-](\d{4})$");
      if(empty_or_null(parts)) return NULL;
      return mktime(year:parts[3], mon:parts[1], mday:parts[2]);
    };
    
    if(format == "month day, year") {
      parts = pregmatch(string:datestr, pattern:"^([A-Za-z]{3,9}) (\d{1,2}), *(\d{4})$");
      if(empty_or_null(parts)) return NULL;
      mon = month_num_by_name(base:1, parts[1]);
      if(!mon) return NULL;
      return mktime(year:parts[3], mon:mon, mday:parts[2]);
    };

    return NULL;
  }
  
  ##
  # Converts a human readable date string to a different human readable format.
  #
  # @param [datestr:string] Human readable date string.
  # @param [from:string] Format of the incoming date string (e.g. yyyy/mm/dd)
  # @param [to:string] Format of the returned date string (e.g. month dd, yyyy)
  #
  # @return Converted human readable date string.
  function convert(datestr, from, to)
  {
    var unixtime = to_unixtime(datestr:datestr, format:from);
    if(!unixtime) return NULL;

    if(to == "yyyy/mm/dd") return strftime("%Y/%m/%d", unixtime);
    if(to == "yyyy-mm-dd") return strftime("%Y-%m-%d", unixtime);
    if(to == "yyyy/dd/mm") return strftime("%Y/%d/%m", unixtime);
    if(to == "yyyy-dd-mm") return strftime("%Y-%d-%m", unixtime);
    if(to == "month day, year") return strftime("%B %e, %Y", unixtime);

    return NULL;
  }

  ##
  # Converts an http date to a unix timestamp.
  #
  # @param [http_date:string] HTTP-date, eg IMF-fixdate from RFC7231
  #
  # @return Unix timestamp, or NULL if we can't parse it
  #
  # @remark example http date: Mon, 05-Dec-2022 04:18:30 GMT
  # @remark example http date: Sat, 03 Dec 2022 04:39:29 GMT
  ##
  function http_date_to_unixtime(http_date)
  {
    var day, month, year, hour, minute, second;
    var parts, output;

    parts = pregmatch(string:http_date, pattern:"^(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat), ([0-9]{2})[ -](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[ -]([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT$");

    if (isnull(parts))
      return NULL;

    day = int(parts[1]);
    month = parts[2];
    year = int(parts[3]);
    hour = int(parts[4]);
    minute = int(parts[5]);
    second = int(parts[6]);

    output = mktime_tz(
      year:year,
      mon:_months_str[_months_abrev[month]]+1,
      mday:day,
      hour:hour,
      min:minute,
      sec:second,
      tz:'GMT'
    );

    return output;
  }

}
