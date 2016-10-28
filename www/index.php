<? include 'common.php'; ?>
<?
  $_SESSION['refresh'] = true;
  /* firewall variables. */
  set_preset_timespan ("firewall");
  if (!isset ($_SESSION ['firewall_nat']))
    $_SESSION ['firewall_nat'] = "off";
  if (!isset ($_SESSION ['firewall_ip_src']))
    $_SESSION ['firewall_ip_src'] = "0.0.0.0";
  if (!isset ($_SESSION ['firewall_ip_dst']))
    $_SESSION ['firewall_ip_dst'] = "0.0.0.0";
  if (!isset ($_SESSION ['firewall_ip_proto']))
    $_SESSION ['firewall_ip_proto'] = IPPROTO_ANY;
  if (!isset ($_SESSION ['firewall_spt']))
    $_SESSION ['firewall_spt'] = "0";
  if (!isset ($_SESSION ['firewall_dpt']))
    $_SESSION ['firewall_dpt'] = "0";
  if (!isset ($_SESSION ['firewall_my_delta']))
    $_SESSION ['firewall_my_delta'] = 60;
  /* dns variables. */
  set_preset_timespan ("dns");
  if (!isset ($_SESSION ['dns_nat']))
    $_SESSION ['dns_nat'] = "off";
  if (!isset ($_SESSION ['dns_client']))
    $_SESSION ['dns_client'] = "0.0.0.0";
  if (!isset ($_SESSION ['dns_query']))
    $_SESSION ['dns_query'] = "";
  if (!isset ($_SESSION ['dns_my_delta']))
    $_SESSION ['dns_my_delta'] = 60;
?>

<html>

<head>
  <title><? echo "..:: ".$program_name." ::.. - Query Page"; ?></title>
  <link href="css/css.css" type="text/css" rel="stylesheet" />
  <link href="css/style.css" type="text/css" rel="stylesheet" />
  <link href="css/main.css" type="text/css" rel="stylesheet" />
  <script type="text/javascript" src="jscalendar/calendar.js"></script>
  <script type="text/javascript" src="jscalendar/lang/calendar-en.js"></script>
  <script type="text/javascript" src="jscalendar/calendar-setup.js"></script>
  <script language="javascript" src="common.js"></script>
  <script type="text/javascript">
    // Initialize the calendar
    calendar = null;

    // This function displays the calendar associated to the input field 'id'
    function
    showCalendar (id)
    {
      var el = document.getElementById (id);
      if (calendar != null)
        {
          // we already have some calendar created
          calendar.hide ();         // so we hide it first.
        }
      else
        {
          // first-time call, create the calendar.
          var cal = new Calendar (true, null, selected, closeHandler);
          cal.weekNumbers = false;  // Do not display the week number
          cal.showsTime = true;     // Display the time
          cal.time24 = true;        // Hours have a 24 hours format
          cal.showsOtherMonths = false; // Just the current month is displayed
          calendar = cal;           // remember it in the global var
          cal.setRange (1900, 2070);  // min/max year allowed.
          cal.create ();
        }

      calendar.setDateFormat ('%Y-%m-%d %H:%M');  // set the specified date format
      calendar.parseDate (el.value);  // try to parse the text in field
      calendar.sel = el;            // inform it what input field we use

      // Display the calendar below the input field
      calendar.showAtElement (el, "Br");  // show the calendar

      return false;
    }

    // This function update the date in the input field when selected
    function
    selected (cal, date)
    {
      cal.sel.value = date;         // just update the date in the input field.
    }

    // This function gets called when the end-user clicks on the 'Close' button.
    // It just hides the calendar without destroying it.
    function
    closeHandler (cal)
    {
      cal.hide ();                  // hide the calendar
      calendar = null;
    }
  </script>
</head>

<body bgcolor=#FFFFFF>
<center>
  <table width="70%" border="0" cellpadding="2" cellspacing="0">
    <tr>
      <td width="50%" valign="top" align="center">
        <!-- firewall side begin -->
        <form method=POST action="process.php">
        <input type="hidden" name="type" value="firewall">
        <table width="100%" border="1" cellpadding="2" cellspacing="0" class="control">
          <tr class="header">
            <td colspan="2" height="25" class="header"><b>&nbsp;Filter Details - Firewall</b></td>
          </tr>
          <tr>
            <td colspan="2" valign="top">&nbsp;</td>
          </tr>
          <tr>
            <td colspan="2" align="center">
              <table border="1" cellspacing="0" width="70%">
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>Nat:</b>&nbsp; &nbsp; <input class="fixed" name="firewall_nat" type="radio" value="on" <? if ($_SESSION ['firewall_nat'] == "on") echo "checked"; ?>> On&nbsp; &nbsp;
                    <input class="fixed" name="firewall_nat" type="radio" value="off" <? if ($_SESSION ['firewall_nat'] == "off") echo "checked"; ?>> Off
                  </td>
                </tr>
                <tr>
                  <td colspan="2" valign="top">&nbsp;</td>
                </tr>
                <tr>
                  <td valign="top" align="center">
                    <b>From:</b>
                    <input  class="fixed" type="text" style="width:100px" name="firewall_date_from" id="firewall_date_from" value="<? echo $_SESSION ["firewall_date_from"]; ?>">
                    <input type="image" src="images/calendar.gif" alt="Start date selector" border="0" align="absmiddle" onclick="return showCalendar('firewall_date_from');">&nbsp;
                  </td>
                  <td valign="top" align="center">
                    <b>To:</b>
                    <input class="fixed" type="text" style="width:100px" name="firewall_date_to" id="firewall_date_to" value="<? echo $_SESSION ["firewall_date_to"]; ?>">
                    <input type="image" src="images/calendar.gif" alt="End date selector" border="0" align="absmiddle" onclick="return showCalendar('firewall_date_to');">&nbsp;&nbsp;
                  </td>
                </tr>
                <tr>
                  <td valign="top" colspan="2">&nbsp;</td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>IP Src:</b>
                    <input class="fixed" type="text" name="firewall_ip_src" style="width:200px" value="<? echo $_SESSION ['firewall_ip_src']; ?>">
                  </td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>IP Dst:</b>
                    <input class="fixed" type="text" name="firewall_ip_dst" style="width:200px" value="<? echo $_SESSION ['firewall_ip_dst']; ?>">
                  </td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>Proto:</b> <input class="fixed" name="firewall_ip_proto" type="radio" value="<? echo IPPROTO_TCP; ?>" <? if ($_SESSION ['firewall_ip_proto'] == IPPROTO_TCP) echo "checked"; ?>> TCP &nbsp; &nbsp;
                    <input class="fixed" name="firewall_ip_proto" type="radio" value="<? echo IPPROTO_UDP; ?>" <? if ($_SESSION ['firewall_ip_proto'] == IPPROTO_UDP) echo "checked"; ?>> UDP &nbsp; &nbsp;
                    <input class="fixed" name="firewall_ip_proto" type="radio" value="<? echo IPPROTO_ANY; ?>" <? if ($_SESSION ['firewall_ip_proto'] == IPPROTO_ANY) echo "checked"; ?>> Any
                  </td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>Src Port:</b> <input class="fixed" type="text" name="firewall_spt" style="width:40px" value="<? echo $_SESSION ['firewall_spt']; ?>"> &nbsp; &nbsp; &nbsp;
                    <b>Dst Port:</b> <input class="fixed" type="text" name="firewall_dpt" style="width:40px" value="<? echo $_SESSION ['firewall_dpt']; ?>">
                  </td>
                </tr>
                <tr>
                  <td valign="top" colspan="2">&nbsp;</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td align="center" valign="top" colspan="2"><b>Results per page:</b>&nbsp; &nbsp;
            <input class="fixed" type="text" name="firewall_my_delta" style="width:40px" value="<? echo $_SESSION ['firewall_my_delta']; ?>"></td>
          </tr>
          <tr>
            <td colspan="2" valign="top">&nbsp;</td>
          </tr>
          <tr>
            <td nowrap="nowrap" align="center">
              <input type="submit" class="button" value=" Search " style="width: 80px">
            </td>
            <td nowrap="nowrap" align="center">
              <input type="reset" class="button" value=" Reset " style="width: 80px">
            </td>
          </tr>
        </table>
        </form>
        <!-- firewall side end -->
      </td>
    </tr>
    <tr>
      <td width="50%" valign="top"  align="center">
        <!-- dns side begin -->
        <form method=POST action="process.php">
        <input type="hidden" name="type" value="dns">
        <table width="100%" border="1" cellpadding="2" cellspacing="0" class="control">
          <tr class="header">
            <td colspan="2" height="25" class="header"><b>&nbsp;Filter Details - Dns</b></td>
          </tr>
          <tr>
            <td colspan="2" valign="top">&nbsp;</td>
          </tr>
          <tr>
            <td colspan="2" align="center">
              <table border="1" cellspacing="0" width="70%">
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>Nat:</b>&nbsp; &nbsp; <input class="fixed" name="dns_nat" type="radio" value="on" <? if ($_SESSION ['dns_nat'] == "on") echo "checked"; ?>> On&nbsp; &nbsp;
                    <input class="fixed" name="dns_nat" type="radio" value="off" <? if ($_SESSION ['dns_nat'] == "off") echo "checked"; ?>> Off
                  </td>
                </tr>
                <tr>
                  <td colspan="2" valign="top">&nbsp;</td>
                </tr>
                <tr>
                  <td valign="top" align="center">
                    <b>From:</b>
                    <input  class="fixed" type="text" style="width:100px" name="dns_date_from" id="dns_date_from" value="<? echo $_SESSION ["dns_date_from"]; ?>">
                    <input type="image" src="images/calendar.gif" alt="Start date selector" border="0" align="absmiddle" onclick="return showCalendar('dns_date_from');">&nbsp;
                  </td>
                  <td valign="top" align="center">
                    <b>To:</b>
                    <input class="fixed" type="text" style="width:100px" name="dns_date_to" id="dns_date_to" value="<? echo $_SESSION ["dns_date_to"]; ?>">
                    <input type="image" src="images/calendar.gif" alt="End date selector" border="0" align="absmiddle" onclick="return showCalendar('dns_date_to');">&nbsp;&nbsp;
                  </td>
                </tr>
                <tr>
                  <td valign="top" colspan="2">&nbsp;</td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>Client:</b>
                    <input class="fixed" type="text" name="dns_client" style="width:200px" value="<? echo $_SESSION ['dns_client']; ?>">
                  </td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">
                    <b>Query:</b>
                    <input class="fixed" type="text" name="dns_query" style="width:200px" value="<? echo $_SESSION ['dns_query']; ?>">
                  </td>
                </tr>
                <tr>
                  <td valign="top" align="center" colspan="2">&nbsp;</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td align="center" valign="top" colspan="2"><b>Results per page:</b>&nbsp; &nbsp;
            <input class="fixed" type="text" name="dns_my_delta" style="width:40px" value="<? echo $_SESSION ['dns_my_delta']; ?>"></td>
          </tr>
          <tr>
            <td colspan="2" valign="top">&nbsp;</td>
          </tr>
          <tr>
            <td nowrap="nowrap" align="center">
              <input type="submit" class="button" value=" Search " style="width: 80px">
            </td>
            <td nowrap="nowrap" align="center">
              <input type="reset" class="button" value=" Reset " style="width: 80px">
            </td>
          </tr>
        </table>
        </form>
        <!-- dns side end -->
      </td>
    </tr>
  </table>
</center>
</body>
</html>
