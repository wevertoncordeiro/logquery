<?
if (isset($_GET['sid']))
  session_id(strip_tags($_GET['sid']));
session_start();
$program_name = "Log Analyzer";

define ('DEFAULT_TIMESPAN', 300);

define ('IPPROTO_TCP', "TCP");
define ('IPPROTO_UDP', "UDP");
define ('IPPROTO_ANY', "");

$_elements = array();
$_cur_path = '';
$index = '';

function send_xml_query($query, $server, $port, $timeout)
{
  global  $_elements;

  $e = error_reporting(0);
  $socket = fsockopen($server, $port, $errno, $errstr, $timeout);
  if (!$socket) {
    $_elements['/RESULT/TYPE'] = array();
    array_push($_elements['/RESULT/TYPE'], "error");
    $_elements['/RESULT/ENTRY/ERROR'] = array();
    array_push($_elements['/RESULT/ENTRY/ERROR'], "0");
    $_elements['/RESULT/ENTRY/MESSAGE'] = array();
    array_push($_elements['/RESULT/ENTRY/MESSAGE'], "error opening connection");
  } else {
    $xph = xml_parser_create();
    if (is_resource($xph)) {
      xml_parser_set_option($xph, XML_OPTION_CASE_FOLDING, true);
      if (!xml_set_element_handler($xph, 'start_elem_handler', 'end_elem_handler')) {
        $_elements['/RESULT/TYPE'] = array();
        array_push($_elements['/RESULT/TYPE'], "error");
        $_elements['/RESULT/ENTRY/ERROR'] = array();
        array_push($_elements['/RESULT/ENTRY/ERROR'], "0");
        $_elements['/RESULT/ENTRY/MESSAGE'] = array();
        array_push($_elements['/RESULT/ENTRY/MESSAGE'], "could not set XML handlers");
      } else if (!xml_set_character_data_handler($xph, "tagData")) {
        $_elements['/RESULT/TYPE'] = array();
        array_push($_elements['/RESULT/TYPE'], "error");
        $_elements['/RESULT/ENTRY/ERROR'] = array();
        array_push($_elements['/RESULT/ENTRY/ERROR'], "0");
        $_elements['/RESULT/ENTRY/MESSAGE'] = array();
        array_push($_elements['/RESULT/ENTRY/MESSAGE'], "could not set XML handler");
      } else {
        fputs($socket, $query);
        while ($data = fgets($socket, 4096))
          xml_parse($xph, $data, feof($socket));
        xml_parser_free($xph);
      }
    }
    fclose($socket);
    error_reporting($e);
  }
  return $_elements;
}

function tagData($xph, $tagData)
{
  global $index, $_elements;

  $path = "$index/VALUE";

  if (trim($tagData)) {
    $e = error_reporting(0);
    if (isset($_elements[$path]))
      array_push($_elements[$path], $tagData);
    else {
      $_elements[$path] = array();
      array_push($_elements[$path], $tagData);
    }
  }
}

function start_elem_handler($xph, $name, $attrs)
{
  global  $_elements, $_cur_path, $index, $count;

  $e = error_reporting(0);
  $_cur_path .= "/$name";
  while (list($key,$val) = each($attrs)) {
    $index = "$_cur_path/$key";
    if (isset($_elements[$index]))
      array_push($_elements[$index], $val);
    else {
      $_elements[$index] = array();
      array_push($_elements[$index], $val);
    }
  }
  error_reporting($e);
}

function end_elem_handler($xph, $name)
{
  global  $_elements, $_cur_path;

  $_cur_path = dirname($_cur_path);
}

function set_preset_timespan ($type) {
  if (!isset ($_SESSION [$type."_date_to"])) {
    $_date_to = time();
    $date_to_year = date("Y", $_date_to);
    $date_to_month = date("m", $_date_to);
    $date_to_day = date("d", $_date_to);
    $date_to_hour = date("H", $_date_to);
    $date_to_min = date("i", $_date_to);
    $date_to_sec = 00;
    $_SESSION [$type."_date_to"] = $date_to_year . "-" . $date_to_month . "-".$date_to_day . " ".$date_to_hour . ":" . $date_to_min;
  }

  if (!isset ($_SESSION [$type."_date_from"])) {
    $_date_from = strtotime ($_SESSION [$type."_date_to"]) - DEFAULT_TIMESPAN;
    $date_from_year = date("Y", $_date_from);
    $date_from_month = date("m", $_date_from);
    $date_from_day = date("d", $_date_from);
    $date_from_hour = date("H", $_date_from);
    $date_from_min = date("i", $_date_from);
    $date_from_sec = 00;
    $_SESSION [$type."_date_from"] = $date_from_year . "-" . $date_from_month . "-" . $date_from_day . " " . $date_from_hour . ":" . $date_from_min;
  }
}

?>