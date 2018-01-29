<?php

$server = rtrim("REPLACE_SERVER", '/');
$hopName = "REPLACE_HOP_NAME";


function do_get_request($url, $optionalHeaders = null)
{
  global $hopName;
  $aContext = array(
    'http' => array(
      'method' => 'GET'
    ),
    'ssl'=>array(
      "verify_peer"=>false,
      "verify_peer_name"=>false,
    ),
  );
  $headers = array('Hop-Name' => $hopName);
  if ($optionalHeaders !== null) {
    $headers['Cookie'] = $optionalHeaders;
  }
  $aContext['http']['header'] = prepareHeaders($headers);
  $cxContext = stream_context_create($aContext);
  echo file_get_contents($url, False, $cxContext);
}


function do_post_request($url, $data, $optionalHeaders = null)
{
  global $hopName;
  $params = array(
    'http' => array(
      'method' => 'POST',
      'content' => $data
    ),
    'ssl'=>array(
      'verify_peer'=>false,
      'verify_peer_name'=>false,
    ),
  );
  $headers = array('Hop-Name' => $hopName);
  if ($optionalHeaders !== null) {
    $headers['Cookie'] = $optionalHeaders;
  }
  $params['http']['header'] = prepareHeaders($headers);
  $ctx = stream_context_create($params);
  $fp = @fopen($url, 'rb', false, $ctx);
  if (!$fp) {
    return '';
  }
  $response = @stream_get_contents($fp);
  if ($response === false) {
    return '';
  }
  echo $response;
}

function prepareHeaders($headers) {
  $flattened = array();

  foreach ($headers as $key => $header) {
    if (is_int($key)) {
      $flattened[] = $header;
    } else {
      $flattened[] = $key.': '.$header;
    }
  }

  return implode("\r\n", $flattened);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $requestURI = $_SERVER['REQUEST_URI'];
  if(isset($_COOKIE['session'])) {
    return do_get_request($server.$requestURI, "session=".str_replace(' ', '+', $_COOKIE['session']));
  }
  else {
    return do_get_request($server.$requestURI);
  }
}

else {
  // otherwise it's a POST
  $requestURI = $_SERVER['REQUEST_URI'];
  $postdata = file_get_contents("php://input");

  if(isset($_COOKIE['session'])) {
    return do_post_request($server.$requestURI, $postdata, "session=".str_replace(' ', '+', $_COOKIE['session']));
  }
  else {
    return do_post_request($server.$requestURI, $postdata);
  }
}

?>
