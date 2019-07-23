<?php
/** Deal with VirusTotal.com file checks.
 *  This class will allow you to scan files for viruses using the API from VirusTotal.com.
 *  You will need an API key (can be obtained for free at https://www.virustotal.com/) to
 *  use this class. Apart from initializing the class, you will only need to call its
 *  checkFile() method and, if that finally returns TRUE, obtain your results via the
 *  getResponse() method.
 *  Idea taken from a script by Adrian at www.TheWebHelp.com and reworked into a proper
 *  PHP class by Izzy.
 * @class virustotal
 * @author Adrian at www.TheWebHelp.com
 * @author Izzy at android.izzysoft.de
 * @see https://www.virustotal.com/de/documentation/public-api/
 * @see https://www.thewebhelp.com/php/scripts/virustotal-php-api/
 */
class virustotal {

  /** API_KEY for the service
   * @class virustotal
   * @attribute string api_key
   */
  private $api_key = '';

  /** Enable debug output
   * @class virustotal
   * @attribute bool debug
   */
  private $debug = false;

  /** last JSON response from service (or empty if not yet retrieved)
   * @class virustotal
   * @attribute protected array json_response
   * @verbatim important elements (dump it for more details; full elements only when scan completed):
   *    * positives: number of malware hits (0=clean)
   *    * total: number of engines used
   *    * permalink: link to result page
   *    * scans: detailed result array[name: array[bool detected, str version, str result (name of threat), str update (YYYYMMDD)]]
   *    * scan_date: YYYY-MM-DD HH24:MI:SS
   *    * response_code (int), verbose_msg (str)
   *    * also hashes/identifiers: sha256, sha1, md5, scan_id, resource
   */
  public $json_response = [];

  /** ScanID we can use to query the state for this file
   * @class virustotal
   * @attribute protected string scanID
   */
  protected $scanID = '';

  /** Initialize the class by setting up the API_KEY
   * @construct virustotal
   * @param string api_key VirusTotal API key
   */
  function __construct($api_key) {
    $this->api_key = $api_key;
  }

  /** Ask VirusTotal to rescan an already submitted file
   * @class virustotal
   * @method rescan
   * @param str hash    File Hash (MD5/SHA256) of the file to rescan
   * @param str maxage  max age (in days) for an already existing result set. If it's newer, we won't ask for a rescan but stick with that. Set to 0 to enforce a rescan.
   * @return number haveResults -99: got no response; -1: error; 0: file is enqueued, 1: results ready; use self::getResponse() to obtain details;
   *                            other negative values: other errors (most likely unknown / not described in API and should not happen)
   * @info Note that the -99 (got no response) return code usually means you've exceeded the limits of your key (i.e. 4 requests per minute for a public key)
   */
  function rescan($hash,$maxage=7) {
    if ( empty($hash) ) {
      $this->json_response = json_encode(['error'=>"virustotal::rescan needs a hash but got an empty string"]);
      return -1;
    }
    $maxage = abs($maxage) * 86400;     // convert to seconds
    if ( $maxage > 86399 ) {
      $res = $this->checkFile('',$hash);  // check for existing results
      switch ($res) {
        case -99:                     // API limit exceeded
        case  -1:                     // some error occured
        case   0: return $res; break; // file still queued, so no results yet at all
        case   1: break;              // we got a result, so do not yet return :)
        default : return $res; break; // unknown error
      }

      // still here? So we've got a result to examine:
      $resp = json_decode($this->json_response)->scan_date;   // "YYYY-MM-DD HH:MI:SS"
      if ( time() - strtotime($resp) < $maxage ) return 1;    // result still valid
    }

    // still here? OK, so we really initiate a rescan:
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/vtapi/v2/file/rescan');
    curl_setopt($ch, CURLOPT_POST,1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, ['apikey'=>$this->api_key, 'resource'=>$hash]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
    $api_reply = curl_exec ($ch);
    curl_close ($ch);

    $reply = json_decode($api_reply);
    if ( is_object($reply) && property_exists($reply,'response_code') ) {
        $api_rc = $reply->response_code;
    } else {
        $api_rc = -99;
    }
    if ( $api_rc === '' ) $api_reply = -99;

    // continue depending on the result
    switch ( $api_rc ) {
       case  1 :  // successfully enqueued for rescan
                  $this->json_response = json_encode(['scan_id'=>$reply->scan_id,'sha256'=>$reply->sha256,'resource'=>$reply->resource,'permalink'=>$reply->permalink,'verbose_msg'=>'Rescan scheduled','response_code'=>$api_rc]);
                  //$this->json_response = json_encode('verbose_msg'=>'Rescan scheduled','response_code'=>$api_rc]);
                  return 0;
                  break;
       case  0 :  // hash not known to the service
                  $this->json_response = json_encode(['response_code'=>0,'verbose_msg'=>'virustotal::rescan: hash unknown to VirusTotal, no rescan possible']);
                  return -1;
                  break;
       case -99:  // we've got no response (API limit exceeded?)
                  $this->json_response = json_encode(['response_code'=>-99,'verbose_msg'=>'Got empty response from VirusTotal. API limit exceeded?']);
                  return -99;
                  break;
       default :  // some error occured
                  $this->json_response = json_encode(['response_code'=>$api_reply,'error'=>'API error: an unknown error occured']);
                  return -1;
                  break;
    }
  }

  /** Check a file and get the results
   * @class virustotal
   * @method checkFile
   * @info at least one of fileName or file_hash (or both) must be provided -- they cannot be both empty, or we don't know what to check :)
   * @param optional string fileName    Name of the file to check. We must be able to access it by this name, so include path if needed
   * @param optional string hash        File Hash (MD5/SHA256) or Scan ID to use. If not passed, hash will be calculated. Scan ID gives more details on queue status.
   * @return number haveResults         -99: got no response; -90: error on upload; -1: error; 0: no results, 1: results ready; use self::getResponse() to obtain details;
   *                                    self::getScanId for the ScanID (set only after initial enqueue, i.e. upload of the file)
   *                                    other negative values: other errors (most likely unknown / not described in API and should not happen)
   * @info Note that the -99 (got no response) return code usually means you've exceeded the limits of your key (i.e. 4 requests per minute for a public key)
   */
  public function checkFile($fileName='', $hash='') {
    if ( ! file_exists($fileName) ) {
      if ( empty($hash) ) {
        $this->json_response = json_encode(['error'=>"virustotal::checkFile could not find the file specified: '$fileName', and no hash/scanID was provided"]);
        return -1;
      } else {
        $fileNamePassed = $fileName;
        $fileName = '';
      }
    }

    // calculate a hash of this file if not provided, we will use it as an unique ID when quering about this file
    if ( empty($hash) )
        $hash = hash_file('sha256', $fileName);

    // first check if a report for this file already exists, so we don't need to upload
    $report_url = 'https://www.virustotal.com/vtapi/v2/file/report?apikey='.$this->api_key."&resource=".$hash;
    if ( ! $api_reply = @file_get_contents($report_url) ) $api_reply = '';
    ( $api_reply === '' ) ? $api_reply_array = ['response_code'=>-99,'verbose_msg'=>'Got empty response from VirusTotal'] : $api_reply_array = json_decode($api_reply, true);

    // continue depending on the result
    $api_reply_array['step'] = 'CheckFile';
    switch ( $api_reply_array['response_code'] ) {
       case -99:  // we've got no response (API limit exceeded?)
                  $this->json_response = json_encode($api_reply_array);
                  return -99;
                  break;
       case -2 :  // resource is already queued for analysis
                  $this->json_response = $api_reply;
                  return 0;
                  break;
       case  1 :  // reply is OK (it contains an antivirus report)
                  $this->json_response = $api_reply;
                  return 1;
                  break;
       case  0 :  // file not yet known to the service
                  if ( !empty($fileName) ) { // self::json_response will be set by self::uploadFile
                    if ( $this->uploadFile($fileName) ) return 0; // results are not available immediately
                    if ($this->debug) print_r($api_reply_array);
                    return -90; // an error occured during upload
                  } else {
                    $api_reply_array['error'] = "virustotal::checkFile: hash unknown to VirusTotal and file '$fileNamePassed' could not be found";
                    $this->json_response = json_encode($api_reply_array);
                    if ($this->debug) print_r($api_reply_array);
                    return -1;
                  }
                  break;
       default :  // some error occured
                  $api_reply_array['error'] = 'API error: '.$api_reply_array['verbose_msg'];
                  $this->json_response = json_encode($api_reply_array);
                  if ($this->debug) print_r($api_reply_array);
                  return -1;
                  break;
    }
  }

  /** Upload a file to check
   *  self::checkFile() calls this automatically when needed – so only call this if you're knowing what you're doing :)
   * @class virustotal
   * @method uploadFile
   * @param string fileName Name of the file to check. We must be able to access it by this name, so include path if needed
   * @return bool success   use self::getResponse() for details, self::getScanId for the ScanID
   */
  public function uploadFile($fileName) {
    if ( ! file_exists($fileName) ) {
        $this->json_response = json_encode(['error'=>"virustotal::uploadFile could not find the file specified: '$fileName'"]);
        return FALSE;
    }

    $file_size_mb = filesize($fileName)/1024/1024;     // get the file size in mb, we will use it to know at what url to send for scanning (it's a different URL for over 30MB)
    $mimetype = mime_content_type($fileName);
    if ( empty($mimetype) ) $mimetype = 'application/octet-stream';

    $post_url = 'https://www.virustotal.com/vtapi/v2/file/scan';
    $post['apikey'] = $this->api_key;
    $cfile = new CURLFile($fileName,$mimetype);
    $post['file'] = $cfile;

    // get a special URL for uploading files larger than 32MB (up to 200MB)
    if($file_size_mb >= 32) {// get a special URL for uploading files larger than 32MB (up to 200MB)
        $api_reply = @file_get_contents('https://www.virustotal.com/vtapi/v2/file/scan/upload_url?apikey='.$this->api_key);
        $api_reply_array = json_decode($api_reply, true);
        if ( isset($api_reply_array['upload_url']) and $api_reply_array['upload_url']!='' ) {
            $post_url = $api_reply_array['upload_url'];
        } else {
            $this->json_response = json_encode(['error'=>"Failed to obtain special URL for big file '$fileName'. Make sure you got the extra privilege."]);
            return false;
        }
    }

    // send the file for checking
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,$post_url);
    curl_setopt($ch, CURLOPT_POST,1);
    curl_setopt($ch, CURLOPT_POST,1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
    $api_reply = curl_exec ($ch);
    curl_close ($ch);


    // now evaluate results
    $api_reply_array = json_decode($api_reply, true);
    if ($api_reply_array['response_code']==1) { // file successfully enqueued
        $this->scanID = $api_reply_array['scan_id'];
        $this->json_response = $api_reply;
        return TRUE;
    } else {
        $api_reply_array['error'] = 'API error: '.$api_reply_array['verbose_msg'];
        $api_reply_array['step'] = 'Upload';
        $this->json_response = json_encode($api_reply_array);
        if ($this->debug) print_r($api_reply_array);
        return FALSE;
    }
  }

  /** Obtain the ScanID of the latest uploaded file
   * @class virustotal
   * @method getScanId
   * @return string scanId (empty if no file was uploaded by this class instance yet)
   */
  public function getScanId() {
    return $this->scanID;
  }

  /** Obtain the JSON response array from the latest check
   * @class virustotal
   * @method getResponse
   * @return array response
   */
  public function getResponse() {
    return $this->json_response;
  }

} // end class virustotal
?>