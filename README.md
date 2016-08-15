# virustotal
This is a PHP library for the [VirusTotal.COM public API version
2.0](https://www.virustotal.com/de/documentation/public-api/). It's based upon
[the work of Adrian at
www.TheWebHelp.com](https://www.thewebhelp.com/php/scripts/virustotal-php-api/).
As Adrian didn't include a license with his work, I didn't either (I cannot
put part of his work under a license of my choice, after all).


## Requirements
* PHP (of course; tested with 5.4) with CURL support.
* an API key (available for free at the VirusTotal website)

## Usage
Usage is pretty easy. Best demonstrated using an example:

    require_once('virustotal.class.php');
    $vt = new virustotal($apikey);
    $res = $vt->checkFile($filename,$hash); // $hash is optional. Pass the $scan_id if you have it, or the file hash
    switch($res) {
      case -99: // API limit exceeded
        // deal with it here – best by waiting a little before trying again :)
        break;
      case  -1: // an error occured
        // deal with it here
        break;
      case   0: // no results (yet) – but the file is already enqueued at VirusTotal
        $scan_id = $vt->getScanId();
        $json_response = $vt->getResponse();
        break;
      case   1: // results are available
        $json_response = $vt->getResponse();
        break;
      default : // you should not reach this point if you've placed the break before :)
    }
    // deal with the JSON response here

For details on the JSON response (both on enqueuing a file and when getting
the final scan results), please consult the [VirusTotal API
documentation](https://www.virustotal.com/de/documentation/public-api/). For
details on the PHP class in this repository, consult the code. You should find
it well documented :)