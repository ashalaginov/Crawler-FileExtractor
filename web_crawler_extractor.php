<?php 
// Simple Web crawler - file downloader with multi-thread capabilities. Requires php, curl, libxml and screen. Executes in two loops: 1. by country code, 2. corresponding URL from this country. 
// The depth is 3 with max number of URLs in stack per depth - 10000

// Required files and folders:
// country_codes.txt - list of two letters country codes (bg, lt, se, etc.)
// final_<two_letter_country_code>.txt - list of domain names per country
// malware_collection_10000/ - the output for each country/website files and logs
// final_<two_letter_country_code>.txt

// Example of fily types by MIME:
//'exe' = 'application/octet-stream' 
//'exe' = 'application/x-msdownload' 
//'apk' = 'application/vnd.android.package-archive' 
//'zip' = 'application/zip' 
//'rar' = 'application/x-rar-compressed'

$file_interest=array('application/octet-stream','application/vnd.android.package-archive','application/zip','application/x-rar-compressed','application/x-msdownload');

// Number of executionn threads
$n_forks = 20;

//Automated fetching, writes url of parent-child
$path="/malware_collection_10000/" ;

//Read 2 letters country codes
$country_codes = file("country_codes.txt", FILE_IGNORE_NEW_LINES);

//Disable errors messages of XML with malformed nature
libxml_use_internal_errors(true);

//EXTERNAL loop - country by country
foreach($country_codes as $key => $country)
{
	echo "\nCountry: $country\n";
	
	//Read URL per country
	$domains = file("final_$country.txt", FILE_IGNORE_NEW_LINES);
	
	if (!is_dir($path.$country)) {
		mkdir($path.$country);
	}
	
	$total =count($domains);
	$p = array();
	$left=array();
	$right=array();
	
	//Decides on number of batches per thread
	for ($i = 0; $i < $n_forks; $i++){
		$left[$i] = ceil($total * $i / $n_forks);
		$right[$i]=ceil($total * $i / $n_forks)+ceil($total / $n_forks);
	}

	//Envokes child processes
	for ($i = 0; $i < $n_forks; $i++) {
		$pids[$i] = pcntl_fork();
		if (!$pids[$i]) {
			//Child process
			runChildProcess($i,$key,$country,$domains,$left,$right,$file_interest,$path);
			exit(0);
		}
	}

	//Waits until the work is done for each thread
	for ($i = 0; $i <= $n_forks; $i++) {
		pcntl_waitpid($pids[$i], $status, WUNTRACED);
	}

	unset($p);
	unset($left);
	unset($right);
	
}



function runChildProcess($i,$key,$country,$domains,$left,$right,$file_interest,$path) {
	//INTERNAL loop - domain by domain
	echo "Child: $i\n";
	if (!is_dir($path.$country."/logs")) {
		mkdir($path.$country."/logs");
	}
	
	for($k=$left[$i];$k<$right[$i];$k++){
		$main_url=$domains[$k];
		$main_url_path=$main_url;
	
		//check hhtp/https
		$status=checkHttp($main_url);
		if($status == 0)
			$main_url="https://".$main_url;
		
		$output="";

		$output.="\n$k Url: $main_url\n";
		echo $output;
		
		//first run - array of URLs
		$output.= "\n First run ($main_url):";
		$rootUrls=fetchUrls($main_url);
		print_r(count($rootUrls));
		echo "\n";
		$rootUrls=array_unique($rootUrls);
		$output.="  ".count($rootUrls)."";
		
		//second run - checks file types and collects set of URLs to follow
		$output.= "\n Second run ($main_url):";
		$firstUrls=array();
		foreach($rootUrls as $url){
		    if(count(array_unique($firstUrls))<10000){
				if(in_array(strtolower(urlType($url)),$file_interest)){
					if (!is_dir($path.$country."/".$main_url_path)) {
						mkdir($path.$country."/".$main_url_path);
					}
					echo "FILE\n";
					// fetching file
					shell_exec("cd ".$path.$country."/".$main_url_path."; /usr/local/bin/screen -dm /usr/local/bin/curl --fail --silent --show-error -L -O ".$url);
					$output.= "\nFile detected: ".$url." \n";
				}elseif(strpos(urlType($url), "text/html")!== false){
					$tmp_urls=fetchUrls($url);	
					$firstUrls=array_merge($firstUrls,$tmp_urls);
				}
			}
		}
		$firstUrls=array_unique($firstUrls);
		$firstUrls=array_diff($firstUrls,$rootUrls);
		$output.=count($firstUrls);
		echo "\n";
		unset($tmp_urls);

		//third run - checks file types and collects set of URLs to follow 
		$output.= "\n Third run ($main_url):";
		$secondUrls=array();
		foreach($firstUrls as $url){
			if(count(array_unique($secondUrls))<10000){
				if(in_array(strtolower(urlType($url)),$file_interest)){
					if (!is_dir($path.$country."/".$main_url_path)) {
						mkdir($path.$country."/".$main_url_path);
					}
					shell_exec("cd ".$path.$country."/".$main_url_path."; /usr/local/bin/screen  -dm  /usr/local/bin/curl --fail --silent --show-error -L -O ".$url);
					// fetching file
					$output.= "\nFile detected: ".$url." \n";
				}elseif(strpos(urlType($url), "text/html")!== false){
					$tmp_urls=fetchUrls($url);
					$secondUrls=array_merge($secondUrls,$tmp_urls);
				}
			}
		}
		$secondUrls=array_unique($secondUrls);
		$secondUrls=array_diff($secondUrls,$firstUrls,$rootUrls);
		$output.=count($secondUrls);
		print_r(count($secondUrls));
		unset($tmp_urls);

		//writes logs
		file_put_contents($path.$country."/logs/log_".$main_url_path.".txt",$output);
		sleep(1);
	}
	
}


///////////////////FUNCTIONS////////////////////////////////////

// extract URLs from a page
function fetchUrls($url){
	$urls=array();
	$files=array();
	$ch = curl_init($url);
	curl_setopt($ch,CURLOPT_URL,$url);
	curl_setopt($ch,CURLOPT_USERAGENT, 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0');
	curl_setopt($ch,CURLOPT_HEADER,0);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
	curl_setopt($ch,CURLOPT_FOLLOWLOCATION,1);
	curl_setopt($ch,CURLOPT_ENCODING, 'UTF-8');
	curl_setopt($ch,CURLOPT_TIMEOUT,120);
	$html = curl_exec($ch);

	if(strlen($html)>0){
		$dom = new DOMDocument;
		$dom->loadHTML($html);
		
		foreach ($dom->getElementsByTagName('a') as $node)
		{
			$url_selected=$node->getAttribute("href");
			if($url_selected!="" && $url_selected!="#"){
				if($url_selected[0]=="/")
					$urls[]=$url.$url_selected;
				else
					$urls[]=$url_selected;
			}
		}
	}
	curl_close($ch);
	
	return $urls;
}

// check URL type
function urlType($url){
   # the request
	$ch = curl_init($url);
    curl_setopt($ch,CURLOPT_URL,$url);
    curl_setopt($ch,CURLOPT_USERAGENT, 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0');
    curl_setopt($ch,CURLOPT_HEADER,0);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch,CURLOPT_FOLLOWLOCATION,1);
    curl_setopt($ch, CURLOPT_ENCODING, 'UTF-8');
    curl_setopt($ch,CURLOPT_TIMEOUT,120);
	curl_exec($ch);
	# get the content type
	return curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
}

// check whether there is a redirect on the webpage
function checkHttp($url){
 # the request
	$ch = curl_init($url);
	curl_setopt($ch,CURLOPT_URL,$url);
	curl_setopt($ch,CURLOPT_USERAGENT, 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0');
	curl_setopt($ch,CURLOPT_HEADER,0);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
	curl_setopt($ch,CURLOPT_FOLLOWLOCATION,0);
	curl_setopt($ch, CURLOPT_ENCODING, 'UTF-8');
	curl_setopt($ch,CURLOPT_TIMEOUT,120);
	$html = curl_exec($ch);

	# get the status
	$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	if (($code == 301) || ($code == 302)) {
		//This was a redirect
		return 0;
	}else
		return 1;
}


?>
