<?php
$header_prefix = 'file';
?>
<html>
<head>
<title>Test upload</title>
</head>
<body>
<?
if ($_POST){
    echo "<h2>Uploaded files:</h2>";

    echo "<table border=\"2\" cellpadding=\"2\">";

    echo "<tr><td>Archive path</td><td>File name</td><td>Location</td><td>Content type</td><td>MD5</td><td>Size</tr>";

    $fdesc_keys = array_keys($_POST);

    foreach($fdesc_keys as $fdesc_key) {
        if(strpos($fdesc_key, $header_prefix) == 0 &&
            strpos($fdesc_key, "_name") > 0) {
            $key = substr($fdesc_key, 0, count($fdesc_key) - 6);

            if (array_key_exists($key."_name", $_POST) && array_key_exists($key."_path",$_POST)) {
                $archive_path = $_POST[$key."_archive_path"];
                $tmp_name = $_POST[$key."_path"];
                $name = $_POST[$key."_name"];
                $content_type = $_POST[$key."_content_type"];
                $md5 = $_POST[$key."_md5"];
                $size = $_POST[$key."_size"];

                echo "<tr><td>$archive_path</td><td>$name</td><td>$tmp_name</td><td>$content_type</td><td>$md5</td><td>$size</td>";
            }
        }
	}

    echo "</table>";

}else{?>
<h2>Select files to upload</h2>
<form name="upload" method="POST" enctype="multipart/form-data" action="/upload">
<input type="file" name="file1"><br>
<input type="file" name="file2"><br>
<input type="file" name="file3"><br>
<input type="file" name="file4"><br>
<input type="file" name="file5"><br>
<input type="file" name="file6"><br>
<input type="submit" name="submit" value="Upload">
<input type="hidden" name="test" value="value">
</form>
<?}
?>
</body>
</html>
