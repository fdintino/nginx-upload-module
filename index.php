<?php
$header_prefix = 'file';
$upload_dir = 'upload';
$slots = 6;

if ($_POST){
	for ($i=0;$i<=$slots;$i++){
		$key = $header_prefix.$i;
		if (array_key_exists($key."_name", $_POST) && array_key_exists($key."_path",$_POST)) {
			$tmp_name = $_POST[$key."_path"];
			$name = $_POST[$key."_name"];
			$newname = $upload_dir."/".$name;
			if (rename($tmp_name, $newname)) {
				echo "Moved to $upload_dir successfull<br/>\n";
			} else {
				echo "Failed to move file<br/>\n";
			}
		}else{
			continue;
		}
	}
}else{?>

<html>
<head>
<title>Test upload</title>
</head>
<body>
<h2>Select files to upload</h2>
<form name="upload" method="POST" enctype="multipart/form-data" action="/doupload">
<input type="file" name="file1"><br>
<input type="file" name="file2"><br>
<input type="file" name="file3"><br>
<input type="file" name="file4"><br>
<input type="file" name="file5"><br>
<input type="file" name="file6"><br>
<input type="submit" name="submit" value="Upload">
<input type="hidden" name="test" value="value">
</form>
</body>
</html>
	
<?}
?>