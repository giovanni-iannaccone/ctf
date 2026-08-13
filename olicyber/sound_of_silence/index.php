<!DOCTYPE html>
<html>
<head>
    <title>Sound of silence</title>
</head>
<body style="background-color:black">

<canvas id="canvas" style="position:fixed; top:0;left:0"></canvas>

<div style="position: absolute;margin-left: auto;margin-right: auto;left: 0;right: 0;text-align: center;z-index: 1">
    
    <form method="POST">
        <input type="text" name="input">
        <button type="submit">Invia</button>
    </form>
    
    <?php

        include_once('./secret.php');

        $amp = 100;

        if(isset($_POST['input'])){
            $s = $_POST["input"];

            $amp = 10*strlen($s);

            if(strlen($s) == 0){
                echo "<p style=\"color:white\">Finalmente un po' di silenzio...</p>";

                $f = $FLAG.$s;

                if($f !== $FLAG){
                    echo "<p style=\"color:white\">$FLAG</p>";
                }
            }
        }

    ?>

</div>

<script src="js/wavy.min.js"></script>
<script src="js/index.js"></script>
<?php
    echo "<script>wave.amplitude *= (".strval($amp)."/100);wave.animate60();</script>"
?> 

</body>
</html>