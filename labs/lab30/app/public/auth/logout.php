<?php
require __DIR__.'/../../src/bootstrap.php';start_session();$_SESSION=[];session_destroy();header('Location: /auth/login.php');
