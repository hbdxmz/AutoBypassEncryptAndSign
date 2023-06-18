#### AutoBypassEncryptAndSign
1. PS：项目中的插件并不是通用的，因为不同厂商针对自己业务的数据包加密算法、签名保护算法各种各样，需要先还原加密算法（或者签名保护算法），再对应的修改插件的加密算法（或者签名保护算法），笔者通过几个案例介绍这类业务的通用测试流程：常见加密算法分析流程、burp插件开发、联动Xray半自动化挖洞，主要是通过介绍这类业务的通用测试方法，降低安全测试的人力成本
2. 案例：https://xz.aliyun.com/t/12295
3. 项目中的两个插件源码即案例中介绍的自动加解密数据包密文、自动绕过签名保护的插件源码


## 场景

在金融银行类安全测试中，经常见到数据包加密、签名保护，这种业务不能直接进行有效的安全测试，修改数据包参数会重放失败，爬虫见到密文也是懵逼

1. 整体加密
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/406436d2-538d-4b14-928e-e8bcd3a0024c)
2. 分段加密
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/04a9d171-d619-4bff-adac-a10acc6bb11d)
3. 接口签名保护
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/aaffd969-8f03-447f-aa68-f4982d929c08)

## 测试套路

对于这种业务，不管是手工还是借助工具，需要先还原加密算法（或者签名保护算法）。知道了加密逻辑后，就可以开发burp插件完成明文状态下的安全测试，最后借助密文数据天然过waf的优势结合Xray等漏扫工具完成半自动的安全测试（逻辑漏洞还得需要手工测）。 笔者通过几个案例介绍这类业务的通用测试流程：常见加密算法分析流程、burp插件开发、联动Xray半自动化挖洞。  
所以案例只是案例，读者不要纠结于这些案例中的加密算法，因为加密有很多组合形式。主要是通过本文介绍这类业务的通用测试方法，降低安全测试的人力成本

## 案例

常见签名的生成算法：sign = MD5( sort( 业务参数+时间戳+其他参数) )，拼接业务参数+时间戳+其他参数，对字符串排序，计算字符串MD5作为sign。客户端和服务端使用相同的算法生成sign，服务端接收到请求后，先计算一次sign，如果业务参数、时间戳、其他参数中有一个被修改过，得到的sign就与客户端发送过来sign不一致，签名校验就会失败，不再处理请求

### 签名校验

1、不修改数据包，重放请求，此时可以正常响应

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/be90cd56-ed80-4752-b03e-d63834f92b33">


2、然后修改参数icon\_type的值为11，再次重放，此时会提示"message":"sign invalid"，请求中的api\_sign是签名的值，需要知道api\_sign是怎么计算出来的

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/e67dd6bd-8d95-4c5e-9ccd-6d754e9b5d2d">


3、用url参数作为关键字搜索，在js中定位api\_sign，设置断点

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/5ab08ba2-d061-49fb-a485-eb29c5fedaa0">


4、刷新网页，停在了断点位置，单步步入进入函数内部,可以看到加入了两个参数app\_key、app\_pwd，然后单步往下走，参数c的值此时为device\_id=069c8db0-af49-11ed-9a08-3b99f11ff116×tamp=1676725825997&session\_token=G2de7f3ab78910b46ad8c07d6e25c627&app\_key=f6aefd6691f04573bdf9e044137372bc，也就是所有url参数

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/b60b7446-756d-4606-bc58-b488ea20c6e7">


5、继续单步走，进行了一次排序，c的值为app\_key=f6aefd6691f04573bdf9e044137372bc&device\_id=069c8db0-af49-11ed-9a08-3b99f11ff116&session\_token=G2de7f3ab78910b46ad8c07d6e25c627×tamp=1676725825997

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/461d1074-6882-4b76-bc57-bfcc567d4fcd">


6、之后就是拼接字符串，app\_key+"Oic"+app\_pwd+"QeeeS99u3d"+c+app\_key+app\_pwd

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/90e0e7ef-8ca3-4686-a240-9aef0c645627">


7、得到的字符串为：  
f6aefd6691f04573bdf9e044137372bcOic72e78efefe6b4577a1f7afbca56b6e28993c06ea4bb84cde8dd70e582dbc76cbQeeeS99u3dapp\_key=f6aefd6691f04573bdf9e044137372bc&device\_id=069c8db0-af49-11ed-9a08-3b99f11ff116&session\_token=G2de7f3ab78910b46ad8c07d6e25c627×tamp=1676725825997f6aefd6691f04573bdf9e044137372bc72e78efefe6b4577a1f7afbca56b6e28993c06ea4bb84cde8dd70e582dbc76cb

8、最后获取这个字符串的MD5，就是签名api\_sign的值

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/732f2008-16ca-4677-9dcd-1708b4e7eaea">


9、还原了api\_sign的计算方式，就可以开发burp插件自动更新签名校验的参数api\_sign

1. ### 用burp插件自动更新签名

burp插件的接口开发可以参考官方文档和官方的代码demo，[https://portswigger.net/burp/extender/api/index.html](https://portswigger.net/burp/extender/api/index.html)

使用maven获取burp开发的接口依赖文件，插件开发规范：包名为burp，类名为BurpExtender
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/a7193eee-e129-4ab8-8597-22933b0f1bed)

首先在processHttpMessage中，检查uri参数，移除原来参数api\_sign

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/06abeb8a-1ee3-4d3f-85c4-39f70fe70745">


根据修改后的uri参数，使用已还原的api\_sign生成算法得到新的api\_sign

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/44a01abc-9a11-42f9-b466-be072d55eeef">


此时修改参数，重放请求后，插件会自动更新url中api\_sign的值（ps：下面这两个截图是笔者随意找的测试站点，url参数也是自己加的，读者根据上下文理解意思即可）

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/ede969c6-ac07-426c-afd1-477174c1e6df">

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0b75562a-b0a7-48fc-8b25-e96c6fba137c">

在控制台查看更新的api\_sign，此时修改请求参数做安全测试就不再受签名保护限制了

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/2ca9a834-cb2c-4674-b1a6-def813608aaf">


#### 数据包分段加密

一个H5应用，在微信可以正常访问，放到浏览器访问限制

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/02898bdd-ca07-4f0a-bec1-95b28ca17e2f)


修改一下User-Agent，修改为安卓或ios手机的UserAgent，再刷新页面后能正常访问  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/7f81d2cb-cf30-4436-9826-cc337a6e36d5)


随便输入一个卡号后先抓个包看看

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/c0662c7c-7bde-4667-9b7f-198923d72a4f)



数据包都做了加密

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/62db7275-6acc-426f-9dbf-4f96fdd1e5f3)


任意修改一个密文字符，把第一个字符c改成1，服务端不能正常处理密文  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/61036c5a-5453-458f-88f1-9cfc67e1057b)


直接发明文包不行，明文会被当成密文去解密  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/30d05ae7-cdea-46df-ba09-697c03a77e5d)


使用数据包的参数encryptData定位加密代码位置，展开js文件，搜索关键字；单击{}格式化js，方便阅读  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/052d6564-039e-4d62-9143-02a49e9d93dd)


单步步入调试进入pten函数，参数e是默认DES密钥  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/9b1e08ba-4098-4a5a-8c14-fe96900ba0e3)


查看setMd5的入参，可以debug一行一行看  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/104e5f11-e5c7-42ac-860c-aae7848b2d24)


也可以将方法代码放到控制台查看  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/dd17939c-fc02-45bb-8e12-e6b849dd4a1b)


可以看到第一部分MD5的构造是原始参数json+DES密钥e，拼接后做MD5

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0566004c-7036-46b9-87d0-d4f4d5443b21)


setDES这部分是ECB模式，Pkcs7填充的DES加密，密钥是e

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/98dd2aa5-cef0-4423-a916-264a7ae61fa7)


参数n是rsa加密DES密钥得到的密文，是一个固定值。最后返回MD5+splitStr+DES加密后参数+splitStr+rsa加密的DES密钥  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/e3f04743-70e2-49c6-bba5-c9c46292209b)


splitStr是一个分割字符，用于将不同加密加密方式得到的密文分割开，服务端收到密文后，按splitStr分割密文，再逐段解密  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/d4c35aa1-c25a-48fc-a450-556f88295d61)


拿到控制台看看是什么字符  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/1d9dd0ea-9fac-445c-a2d1-38e16700ece8)


也就是数据包中见到的\\u001d  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/b21dfa0a-58d4-4b87-b9ca-0b9c952b2b2f)


验证一下：解密中间部分的密文, 得到原始参数的json  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/df43d4ff-c44e-443f-a0e2-1ed4c957cf7b)


ptde函数用于解密返回包的密文

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/6000286b-4b18-47b1-87c7-173253c9ba3c)


![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/cc858ab0-42b0-4471-9b09-3da4c989ac86)


单步步入getDESModeEBC函数，使用密钥e进行DES解密，没有其他处理

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/111ad6c9-56cd-4223-bbfb-9f0f6f541359)


在线解密验证下  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0059422b-fb84-47ca-9ee8-382debf4a846)


得到结论：  
请求包的加密：MD5(原始参数+DES密钥)+”\\u001d”+DES(原始参数) +”\\u001d”+RSA(DES密钥)  
返回包的解密：直接用DES密钥解密即可

### 分段解密

用正则获取两个\\u001d中间的密文，

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/f4c465cf-7a4a-409c-a769-7acdc6fb462c)


解密后在burp控制台打印，看看能不能正常解密  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/42e06388-535a-4579-b067-4fefabd4a383)


明文请求的body则加密后重新封包  
<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/ea18db3b-99ac-4b09-8692-2a79966f90a8">

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/4ce62439-2999-4934-8a82-1013c9d7f8fe)

这时候使用明文发包没问题了  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/eb0a8518-2bc4-4a3d-8e61-89257f1f4b8a)


使用IMessageEditorTab在burp中增加一个控件，用于获取解密后的完整请求包，在IMessageEditorTab中填入header和解密后的原始参数  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0708cbae-b110-44fc-854e-d7c74c283d7a)



先判断是否请求中包含参数encryptData  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/bad29a01-1e2b-4f29-a365-4c4a7dd843e9)



包含则说明是密文包，再启用控件，解密密文  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/58b33b0f-8796-4c05-b2de-f65fa8f89604)

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/a300eebd-341a-4526-a3fc-3414f0049b41)

点击“参数明文”控件，获取到了解密后的完整请求包，对明文参数进行安全测试，重放后插件会自动完成密文构造  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/eaa73581-641b-4822-be26-61251524bbc3)

对于变化的密钥，可以提供一个ui界面，在输入框设置密钥，rsa等动态变化的值  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/6af82e8a-bbe9-4d4e-a5cb-8f6724d0a114)

body中密文部分存放在encryptData参数
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/952874c5-0c82-4585-b111-68dbe2c89507)

最后需要把返回包的密文也处理掉，由于在burp插件开发中返回包没有参数的概念，只能通过偏移获取body，解密后，用明文替换密文，再用IMessageEditorTab展示解密后的数据包  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/2c6d5ac9-0075-4f50-9168-93e5f8b026f6)


此时原始响应还是密文，因为客户端需要解密这个密文，IMessageEditorTab中明文只是展示作用，辅助安全测试，不会返回给客户端  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/9671cac8-a11c-439b-a54f-37328c7aa3d4)

![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/1ef8cd1a-4e7b-49a3-a6e8-10d07e785f9b)

encryptData中的密文被替换为明文展示，之后的安全测试就完全是明文了  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/dcdc422a-cce8-4fde-bbf4-74b2f98841e3)


### 自动BypassWAF 联动Xray

这也是数据包加密给安全测试人员的彩蛋吧，数据包加密有一个好处：天然对waf等态势感知设备免疫，自带绕过属性：  
明文的payload会被waf识别  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/b6de5b22-a68a-4d70-830a-bb4f91200bee)


如果直接扫描原始请求，会触发WAF拦截  
<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0c5434cb-9dcb-4d4b-94b1-dfc24fc5ed07">

加密后waf没法再识别，如果还原了加密算法，也就间接的绕过了waf（但是，除了前置的waf，应用程序自身也会对参数做合法性校验）  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/c1fa5396-048a-4391-923b-2c0e2fb03104)


控制台打印加密的payload  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/d669d010-ac83-4954-81ff-8c4afdcf4420)


于是可以结合漏扫工具做半自动的安全测试（逻辑漏洞还是需要手工测试），示意图如下  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/33bd3f01-5c32-4744-880b-2da217f17da7)


1、burpA中联动Xray  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0a369147-2a67-4086-8d7b-98643cdbc10d)


2、开启联动Xray的开关  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/ad036a47-22ce-4a04-8d46-30b3d1279bbf)


3、这个开关用于控制是否对明文请求包做加密，在联动Xray时，需要给Xray明文包，所以开启后从burpA重放的明文请求包不做加密，直接给Xray去做payload构造  


4、设置Xray的代理  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/2e948eb6-06ca-46df-84dd-d63dcf3e60d9)


5、burpB作为Xray的代理  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/9a93daba-9eb5-41db-8495-10619129ead5)


6、将插件代码拷贝一份，打包为另一个插件，作为联动Xray的专用插件。其他代码不用动，只修改BurpExtender.java中processHttpMessage方法代码：只处理经过Proxy的http流量，做两件事：加密请求body，解密响应body  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/57d9607f-70e8-4901-a7cd-6661c2ad45c8)


7、启动Xray监听127.0.0.1:7777, 在burpA的Repeater中重放明文请求包  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/71aadd5b-26f4-4f9c-90db-611294f97e01)


8、Xrays收到burpA的明文请求，在明文包构造payload，开始扫描，从Xray日志可以看到，未触发WAF  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/d9f42084-4462-4bfb-8054-552238a13eaa)

如果直接扫描原始请求，会触发WAF拦截

<img width="640" alt="image" src="https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/0c5434cb-9dcb-4d4b-94b1-dfc24fc5ed07">


9、burpB收到Xray的明文请求，加密请求中明文中包含payload的body再发给服务端，扫描器能正常工  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/cd133ad4-8d59-4374-b0b6-a8799006b163)


10、查看控制台打印的密文body：  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/b3288b76-c9df-4974-b9ef-94b23b9d0b3f)


11、burpB解密响应的密文body后返回给Xray，从状态码和返回包可以看到未触发WAF拦截，Xray再根据明文响应包内容判断是否存在漏洞  
![image](https://github.com/hbdxmz/AutoBypassEncryptAndSign/assets/94107024/f52fe3e4-8f85-4ca4-a39e-cd18dab25f02)
