# Java安全编码规范

## 防止SQL注入

SQL注入是一种常见攻击方式，由于开发者采用sql 拼凑的方式，用来自网络中不安全的参数形成sql 语句访问数据库， 攻击者常常采用该漏洞组合成非法的sql 语句，使得信息泄露， 访问到本来没有权限查看的内容或者直接破坏数据库信息等。发生SQL Injection 有以下几种方式：

- 进入程序的数据来自不可信赖的资源。
- 数据用于动态构造一个SQL查询。

应对措施：

- 开发者可以采用带参方式访问sql 语句访问数据库，在java 中即采用PreparedStatement 的方式访问数据库。
- 如果开发者一定要使用sql 拼凑的方式访问数据， 对字符串要检查并过滤单引号&#39; , 对于可能为整形或者浮点类型参数，要先转整形，或者浮点，再进行拼凑。

### 不合规代码示例

此不合规代码示例用于系统认证用户密码。密码作为char数组传递，创建数据库连接，然后对密码进行哈希。

此代码示例通过将未定义的输入参数username并入SQL命令中允许SQL注入攻击，允许攻击者注入validuser&#39; OR &#39;1&#39;=&#39;1。该password参数不能使用，因为它被传递给hashPassword()，该方法对输入进行了过滤。
```java
class Login {

  public Connection getConnection() throws SQLException {

    DriverManager.registerDriver(new

            com.microsoft.sqlserver.jdbc.SQLServerDriver());

    String dbConnection =

      PropertyManager.getProperty(&quot;db.connection&quot;);

    // Can hold some value like

    // &quot;jdbc:microsoft:sqlserver://&lt;HOST&gt;:1433,&lt;UID&gt;,&lt;PWD&gt;&quot;

    return DriverManager.getConnection(dbConnection);

  }

  String hashPassword(char[] password) {

    // Create hash of password

  }

  public void doPrivilegedAction(String username, char[] password)

                                 throws SQLException {

    Connection connection = getConnection();

    if (connection == null) {

      // Handle error

    }

    try {

      String pwd = hashPassword(password);

      String sqlString = &quot;SELECT \* FROM db\_user WHERE username = &#39;&quot;

                         + username +

                         &quot;&#39; AND password = &#39;&quot; + pwd + &quot;&#39;&quot;;

      Statement stmt = connection.createStatement();

      ResultSet rs = stmt.executeQuery(sqlString);
```
```java
String userid = (String)session.getAttribute(&quot;classname&quot;);

String param1= request.getParameter( &quot;param1&quot;);

StringBuffer strbuf=new StringBuffer();

strbuf.append( &quot;select \* from table1 where userid= &quot;);

strbuf.append(userid);

strbuf.append( &quot; and param1= &#39;&quot; ).append(param1).append( &quot;&#39;&quot; );

String sql=strbuf.toString();

// 当param1为 test &#39; or 1=1

那么这条语句就为 select \* from table1 where userid=$userid and

param1=&#39;test &#39; or 1=1 这样查询出来的数据就超越了这个用户访问的范围。
```
### 合规解决方案（PreparedStatement）

正确解决方案应该使用带有?字符作为参数的占位符的参数查询。此代码还验证username参数的长度，防止攻击者提交任意长的用户名。
```java
    Connection connection = getConnection();

    if (connection == null) {

      // Handle error

    }

    try {

      String pwd = hashPassword(password);

      // Validate username length

      if (username.length() &gt; 8) {

        // Handle error

      }

      String sqlString =

        &quot;select \* from db\_user where username=? and password=?&quot;;

      PreparedStatement stmt = connection.prepareStatement(sqlString);

      stmt.setString(1, username);

      stmt.setString(2, pwd);

      ResultSet rs = stmt.executeQuery();
```
使用类的set\*()方法PreparedStatement强制执行强类型检查。此技术可减轻SQL注入  [漏洞](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-vulnerabi)，因为输入可通过双引号中的自动陷阱正确转义。对于将数据插入数据库的查询，也必须使用PreparedStatement。

### 合规解决方案（ESAPI）

使用ESAPI进行参数验证
```java
//ESAPI versionofquery

Codec ORACLE\_CODEC=new OracleCodec();

//we&#39;re using oracle

String query=&quot;SELECT name FROM users WHERE id=&quot;+

        ESAPI.encoder().encodeForSQL(ORACLE\_CODEC,validatedUserId)+&quot;

        AND date\_created&gt;=&#39;&quot;+

        ESAPI.encoder().encodeForSQL(ORACLE\_CODEC,validatedStartDate)+&quot;&#39;&quot;;

myStmt=conn.createStatement(query);

//execute statement and get results
```
## 防止XML注入

可扩展标记语言（XML）旨在帮助存储，结构化和传输数据。由于其平台独立性，灵活性和相对简单性，XML已经在广泛的应用中使用。然而，由于其多功能性，XML容易受到广泛的攻击，包括XML注入。

用户可以通过输入的字符串注入XML标签，然后被合并到xml文件中。这些标记由XML解析器解释，并可能导致数据被覆盖。

允许用户指定购买数量的在线商店应用程序可能会生成以下XML文档：
```
<item> 
    <description>Widget</description> 
    <price>500.0</price> 
    <quantity>1</quantity>
</item>
```

攻击者可能输入以下字符串，而不是数量的计数：
```
1</quantity><price>1.0</price><quantity>1
```
在这种情况下，XML解析为以下内容：
```
<item> 
    <description>Widget</description> 
    <price>500.0</price> 
    <quantity>1</quantity>
    <price>1.0</price>
    <quantity>1</quantity>
</item>
```
XML解析器可以解释此示例中的XML，使得第二价格字段覆盖第一价格字段，将项目的价格改为1。

### 不合规代码示例

在这个不合规的代码示例中，客户端使用简单的字符串拼接构建XML查询以发送到服务器。如果该方法不执行输入验证，可能发生XML注入。
```java
import java.io.BufferedOutputStream;

import java.io.ByteArrayOutputStream;

import java.io.IOException;

public class OnlineStore {

  private static void createXMLStreamBad(final BufferedOutputStream outStream,

      final String quantity) throws IOException {

    String xmlString = &quot;&lt;item&gt;\n&lt;description&gt;Widget&lt;/description&gt;\n&quot;

        + &quot;&lt;price&gt;500&lt;/price&gt;\n&quot; + &quot;&lt;quantity&gt;&quot; + quantity

        + &quot;&lt;/quantity&gt;&lt;/item&gt;&quot;;

    outStream.write(xmlString.getBytes());

    outStream.flush();

  }

}
```
### 合规解决方案（输入验证）

根据发送数据的特定数据和命令解释器或解析器，必须使用适当的方法来 [清理](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary)不受信任的用户输入。此合规解决方案验证quantity是无符号整数：
```java
import java.io.BufferedOutputStream;

import java.io.ByteArrayOutputStream;

import java.io.IOException;

public class OnlineStore {

  private static void createXMLStream(final BufferedOutputStream outStream,

      final String quantity) throws IOException, NumberFormatException {

    // Write XML string only if quantity is an unsigned integer (count).

    int count = Integer.parseUnsignedInt(quantity);

    String xmlString = &quot;&lt;item&gt;\n&lt;description&gt;Widget&lt;/description&gt;\n&quot;

        + &quot;&lt;price&gt;500&lt;/price&gt;\n&quot; + &quot;&lt;quantity&gt;&quot; + count + &quot;&lt;/quantity&gt;&lt;/item&gt;&quot;;

    outStream.write(xmlString.getBytes());

    outStream.flush();

  }

}
```
### 合规解决方案（XML模式）

用于检查尝试注入的XML的更通用的机制是使用文档类型定义（DTD）或schema来验证它。必须严格定义schema，以防止被注入。这里是一个合适的schema来验证我们的XML片段：
```
<xs:schema xmlns:xs=" http://www.w3.org/2001/XMLSchema"><xs:element name="item"> <xs:complexType> <xs:sequence> <xs:element name="description" type="xs:string"/> <xs:element name="price" type="xs:decimal"/> <xs:element name="quantity" type="xs:nonNegativeInteger"/> </xs:sequence> </xs:complexType></xs:element></xs:schema>
```
Schema保存为文件schema.xsd。使用这个schema来防止XML注入。
```java
import java.io.BufferedOutputStream;

import java.io.ByteArrayOutputStream;

import java.io.File;

import java.io.IOException;

import java.io.StringReader;

import javax.xml.XMLConstants;

import javax.xml.parsers.ParserConfigurationException;

import javax.xml.parsers.SAXParser;

import javax.xml.parsers.SAXParserFactory;

import javax.xml.transform.stream.StreamSource;

import javax.xml.validation.Schema;

import javax.xml.validation.SchemaFactory;

import org.xml.sax.InputSource;

import org.xml.sax.SAXException;

import org.xml.sax.SAXParseException;

import org.xml.sax.XMLReader;

import org.xml.sax.helpers.DefaultHandler;

public class OnlineStore {

  private static void createXMLStream(final BufferedOutputStream outStream,

      final String quantity) throws IOException {

    String xmlString;

    xmlString = &quot;&lt;item&gt;\n&lt;description&gt;Widget&lt;/description&gt;\n&quot;

        + &quot;&lt;price&gt;500.0&lt;/price&gt;\n&quot; + &quot;&lt;quantity&gt;&quot; + quantity

        + &quot;&lt;/quantity&gt;&lt;/item&gt;&quot;;

    InputSource xmlStream = new InputSource(new StringReader(xmlString));

    // Build a validating SAX parser using our schema

    SchemaFactory sf = SchemaFactory

        .newInstance(XMLConstants.W3C\_XML\_SCHEMA\_NS\_URI);

    DefaultHandler defHandler = new DefaultHandler() {

      public void warning(SAXParseException s) throws SAXParseException {

        throw s;

      }

      public void error(SAXParseException s) throws SAXParseException {

        throw s;

      }

      public void fatalError(SAXParseException s) throws SAXParseException {

        throw s;

      }

    };

    StreamSource ss = new StreamSource(new File(&quot;schema.xsd&quot;));

    try {

      Schema schema = sf.newSchema(ss);

      SAXParserFactory spf = SAXParserFactory.newInstance();

      spf.setSchema(schema);

      SAXParser saxParser = spf.newSAXParser();

      // To set the custom entity resolver,

      // an XML reader needs to be created

      XMLReader reader = saxParser.getXMLReader();

      reader.setEntityResolver(new CustomResolver());

      saxParser.parse(xmlStream, defHandler);

    } catch (ParserConfigurationException x) {

      throw new IOException(&quot;Unable to validate XML&quot;, x);

    } catch (SAXException x) {

      throw new IOException(&quot;Invalid quantity&quot;, x);

    }

    // Our XML is valid, proceed

    outStream.write(xmlString.getBytes());

    outStream.flush();

  }

}
```
使用Schema或DTD来验证XML时很方便。

## 防止资源注入

允许用户可以通过输入来控制资源标识符，会让攻击者有能力访问或修改被保护的系统资源。

发生resource injection 有以下两种方式：

1. 攻击者可以指定已使用的标识符来访问系统资源。例如，攻击者可以指定

用来连接到网络资源的端口号。

2. 攻击者可以通过指定特定资源来获取某种能力， 而这种能力在一般情况下

是不可能获得的。

### 不合规代码示例
```java
String dsn = request.getParameter(&quot;DSN&quot;);

DataSource ds = (DataSource) ctx.lookup( dsn);
```
### 合规解决方案

开发者可以定制一份白名单，通过关键字关联需要资源内容， http 请求中传

递是不是实际的资源内容， 而是关键字， 开发者得到关键字后在白名单中寻找需

要的信息，进行后续操作。
```java
String dsnKey = request.getParameter(&quot;DSN &quot;);

String dsn =WhiteList.get(dsnKey);

DataSource ds = (DataSource) ctx.lookup( dsn);
```
### 合规解决方案（ESAPI）

使用ESAPI的AccessReferenceMap 实现使用非直接的对象引用
```java
MyObject obj;//generate your object

Collection coll;//holds objects for displayinUI

//create ESAPI random access reference map

AccessReferenceMap map=new RandomAccessReferenceMap();

//get indirect reference using direct reference as seed input

String indirectReference=map.addDirectReference(obj.getId());

//set indirect reference for each object-requires your app object to have this method

bj.setIndirectReference(indirectReference);

//add object to display collection

coll.add(obj);

//store collection in request/session and forward to UI
```
## 防止跨站请求伪造

跨站请求伪造，也被称成为&quot;oneclickattack&quot; 或者sessionriding ，通常缩写为CSRF或者XSRF，是一种对网站的恶意利用。尽管听起来像跨站脚本（ XSS），但它与XSS非常不同，并且攻击方式几乎相左。XSS利用站点内的信任用户，而CSRF则通过伪装来自受信任用户的请求来利用受信任的网站。与XSS攻击相比， CSRF攻击往往不大流行（因此对其进行防范的资源也相当稀少）和难以防范，所以被认为比XSS更具危险性。

攻击者能让受害用户修改可以修改的任何数据，或者是执行允许使用的任何功能。

### 合规解决方案（ESAPI）

新建CSRF令牌添加进用户每次登陆以及存储在httpsession 里，这种令牌至少对每个用户会话来说应该是唯一的，或者是对每个请求是唯一的。
```java
//this code is in the DefaultUser implementation of ESAPI

Private String csrfToken = resetCSRFToken();

Public String resetCSRFToken(){

csrfToken=ESAPI.randomizer().getRandomString(8,DefaultEncoder.CHAR\_ALPHANUMERICS);

return csrfToken;

}
```
使用ESAPI的AccessReferenceMap 实现使用非直接的对象引用
```java
MyObject obj;//generate your object

Collection coll;//holds objects for displayinUI

//create ESAPI random access reference map

AccessReferenceMap map=new RandomAccessReferenceMap();

//get indirect reference using direct reference as seed input

String indirectReference=map.addDirectReference(obj.getId());

//set indirect reference for each object-requires your app object to have this method

bj.setIndirectReference(indirectReference);

//add object to display collection

coll.add(obj);
```
//store collection in request/session and forward to UI

令牌可以包含在URL中或作为一个URL参数记/ 隐藏字段。
```
//from HTTP Utilitiles interface

Final static String CSRF\_TOKEN\_NAME=&quot;ctoken&quot;;

//this code is from the Default HTTP Utilities implementation in ESAPI

Public String addCSRFToken(Stringhref){

        User user=ESAPI.authenticator().getCurrentUser();

        if(user.isAnonymous()){returnhref;}

        //if there are already parameters append with&amp;,otherwise append with?

        String token=CSRF\_TOKEN\_NAME+&quot;=&quot;+user.getCSRFToken();

        return href.indexOf(&#39;?&#39;)!=-1?href+&quot;&amp;&quot;+token:href+&quot;?&quot;+token;

}

public StringgetCSRFToken(){

        User user=ESAPI.authenticator().getCurrentUser();

        if(user==null) return null;return user.getCSRFToken();

}
```
在服务器端检查提交令牌与用户会话对象令牌是否匹配。
```
//this code is from the Defaul tHTTP Utilities implementation in ESAPI

Public void verifyCSRFToken(HttpServletRequest request)throws IntrusionException{

        User user=ESAPI.authenticator().getCurrentUser();

        //check if user authenticated with this request-noCSRFprotection required

        if(request.getAttribute(user.getCSRFToken())!=null){

                return;

                }

        String token=request.getParameter(CSRF\_TOKEN\_NAME);

        if(!user.getCSRFToken().equals(token)){

                throw new IntrusionException(&quot;Authenticationfailed&quot;,

                &quot;Possibly forgeted HTTP request without proper CSRFtokendetected&quot;);

        }

}
```
在注销和会话超时，删除用户对象会话和会话销毁。
```
//this code is in the DefaultUser implementation of ESAPI

Public void logout(){

        ESAPI.httpUtilities().killCookie(ESAPI.currentResponse(),ESAPI.currentRequest(),

        HTTPUtilities.REMEMBER\_TOKEN\_COOKIE\_NAME);

        HttpSession session=ESAPI.currentRequest().getSession(false);

        if(session!=null){

                removeSession(session);

                session.invalidate();

        }

        ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(),

        ESAPI.currentResponse(),&quot;JSESSIONID&quot;);

        loggedIn=false;

        logger.info(Logger.SECURITY\_SUCCESS,&quot;Logout successful&quot;);

        ESAPI.authenticator().setCurrentUser(User.ANONYMOUS);

}
```
## 防止跨站脚本XSS

跨站脚本XSS指利用网站漏洞从用户那里恶意盗取信息。用户在浏览网站、使用即时通讯软件、甚至在阅读电子邮件时， 通常会点击其中的链接。攻击者通过在链接中插入恶意代码，就能够盗取用户信息。攻击者通常会用十六进制（或其他编码方式） 将链接编码， 以免用户怀疑它的合法性。网站在接收到包含恶意代码的请求之后会产成一个包含恶意代码的页面，而这个页面看起来就像是那个网站应当生成的合法页面一样。许多流行的留言本和论坛程序允许用户发表包含HTML 和javascript 的帖子。假设用户甲发表了一篇包含恶意脚本的帖子， 那么用户乙在浏览这篇帖子时，恶意脚本就会执行，盗取用户乙的session信息。如何导致XSS攻击，一般来说来自http 的post ，或者get 方式取得参数值很可能为恶意代码，如果开发者直接用这些参数组合成http 链接，用户点击该连接，就会造成XSS攻击风险。

应对措施

开发者要保证代码的安全性，使其免受XSS 攻击，可采取以下措施：

- 过滤或转换用户提交数据中的HTML代码。
- 限制用户提交数据的长度

### 不合规代码示例
```java
 String userId = request.getParameter(&quot;sid&quot;);
```
### 合规解决方案（ESAPI）

使用ESAPI进行输入验证
```java
String validatedFirstName=ESAPI.validator().getValidInput(&quot;FirstName&quot;,

        myForm.getFirstName(),&quot;FirstNameRegex&quot;,255,false,errorList);

boolean isValidFirstName=ESAPI.validator().isValidInput(&quot;FirstName&quot;,

        myForm.getFirstName(),&quot;FirstNameRegex&quot;,255,false);
```
使用ESAPI进行输出编码
```java
//performinginputvalidation

String cleanCommen = ESAPI.validator().getValidInput(&quot;comment&quot;,

        request.getParameter(&quot;comment&quot;),&quot;CommentRegex&quot;,300,false,errorList);

//checktheerrorListhere......//performingoutputencodingfortheHTMLcontext

String safeOutput= ESAPI.encoder().encodeForHTML(cleanComment);
```
## 防止恶意文件上传

恶意文件执行是一种能够威胁任何网站形式的漏洞，只要攻击者在具有引入（ include ）功能程式的参数中修改参数内容， WEB服务器便会引入恶意程序内容从而受到恶意文件执行漏洞攻击。

攻击者可利用恶意文件执行漏洞进行攻击取得WEB服务器控制权， 进行不法利益或获取经济利益。

### 合规解决方案（ESAPI）

使用ESAPI进行上传文件名验证
```java
if(!ESAPI.validator().isValidFileName(&quot;upload&quot;,filename,allowedExtensions,false)){

        throw new Validation UploadException(&quot;Upload only simple filenames with

        the following extensions&quot;+allowedExtensions,&quot;Upload failed isValidFileName check&quot;);

}
```
使用ESAPI检查上传文件大小
```java
ServletFileUpload upload=newServletFileUpload(factory);

upload.setSizeMax(maxBytes) ；
```
## 在验证字符串之前对其进行规范化

许多接受不可信输入字符串的应用程序使用基于字符串字符数据的输入过滤和验证机制。例如，应用程序避免跨站点脚本（XSS）漏洞的策略可能包括禁止输入中的&lt;script&gt;标签。这种黑名单机制是安全策略的有用部分，即使它们不足以用于完整的输入验证和过滤。

Java中的字符信息基于Unicode标准。下表显示了Java SE的最新三个版本支持的Unicode版本。

| **Java版本** | **Unicode版本** |
| --- | --- |
| Java SE 6 | Unicode标准版本4.0 [  [Unicode 2003](https://www.securecoding.cert.org/confluence/display/java/Rule+AA.+References#RuleAA.References-Unicode2003) ] |
| Java SE 7 | Unicode Standard，版本6.0.0 [  [Unicode 2011](https://www.securecoding.cert.org/confluence/display/java/Rule+AA.+References#RuleAA.References-Unicode2011) ] |
| Java SE 8 | Unicode标准版本6.2.0 [  [Unicode 2012](https://www.securecoding.cert.org/confluence/display/java/Rule+AA.+References#RuleAA.References-Unicode2012) ] |

接受不受信任的输入时，验证之前需对输入进行标准化。规范化很重要，因为在Unicode中，同一个字符串可以有许多不同的表示。

### 不合规代码示例

Normalizer.normalize() 方法将Unicode文本转换为 [Unicode Standard Annex #15 Unicode Normalization Forms ](http://www.unicode.org/reports/tr15/tr15-23.html)中描述的   [标准规范化形式](http://www.unicode.org/reports/tr15/tr15-23.html)。 通常，用于对任意编码的字符串执行输入验证时最常用的规范化标准是KC（NFKC）。

此不合规代码示例在执行标准化之前验正了String。

| // String s may be user controllable// \uFE64 is normalized to &lt; and \uFE65 is normalized to &gt; using the NFKC normalization formString s = &quot;\uFE64&quot; + &quot;script&quot; + &quot;\uFE65&quot;;// ValidatePattern pattern = Pattern.compile(&quot;[&lt;&gt;]&quot;); // Check for angle bracketsMatcher matcher = pattern.matcher(s);if (matcher.find()) {  // Found black listed tag  throw new IllegalStateException();} else {  // ...}// Normalizes = Normalizer.normalize(s, Form.NFKC); |
| --- |

验证逻辑无法检测&lt;script&gt;标记，因为它在此时未标准化，系统接受了问题输入。

### 合规解决方案

此解决方案在验证字符串之前先将其规范化。替代的字符串被规范化为尖括号。因此，输入验证正确地检测恶意输入并抛出IllegalStateException。
```java
String s = &quot;\uFE64&quot; + &quot;script&quot; + &quot;\uFE65&quot;;

// Normalize

s = Normalizer.normalize(s, Form.NFKC);

// Validate

Pattern pattern = Pattern.compile(&quot;[&lt;&gt;]&quot;);

Matcher matcher = pattern.matcher(s);

if (matcher.find()) {

  // Found blacklisted tag

  throw new IllegalStateException();

} else {

  // ...

}
```
## 验证Runtime.exec()方法

应用程序通常会调用外部程序提供的功能。这种做法是一种重用的形式，甚至可以被认为是一种基于组件的软件工程的粗略形式。当应用程序无法 [清理](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-sa)不受信任的输入并在外部程序的执行中使用它时，会发生命令和参数注入 [漏洞](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-vulnerab)。

任何源自程序的信任边界外部的字符串数据必须在作为当前平台上的命令执行之前进行清理。

### 不合规代码示例（Windows）

此不合规代码示例使用dir命令提供了目录列表。它是使用Runtime.exec()调用Windows dir命令实现的。
```java
class DirList {

  public static void main(String[] args) throws Exception {

    String dir = System.getProperty(&quot;dir&quot;);

    Runtime rt = Runtime.getRuntime();

    Process proc = rt.exec(&quot;cmd.exe /C dir &quot; + dir);

    int result = proc.waitFor();

    if (result != 0) {

      System.out.println(&quot;process error: &quot; + result);

    }

    InputStream in = (result == 0) ? proc.getInputStream() :

                                     proc.getErrorStream();

    int c;

    while ((c = in.read()) != -1) {

      System.out.print((char) c);

    }

  }

}
```

因为Runtime.exec()接收源自环境的未定义的数据，此代码易受命令注入攻击。

攻击者可以使用以下命令来 [利用](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary)此程序：

| java -Ddir=&#39;dummy &amp; echo bad&#39; Java |
| --- |

执行的命令实际上是两个命令：

| cmd.exe /C dir dummy &amp; echo bad |
| --- |

其首先尝试列出不存在的dummy文件夹，然后打印bad到控制台。

### 不合规代码示例（POSIX）

这个不合规的代码示例提供了相同的功能，但使用POSIX ls命令。与Windows版本的唯一区别是传递给的参数Runtime.exec()。
```java
class DirList {

  public static void main(String[] args) throws Exception {

    String dir = System.getProperty(&quot;dir&quot;);

    Runtime rt = Runtime.getRuntime();

    Process proc = rt.exec(new String[] {&quot;sh&quot;, &quot;-c&quot;, &quot;ls &quot; + dir});

    int result = proc.waitFor();

    if (result != 0) {

      System.out.println(&quot;process error: &quot; + result);

    }

    InputStream in = (result == 0) ? proc.getInputStream() :

                                     proc.getErrorStream();

    int c;

    while ((c = in.read()) != -1) {

      System.out.print((char) c);

    }

  }

}
```

攻击者可以提供与前面代码示例中显示效果。实际上执行的命令

 sh -c &#39;ls dummy &amp; echo bad&#39; 


### 合规解决方案（过滤）

该解决方案对用户输入进行过滤，然后传递给Runtime.exec(); 所有其他字符被排除。
```java
// ...

if (!Pattern.matches(&quot;[0-9A-Za-z@.]+&quot;, dir)) {

  // Handle error

}

// ...
```

### 合规解决方案（受限用户选择）

此合规解决方案通过仅将可信字符串传递到防止命令注入Runtime.exec()。用户可以控制使用哪个字符串，但不能直接提供字符串数据Runtime.exec()。
```java
// ...

String dir = null;

int number = Integer.parseInt(System.getProperty(&quot;dir&quot;)); // Only allow integer choices

switch (number) {

  case 1:

    dir = &quot;data1&quot;;

    break; // Option 1

  case 2:

    dir = &quot;data2&quot;;

    break; // Option 2

  default: // Invalid

    break;

}

if (dir == null) {

  // Handle error

}
```

此合规解决方案硬编码可能列出的目录。

如果您有许多可用的目录，此解决方案可能会迅速变得无法管理。一个更可扩展的解决方案是将所有允许的目录从属性文件读入java.util.Properties对象。

### 合规解决方案（避免Runtime.exec()）

当通过执行系统命令执行的任务可以通过某种其他方式来完成时，应该优先选择。此合规解决方案使用该File.list()方法提供目录列表，消除命令或参数注入攻击的可能性。
```java
import java.io.File;

class DirList {

  public static void main(String[] args) throws Exception {

    File dir = new File(System.getProperty(&quot;dir&quot;));

    if (!dir.isDirectory()) {

      System.out.println(&quot;Not a directory&quot;);

    } else {

      for (String file : dir.list()) {

        System.out.println(file);

      }

    }

  }

}

```

## 清理正则表达式中包含的恶意数据

正则表达式（regex）广泛用于匹配文本字符串。例如，POSIX grep实用程序支持用于在指定文本中查找模式的正则表达式。

Java的强大的正则表达式设施必须防止滥用。攻击者可能修改原始正则表达式，使得正则表达式不能符合程序的规范。这种攻击向量，称为_正则表达式注入_，可能会影响控制流，导致信息泄露或导致 [拒绝服务](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-denial-of-serviceattack)（DoS）漏洞。

不可信输入应在使用前进行 [清理](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-sanitize)，以防止正则表达式注入。程序员必须仅向用户提供非常有限的正则表达式功能的子集，以最小化任何误用的机会。

### 正则表达式注入示例

假设系统日志文件包含由各种系统进程输出的消息。一些进程产生公共消息，一些进程产生标记为&quot;私有&quot;的敏感消息。这里是一个示例日志文件：

| 10:47:03 private[423] Successful logout  name: usr1 ssn: 11122333310:47:04 public[48964] Failed to resolve network service10:47:04 public[1] (public.message[49367]) Exited with exit code: 25510:47:43 private[423] Successful login  name: usr2 ssn: 44455666610:48:08 public[48964] Backup failed with error: 19 |
| --- |

用户希望在日志文件中搜索消息，但必须防止看到私人消息。程序可以通过允许用户提供成为以下正则表达式一部分的搜索文本来实现此目的：

(.\*? +public\[\d+\] +.\*&lt;SEARCHTEXT&gt;.\*)


但是，如果攻击者可以替换任何字符串&lt;SEARCHTEXT&gt;，他可以使用以下文本执行正则表达式注入：

.\*)|(.\*


当注入到正则表达式中时，正则表达式变成

(.\*? +public\[\d+\] +.\*.\*)|(.\*.\*)


这个正则表达式将匹配日志文件中的任何行，包括私有的。

### 不合规代码示例

此不合规代码示例使用不受信任的用户的搜索字词搜索日志文件：
```java
import java.io.FileInputStream;

import java.io.IOException;

import java.nio.CharBuffer;

import java.nio.MappedByteBuffer;

import java.nio.channels.FileChannel;

import java.nio.charset.Charset;

import java.nio.charset.CharsetDecoder;

import java.util.regex.Matcher;

import java.util.regex.Pattern;

public class LogSearch {

        public static void FindLogEntry(String search) {

                // Construct regex dynamically from user string

                String regex = &quot;(.\*? +public\\[\\d+\\] +.\*&quot; + search + &quot;.\*)&quot;;

                Pattern searchPattern = Pattern.compile(regex);

                try (FileInputStream fis = new FileInputStream(&quot;log.txt&quot;)) {

                        FileChannel channel = fis.getChannel();

                        // Get the file&#39;s size and map it into memory

                        long size = channel.size();

                        final MappedByteBuffer mappedBuffer = channel.map(

                                        FileChannel.MapMode.READ\_ONLY, 0, size);

                        Charset charset = Charset.forName(&quot;ISO-8859-15&quot;);

                        final CharsetDecoder decoder = charset.newDecoder();

                        // Read file into char buffer

                        CharBuffer log = decoder.decode(mappedBuffer);

                        Matcher logMatcher = searchPattern.matcher(log);

                        while (logMatcher.find()) {

                                String match = logMatcher.group();

                                if (!match.isEmpty()) {

                                        System.out.println(match);

                                }

                        }

                } catch (IOException ex) {

                        System.err.println(&quot;thrown exception: &quot; + ex.toString());

                        Throwable[] suppressed = ex.getSuppressed();

                        for (int i = 0; i &lt; suppressed.length; i++) {

                                System.err.println(&quot;suppressed exception: &quot;

                                                + suppressed[i].toString());

                        }

                }

                return;

        }
```

此代码允许攻击者执行正则表达式注入。

### 合规解决方案（白名单）

此合规解决方案对搜索字词进行清理，过滤掉非字母数字字符（空格和单引号除外）：
```java
        public static void FindLogEntry(String search) {

                // Sanitize search string

                StringBuilder sb = new StringBuilder(search.length());

                for (int i = 0; i &lt; search.length(); ++i) {

                        char ch = search.charAt(i);

                        if (Character.isLetterOrDigit(ch) || ch == &#39; &#39; || ch == &#39;\&#39;&#39;) {

                                sb.append(ch);

                        }

                }

                search = sb.toString();

                // Construct regex dynamically from user string

                String regex = &quot;(.\*? +public\\[\\d+\\] +.\*&quot; + search + &quot;.\*)&quot;;

        // ...

    }

```

此解决方案阻止正则表达式注入，但 也限制搜索术语。例如，用户不能再搜索&quot; name =&quot;，因为从搜索项中去除了非字母数字字符。

### 合规解决方案（Pattern.quote()）

此方案 通过使用Pattern.quote()以转义搜索字符串中的任何恶意字符来 [清理](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-sanitize)搜索项。与以前方案不同，使用标点符号的搜索字符串，例如&quot;name =&quot; 将被允许.
```java
        public static void FindLogEntry(String search) {

                // Sanitize search string

        search = Pattern.quote(search);

                // Construct regex dynamically from user string

                String regex = &quot;(.\*? +public\\[\\d+\\] +.\*&quot; + search + &quot;.\*)&quot;;

        // ...

    }
```

 Matcher.quoteReplacement()方法可以用于转义字符串。

## 不允许异常暴露敏感信息

在异常输出时未能过滤敏感信息会导致信息泄露，有助于攻击者进一步攻击。攻击者可以构造输入参数以暴露应用程序的内部结构和机制。异常消息文本和异常的类型都可能泄漏信息。例如，FileNotFoundException消息显示有关文件系统布局的信息，异常类型显示不存在请求的文件。

程序必须过滤可跨信任边界传播的异常消息和异常类型。下表列出了几个有问题的异常。

| **异常名称** | **信息泄漏威胁** |
| --- | --- |
| java.io.FileNotFoundException | 底层文件系统结构，用户名枚举 |
| java.sql.SQLException | 数据库结构，用户名枚举 |
| java.net.BindException | 枚举打开的端口，当不受信任的客户端可以选择服务器端口 |
| java.util.ConcurrentModificationException | 可以提供有关线程不安全代码的信息 |
| javax.naming.InsufficientResourcesException | 服务器资源不足（可能会帮助DoS） |
| java.util.MissingResourceException | 资源枚举 |
| java.util.jar.JarException | 底层文件系统结构 |
| java.security.acl.NotOwnerException | 所有者枚举 |
| java.lang.OutOfMemoryError | DoS |
| java.lang.StackOverflowError | DoS |

打印堆栈还可能导致意外泄漏有关进程的结构和状态的信息给攻击者。当在控制台中运行的Java程序由于未捕获异常而终止时，异常的消息和堆栈将显示在控制台上; 堆栈本身可以包含关于程序的内部结构的敏感信息。

### 不兼容的代码示例（从异常消息和类型泄漏）

在这个不合规的代码示例中，程序必须读取用户提供的文件，但文件系统的内容和布局是敏感的。程序接受文件名作为输入参数，但无法防止任何结果异常显示给用户。
```java
class ExceptionExample {

  public static void main(String[] args) throws FileNotFoundException {

    // Linux stores a user&#39;s home directory path in

    // the environment variable $HOME, Windows in %APPDATA%

    FileInputStream fis =

        new FileInputStream(System.getenv(&quot;APPDATA&quot;) + args[0]);

  }

}
```
当所请求的文件不存在时，FileInputStream构造函数抛出一个FileNotFoundException，允许攻击者通过重复地将虚构路径名传递给程序来重建底层文件系统。

### 不兼容的代码示例（包装和重新传送敏感异常）

这个不合规的代码示例Log异常，然后在重新抛出异常之前将其包装在更常见的异常中：
```java
try {

  FileInputStream fis =

      new FileInputStream(System.getenv(&quot;APPDATA&quot;) + args[0]);

} catch (FileNotFoundException e) {

  // Log the exception

  throw new IOException(&quot;Unable to retrieve file&quot;, e);

}
```
即使日志中异常对用户不可访问时，原始异常仍然是信息性的，并且可以被攻击者用来发现关于文件系统布局的敏感信息。

### 不合规代码示例（自定义异常）

这个不合规的代码示例记录了异常并抛出一个自定义异常：
```java
class SecurityIOException extends IOException {/\* ... \*/};

try {

  FileInputStream fis =

      new FileInputStream(System.getenv(&quot;APPDATA&quot;) + args[0]);

} catch (FileNotFoundException e) {

  // Log the exception

  throw new SecurityIOException();

}
```
虽然此异常比以前的不合规代码示例泄露有用信息的可能性更小，但它仍然显示指定的文件无法读取。更具体地说，程序对不存在的文件路径和有效文件路径有不同的反应，并且攻击者仍然可以从该程序的异常中推断出关于文件系统的敏感信息。未能限制用户输入使系统容易受到暴力攻击。

### 合规解决方案（安全策略）

此合规解决方案通过安全策略，只有c:\homepath用户可以打开里面的文件，并且不允许用户发现关于此目录之外的文件的任何内容。当无法打开文件或文件不存在于正确的目录中时，会发出简短错误消息。
```java
class ExceptionExample {

  public static void main(String[] args) {

    File file = null;

    try {

      file = new File(System.getenv(&quot;APPDATA&quot;) +

             args[0]).getCanonicalFile();

      if (!file.getPath().startsWith(&quot;c:\\homepath&quot;)) {

        System.out.println(&quot;Invalid file&quot;);

        return;

      }

    } catch (IOException x) {

      System.out.println(&quot;Invalid file&quot;);

      return;

    }

    try {

      FileInputStream fis = new FileInputStream(file);

    } catch (FileNotFoundException x) {

      System.out.println(&quot;Invalid file&quot;);

      return;

    }

  }

}
```
### 合规解决方案（限制输入）

此合规解决方案设置安全策略只允许读取有限的文件。
```java
class ExceptionExample {

  public static void main(String[] args) {

    FileInputStream fis = null;

    try {

      switch(Integer.valueOf(args[0])) {

        case 1:

          fis = new FileInputStream(&quot;c:\\homepath\\file1&quot;);

          break;

        case 2:

          fis = new FileInputStream(&quot;c:\\homepath\\file2&quot;);

          break;

        //...

        default:

          System.out.println(&quot;Invalid option&quot;);

          break;

      }

    } catch (Throwable t) {

      MyExceptionReporter.report(t); // Sanitize

    }

  }

}

}
```
## 避免系统信息泄露

JSP中出现 HTML注释（System Information Leakage：HTMLC ommenitn JSP），

攻击者可以通过html 的注释得到用于攻击的信息。

应对措施：

应该使用JSP注释代替HTML 注释。(JSP注释不会被传递给用户)。

### 不合规代码示例

&lt;! —此处是取得系统信息的注释-&gt;

### 合规解决方案

&lt;%//此处是取得系统信息的注释%&gt;

## 不安全的反射

攻击者能够建立一个不可预测的、贯穿应用程序的控制流程， 使得他们可以潜在地避开安全检测。攻击者能够建立一个在开发者意料之外的、不可预测的控制流程，贯穿应用程序始终。这种形式的攻击能够使得攻击者避开身份鉴定， 或者访问控制检测， 或者使得应用程序以一种意料之外的方式运行。如果攻击者能够将文件上传到应用程序的classpath 或者添加一个classpath 的新入口，那么这将导致应用程序陷入完全的困境。无论是上面哪种情况， 攻击者都能使用反射将新的、多数情况下恶意的行为引入应用程序。

应对措施

### 不合规代码示例
```java
String className = request.getParameter(&quot;classname&quot;);

if ((className != null)&amp;&amp; ((className = className.trim()).length() !=0)) {

// Attempt to load class and get its location.

try {

ProtectionDomain pd = Class.forName(className).getProtectionDomain();

if (pd != null) {

CodeSource cs = pd.getCodeSource();
```
### 合规解决方案

开发者可以定制一份白名单，通过关键字关联需要实例化的类， http 请求中传递是不是实际的类名， 而是关键字， 开发者得到关键字后在白名单中寻找需要的信息，进行实例化。
```java
String classNameKey = request.getParameter(&quot;classname&quot;);

String className=WhiteList.get(classNameKey);

if ((className != null)&amp;&amp; ((className = className.trim()).length() !=0)) {

// Attempt to load class and get its location.

try {

ProtectionDomain pd = Class.forName(className).getProtectionDomain();

if (pd != null) {

CodeSource cs = pd.getCodeSource();
```
## 使用SSLSocket进行安全数据交换

在通过不安全的通信通道传输 [敏感数据](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-sensitived)时，程序必须使用javax.net.ssl.SSLSocket类而不是java.net.Socket类。该类提供安全套接字层/传输层安全（SSL / TLS），以确保该通道不易受到窃听和恶意篡改。

### 不合规代码示例

此不合规代码示例显示了无法保护传输中敏感信息的常规套接字的使用。
```java
// Exception handling has been omitted for the sake of brevity

class EchoServer {

  public static void main(String[] args) throws IOException {

    ServerSocket serverSocket = null;

    try {

      serverSocket = new ServerSocket(9999);

      Socket socket = serverSocket.accept();

      PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

      BufferedReader in = new BufferedReader(

          new InputStreamReader(socket.getInputStream()));

      String inputLine;

      while ((inputLine = in.readLine()) != null) {

        System.out.println(inputLine);

        out.println(inputLine);

      }

    } finally {

      if (serverSocket != null) {

        try {

          serverSocket.close();

        } catch (IOException x) {

          // Handle error

        }

      }

    }

  }

}

class EchoClient {

  public static void main(String[] args)

                          throws UnknownHostException, IOException {

    Socket socket = null;

    try {

      socket = new Socket(&quot;localhost&quot;, 9999);

      PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

      BufferedReader in = new BufferedReader(

          new InputStreamReader(socket.getInputStream()));

      BufferedReader stdIn = new BufferedReader(

          new InputStreamReader(System.in));

      String userInput;

      while ((userInput = stdIn.readLine()) != null) {

        out.println(userInput);

        System.out.println(in.readLine());

      }

    } finally {

      if (socket != null) {

        try {

          socket.close();

        } catch (IOException x) {

          // Handle error

        }

      }

    }

  }

}
```
### 合规解决方案

此合规解决方案用于SSLSocket使用SSL / TLS安全协议保护数据包：
```java
// Exception handling has been omitted for the sake of brevity

class EchoServer {

  public static void main(String[] args) throws IOException {

    SSLServerSocket sslServerSocket = null;

    try {

      SSLServerSocketFactory sslServerSocketFactory =

          (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

      sslServerSocket = (SSLServerSocket) sslServerSocketFactory.

                        createServerSocket(9999);

      SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

      PrintWriter out = new PrintWriter(sslSocket.getOutputStream(),true);

      BufferedReader in = new BufferedReader(

          new InputStreamReader(sslSocket.getInputStream()));

      String inputLine;

      while ((inputLine = in.readLine()) != null) {

        System.out.println(inputLine);

        out.println(inputLine);

      }

    } finally {

      if (sslServerSocket != null) {

        try {

          sslServerSocket.close();

        } catch (IOException x) {

          // Handle error

        }

      }

    }

  }

}

class EchoClient {

  public static void main(String[] args) throws IOException {

    SSLSocket sslSocket = null;

    try {

      SSLSocketFactory sslSocketFactory =

          (SSLSocketFactory) SSLSocketFactory.getDefault();

      sslSocket =

          (SSLSocket) sslSocketFactory.createSocket(&quot;localhost&quot;, 9999);

      PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true);

      BufferedReader in = new BufferedReader(

          new InputStreamReader(sslSocket.getInputStream()));

      BufferedReader stdIn = new BufferedReader(

          new InputStreamReader(System.in));

      String userInput;

      while ((userInput = stdIn.readLine()) != null) {

        out.println(userInput);

        System.out.println(in.readLine());

      }

    } finally {

      if (sslSocket != null) {

        try {

          sslSocket.close();

        } catch (IOException x) {

          // Handle error

        }

      }

    }

  }

}
```
## 生成强随机数

伪随机数发生器（PRNG）使用确定性数学算法来产生具有良好统计特性的数字序列。然而，产生的数字序列不能实现真随机性。PRNG通常以算术种子值开始。该算法使用此种子来生成输出值和新种子。

Java API提供了一个PRNG java.util.Random类。这个PRNG是便携和可重复的。因此，使用相同种子创建java.util.Random类的两个实例将在所有Java实现中生成相同的数字序列。种子值通常在应用程序初始化或每次系统重新启动后重复使用。攻击者可以通过对易受攻击的目标执行一些侦察来学习种子的值，然后可以构建用于估计未来种子值的查找表。

因此，java.util.Random该类不能用于保护 [敏感数据](https://www.securecoding.cert.org/confluence/display/java/Rule+BB.+Glossary#RuleBB.Glossary-sensitiv)。使用更安全的随机数生成器，如java.security.SecureRandom类。

### 不合规代码示例

这个不合规的代码示例使用不安全的java.util.Random类。这个类为每个给定的种子值产生相同的数字序列; 因此，数字序列是可预测的。
```java
import java.util.Random;

// ...

Random number = new Random(123L);

//...

for (int i = 0; i &lt; 20; i++) {

  // Generate another random integer in the range [0, 20]

  int n = number.nextInt(21);

  System.out.println(n);

}
```
### 合规解决方案

此合规解决方案使用java.security.SecureRandom类来产生高质量的随机数：
```java
import java.security.SecureRandom;

import java.security.NoSuchAlgorithmException;

// ...

public static void main (String args[]) {

  SecureRandom number = new SecureRandom();

  // Generate 20 integers 0..20

  for (int i = 0; i &lt; 20; i++) {

    System.out.println(number.nextInt(21));

  }

}
```
### 合规解决方案（Java 8）

此合规解决方案使用SecureRandom.getInstanceStrong() ，以使用强随机算法。
```java
import java.security.SecureRandom;

import java.security.NoSuchAlgorithmException;

// ...

public static void main (String args[]) {

   try {

     SecureRandom number = SecureRandom.getInstanceStrong();

     // Generate 20 integers 0..20

     for (int i = 0; i &lt; 20; i++) {

       System.out.println(number.nextInt(21));

     }

   } catch (NoSuchAlgorithmException nsae) {

     // Forward to handler

   }

}
```
## 不要硬编码敏感信息

密码，服务器IP地址和加密密钥等敏感信息进行硬编码可能会将信息暴露给攻击者。任何有权访问类文件的人都可以反编译它们并发现敏感信息。

### 不合规代码示例

这个不合规的代码示例包括常量中的硬编码服务器IP地址String：
```java
class IPaddress {

  String ipAddress = new String(&quot;172.16.254.1&quot;);

  public static void main(String[] args) {

    //...

  }

}
```
恶意用户可以使用该javap -c IPaddress命令反编译类并发现硬编码的服务器IP地址。反编译器的输出以明文形式显示服务器IP地址172.16.254.1：
```java
Compiled from &quot;IPaddress.java&quot;

class IPaddress extends java.lang.Object{

java.lang.String ipAddress;

IPaddress();

  Code:

   0:     aload\_0

   1:     invokespecial     #1; //Method java/lang/Object.&quot;&lt;init&gt;&quot;:()V

   4:     aload\_0

   5:     new   #2; //class java/lang/String

   8:     dup

   9:     ldc   #3; //String 172.16.254.1

   11:    invokespecial     #4; //Method java/lang/String.&quot;&lt;init&gt;&quot;:(Ljava/lang/String;)V

   14:    putfield    #5; //Field ipAddress:Ljava/lang/String;

   17:    return

public static void main(java.lang.String[]);

  Code:

   0:     return

}

```

### 合规解决方案

将IP地址存储在字符数组而不是字符数组中，并在使用后立即从存储器清除服务器IP地址，进一步限制IP地址的暴露。
```java
class IPaddress {

  public static void main(String[] args) throws IOException {

    char[] ipAddress = new char[100];

    int offset = 0;

    int charsRead = 0;

    BufferedReader br = null;

    try {

      br = new BufferedReader(new InputStreamReader(

             new FileInputStream(&quot;serveripaddress.txt&quot;)));

      while ((charsRead = br.read(ipAddress, offset, ipAddress.length - offset))

          != -1) {

        offset += charsRead;

        if (offset &gt;= ipAddress.length) {

          break;

        }

      }

      // ... Work with IP address

    } finally {

      Arrays.fill(ipAddress,  (byte) 0);

      br.close();

    }

  }

}
```
### 不合规代码示例（硬编码数据库密码）
```java
public final Connection getConnection() throws SQLException {

  return DriverManager.getConnection(

      &quot;jdbc:mysql://localhost/dbName&quot;,

      &quot;username&quot;, &quot;password&quot;);

}
```
### 合规解决方案

此合规解决方案从位于安全目录中的配置文件读取用户名和密码：
```java
public final Connection getConnection() throws SQLException {

  String username;

  String password;

  // Username and password are read at runtime from a secure config file

  return DriverManager.getConnection(

      &quot;jdbc:mysql://localhost/dbName&quot;, username, password);

}
```
敏感信息（如密码）应存储在字符数组而不是字符串中，因为Java虚拟机可能在不再需要字符串后保留字符串。