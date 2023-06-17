package burp;


import java.awt.*;
import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender,IHttpListener,ITab {
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private SetKey setKey;
    public static String key= null;
    public static String rsa= null;
    public static Boolean requtes_flag = true;
    public static Boolean response_flag = false;

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        stdout = new PrintWriter(callbacks.getStdout(), true);
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        callbacks.setExtensionName("xx数据包解密");
        callbacks.registerHttpListener(this);
        callbacks.registerMessageEditorTabFactory(new IMessageEditorTabFactory() {
            public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {

                return new DESDecoder(controller, callbacks, helpers, stdout, editable);
            }
        });
        setKey = new SetKey();
        BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this); // 注册ITab接口
    }





    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){

        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER ) {
            if(messageIsRequest){

            String body = getRequestBody(messageInfo);
            //加密请求body参数
            String newBodys = encryptBody(body);

                if(requtes_flag){
                messageInfo.setRequest(helpers.buildHttpMessage(getHeaders(messageInfo, messageIsRequest), newBodys.getBytes()));
                stdout.println("\n\n密文body: "+newBodys);
            }else {
                messageInfo.setRequest(helpers.buildHttpMessage(getHeaders(messageInfo, messageIsRequest), body.getBytes()));
                stdout.println("\n\n明文body: "+body);
            }


            //处理返回包的密文
        }else{
                IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse()); //getResponse获得的是字节序列
                String resp = new String(messageInfo.getResponse());
                int bodyOffset = analyzedResponse.getBodyOffset();
                String body = resp.substring(bodyOffset);
                String reg = "encryptData\":\"(.*?)\"";
                Pattern pattern = Pattern.compile(reg);
                Matcher matches = pattern.matcher(body);
                if(matches.find()) {
                    String ciphertext = matches.group(1);
                    byte[] bytes = DESUtils.DES_CBC_Decrypt(DESUtils.hexToByteArray(ciphertext), key.getBytes());
                    //flag的值通过ui控件设置，用解密后的明文替换密文
                    if(response_flag){
                        messageInfo.setResponse(helpers.buildHttpMessage(getHeaders(messageInfo, messageIsRequest), body.replace(ciphertext,new String(bytes)).getBytes()));
                    }

                }

            }
    }
    }

    //获取请求body
    public String getRequestBody(IHttpRequestResponse messageInfo){
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        List<IParameter> parameters = requestInfo.getParameters();
        int bodyOffset = requestInfo.getBodyOffset();
        byte[] request = messageInfo.getRequest();

        String request_body = new String(request); //byte[] to String
        String body = request_body.substring(bodyOffset);
        return  body;
    }

    //加密请求包
    public String encryptBody(String plaintext){
        //还原js中的加密算法，构造合法密文
        String splite = "\\u001d";
        String md5 = MD5Util.getMD5Str(plaintext+key).toLowerCase();
        byte[] bytes = DESUtils.DES_CBC_Encrypt(plaintext.getBytes(), key.getBytes());
        String desstr = DESUtils.byteToHexString(bytes).toLowerCase();
        String data = md5+splite+desstr+splite+rsa;
        String newEncryptBody = "{\"encryptData\":\""+data+"\"}";
        return newEncryptBody;
    }

    //获取请求头
    public List<String> getHeaders(IHttpRequestResponse messageInfo, boolean messageIsRequest) {
        if (messageIsRequest) {
            byte[] content = messageInfo.getRequest();
            return helpers.analyzeRequest(content).getHeaders();
        }
        byte[] content = messageInfo.getResponse();
        return helpers.analyzeResponse(content).getHeaders();
    }


    public String getTabCaption() { //设置插件展示名称
        return "解密插件";
    }


    public Component getUiComponent() {//获取ui面板
        return setKey.$$$getRootComponent$$$();
    }



}