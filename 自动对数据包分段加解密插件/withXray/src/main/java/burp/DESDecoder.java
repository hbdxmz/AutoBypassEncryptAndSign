package burp;

import java.awt.*;
import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DESDecoder implements IMessageEditorTab {
    IBurpExtenderCallbacks callbacks;
    IExtensionHelpers helpers;
    PrintWriter stdout;
    boolean editable;
    ITextEditor iTextEditor;
    static final String PARAMETE_NAME = "参数明文";

    public static String key = null;

    public DESDecoder(IMessageEditorController controller, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                      PrintWriter stdout, boolean editable) {
        this.callbacks = callbacks;

        this.helpers = helpers;
        this.stdout = stdout;
        this.editable = editable;
        iTextEditor = callbacks.createTextEditor();
    }


    public String getTabCaption() {
        return String.format("%s", PARAMETE_NAME);
    }

    public Component getUiComponent() {
        return iTextEditor.getComponent();
    }

    public boolean isEnabled(byte[] content, boolean isRequest) {
        return isDES(content, isRequest);
    }


    public void setMessage(byte[] content, boolean isRequest) {

        String new_request = "";
        if (content == null) {
            iTextEditor.setText(null);
            iTextEditor.setEditable(editable);
        } else {
            try{
                if (isRequest){
                IRequestInfo requestInfo = helpers.analyzeRequest(content);
                List<IParameter> parameters = requestInfo.getParameters();
                List<String> headers = requestInfo.getHeaders();

                for (String header:headers) {
                    stdout.println("header: "+header);
                    new_request+=header.trim()+"\r\n";
                }

                for (IParameter parameter:parameters) {
                    if(parameter.getType()==IParameter.PARAM_JSON){
                        if("encryptData".equals(parameter.getName())){
                            String data = parameter.getValue();
                            String reg = "\\\\u001d(.*?)\\\\u001d";
                            Pattern pattern = Pattern.compile(reg);
                            Matcher matches = pattern.matcher(data);
                            if(matches.find()){
                                String ciphertext = matches.group(1);
                                stdout.println("ciphertext: "+ciphertext);
                                byte[] bytes = DESUtils.DES_CBC_Decrypt(DESUtils.hexToByteArray(ciphertext), key.getBytes());
                                String new_byte = new String(bytes);
                                new_request+="\r\n"+new_byte;
                                stdout.println("\n\n解密后："+new_byte);
                            }


                        }
                    }
                }


                // 响应
            }else {
                    IResponseInfo analyzedResponse = helpers.analyzeResponse(content); //getResponse获得的是字节序列
                    List<String> headers = analyzedResponse.getHeaders();
                    String resp = new String(content);
                    int bodyOffset = analyzedResponse.getBodyOffset();//响应包是没有参数的概念的，大多需要修改的内容都在body中
                    String body = resp.substring(bodyOffset);

                    for (String header:headers) {
                        stdout.println("header: "+header);
                        new_request+=header.trim()+"\r\n";
                    }

                    String reg = "encryptData\":\"(.*?)\"";
                    Pattern pattern = Pattern.compile(reg);
                    Matcher matches = pattern.matcher(body);
                    if(matches.find()) {
                        String ciphertext = matches.group(1);
                        stdout.println("encryptData" + ciphertext);
                        byte[] bytes = DESUtils.DES_CBC_Decrypt(DESUtils.hexToByteArray(ciphertext), key.getBytes());
                        String new_data = new String(bytes);
                        //解密后，用明文替换密文，再用IMessageEditorTab展示解密后的数据包，
                        new_request+="\r\n"+body.replace(ciphertext,new_data);
                    }
                }
                iTextEditor.setText(new_request.getBytes());

            }catch(Exception e)
            {
                stdout.print("DES not found");
            }

        }

    }


    public byte[] getMessage() {
        return iTextEditor.getText();
    }


    public boolean isModified() {
        return true;
    }


    public byte[] getSelectedData() {
        return iTextEditor.getSelectedText();
    }


    private boolean isDES(byte[] content, boolean isRequest) {


        // 请求
        if (isRequest) {
            IRequestInfo iReq = helpers.analyzeRequest(content);
            List<IParameter> parameters = iReq.getParameters();
            for (IParameter parameter:parameters){
                if ("encryptData".equals(parameter.getName())) {
                    return true;
                }
            }

        }

        // 响应
        if (!isRequest) {
            IResponseInfo iRes = helpers.analyzeResponse(content);
            String resp = new String(content);
            int bodyOffset = iRes.getBodyOffset();//响应包是没有参数的概念的，大多需要修改的内容都在body中
            String body = resp.substring(bodyOffset);
            if (body.contains("encryptData")){
                return true;
            }

        }
        return false;
    }

}
