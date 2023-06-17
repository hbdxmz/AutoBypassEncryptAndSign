package burp;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DESUtils {

    public static void main(String[] args) {
        String content = "{\"body\":{\"unionId\":\"\",\"bankId\":\"\",\"startDate\":\"20221119\",\"endDate\":\"20230219\",\"loanState\":\"\",\"searchType\":\"0\"},\"header\":{\"bankId\":\"00\",\"unionId\":\"\",\"checkcode\":\"\",\"accId\":\"\",\"openId\":\"\",\"sessionId\":\"\",\"wxRedType\":\"\",\"mobile\":\"\",\"channelNo\":\"308\"}}";

        String key = "wbank@20230219-255019";
        System.out.println("加密前：" + content);
        byte[] encrypted = DESUtils.DES_CBC_Encrypt(content.getBytes(), key.getBytes());

        String s = DESUtils.byteToHexString(encrypted);
        System.out.println("加密后：" + s);
        byte[] decrypted = DESUtils.DES_CBC_Decrypt(encrypted, key.getBytes());
        System.out.println("解密后：" + new String(decrypted).toLowerCase());

        //String byte16 = "0eea43bbaba5d7e1cd0f396ea95942197fea35b31c2245e8449806960c08cf9f49b17e01dad1e263b41f963679ba7bd6d44b6312b3fed7ad236d13305884bd693d83d373d5122f474b95228ae5709ed06bdb011a183ffcab960be17c7acc7724a059dd9794da597a0d9a712ee5872fd74d031549b57662dc2222b63d8e0a618efa6b199388f2d1e457c83896d6158ab3f0519a47c0ee4266949d30f506bc17e8078cd4978dc587ee83fa15e7ba1c4d62edf54a3706a065aad2bc608459cbb1bf0f2071bb7eb538cf5be8fe7f9afc5aaec3e2cb72186cdec3aaa10b95b0bf9c314d96cd94a56eb083f096f7cb48164427c0475e0557fbe242";

        byte[] decrypted1 = DESUtils.DES_CBC_Decrypt(DESUtils.hexToByteArray(s.toLowerCase()), key.getBytes());
        System.out.println("解密后：" + new String(decrypted1));


    }

    public static byte[] DES_CBC_Encrypt(byte[] content, byte[] keyBytes) {
        try {
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey key = keyFactory.generateSecret(keySpec);
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            System.out.println("exception:" + e.toString());
        }
        return null;
    }
    public static byte[] DES_CBC_Decrypt(byte[] content, byte[] keyBytes) {
        try {
            DESKeySpec keySpec = new DESKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey key = keyFactory.generateSecret(keySpec);
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            System.out.println("exception:" + e.toString());
        }
        return null;
    }

    public static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer(bytes.length);
        String sTemp;
        for (int i = 0; i < bytes.length; i++) {
            sTemp = Integer.toHexString(0xFF & bytes[i]);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }


    //16进制字符串转byte数组
    public static byte[] hexToByteArray(String inHex){
        int hexlen = inHex.length();
        byte[] result;
        if (hexlen % 2 == 1){
            //奇数
            hexlen++;
            result = new byte[(hexlen/2)];
            inHex="0"+inHex;
        }else {
            //偶数
            result = new byte[(hexlen/2)];
        }
        int j=0;
        for (int i = 0; i < hexlen; i+=2){
            result[j]=hexToByte(inHex.substring(i,i+2));
            j++;
        }
        return result;
    }

    public static byte hexToByte(String inHex){
        return (byte)Integer.parseInt(inHex,16);
    }
}